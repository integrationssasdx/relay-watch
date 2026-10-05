"""Tests for the offline relay reliability monitor."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

from relay_watch import (
    CheckpointError,
    InvalidInputError,
    ProofVerificationError,
    run,
)
from relay_watch.core import (
    _trusted_roots,
    _validator_set_hash,
    _nearest_rank,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SIGS = ["0xaa11", "0xbb22", "0xcc33"]


def make_event(**overrides):
    """A fully consistent, verifiable event; overrides tweak individual bits."""
    sigs = list(SIGS)
    proof = {
        "light_client_version": "v1",
        "trusted_root": sorted(_trusted_roots("v1", "0xdeadbeef"))[1],
        "header_hash": "0xdeadbeef",
        "validator_set_hash": _validator_set_hash("v1", "chain-7", sigs),
        "signatures": sigs,
        "quorum": 2,
    }
    event = {
        "event_id": "E1",
        "chain_id": "chain-7",
        "sequence": 1,
        "observed_at": 1000,
        "proof_submitted_at": 1100,
        "proof_verified_at": 1500,
        "finalized_at": 2400,
        "proof": proof,
    }
    for key, value in overrides.items():
        if key in proof:
            proof[key] = value
        else:
            event[key] = value
    return event


@pytest.fixture()
def workspace(tmp_path):
    paths = {
        "input": tmp_path / "in.jsonl",
        "checkpoint": tmp_path / "cp.json",
        "output": tmp_path / "report.jsonl",
    }
    return paths


def write_events(path, events):
    path.write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8"
    )


def read_checkpoint(workspace):
    return json.loads(workspace["checkpoint"].read_text(encoding="utf-8"))


def v3_checkpoint(mapping, processed_lines, digest):
    return {
        "schema_version": 3,
        "last_sequence_by_chain": mapping,
        "processed_lines": processed_lines,
        "input_prefix_sha256": digest,
    }


def prefix_digest(path, n):
    """SHA-256 of the raw byte prefix ending after the n-th physical line."""
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    return hashlib.sha256(b"".join(lines[:n])).hexdigest()


def full_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def on_chain(chain_id, **overrides):
    """Like make_event but rebound to an arbitrary chain_id.

    make_event bakes chain-7 into validator_set_hash; this recomputes the
    commitment for the requested chain (unless explicitly overridden) so the
    proof still verifies.
    """
    event = make_event(chain_id=chain_id, **overrides)
    if "validator_set_hash" not in overrides:
        proof = event["proof"]
        proof["validator_set_hash"] = _validator_set_hash(
            proof["light_client_version"], chain_id, proof["signatures"]
        )
    return event


def chain_event(chain_id, sequence, event_id, base, **overrides):
    """A verifiable event on chain_id with a globally-unique timestamp block.

    base is spaced >= 1000 apart between events so every time column stays
    globally unique; extra overrides (e.g. a failing proof) pass through.
    """
    return on_chain(
        chain_id,
        event_id=event_id,
        sequence=sequence,
        observed_at=base,
        proof_submitted_at=base + 100,
        proof_verified_at=base + 500,
        finalized_at=base + 900,
        **overrides,
    )


def interlocked_events():
    """Two chains interleaved in line order: a1 b1 a2 b2 a3 b3.

    Each timestamp column is globally unique; both chains reuse sequences
    1..3 (legal because the identity is (chain_id, sequence)).
    """
    spec = [
        ("chain-a", 1, "A1", 1000),
        ("chain-b", 1, "B1", 2000),
        ("chain-a", 2, "A2", 3000),
        ("chain-b", 2, "B2", 4000),
        ("chain-a", 3, "A3", 5000),
        ("chain-b", 3, "B3", 6000),
    ]
    return [chain_event(chain, seq, eid, base) for chain, seq, eid, base in spec]


# ---------------------------------------------------------------------------
# Happy path / report contents
# ---------------------------------------------------------------------------


def test_verified_report_fields_and_latencies(workspace):
    write_events(workspace["input"], [make_event()])

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert reports == [
        {
            "event_id": "E1",
            "chain_id": "chain-7",
            "sequence": 1,
            "proof_status": "verified",
            "proof_latency_ms": 400,
            "relay_latency_ms": 500,
            "destination_latency_ms": 900,
            "attribution": "destination",
            "finalized_at": 2400,
        }
    ]
    lines = workspace["output"].read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0]) == reports[0]


def test_output_is_jsonl_one_object_per_line(workspace):
    events = [
        make_event(event_id="A", sequence=1),
        make_event(
            event_id="B",
            sequence=2,
            observed_at=2001,
            proof_submitted_at=2100,
            proof_verified_at=2500,
            finalized_at=3400,
        ),
    ]
    write_events(workspace["input"], events)

    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    lines = workspace["output"].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["sequence"] for line in lines] == [1, 2]


@pytest.mark.parametrize(
    "times,expected",
    [
        # source strictly largest (observation after submission, quick finalize)
        (dict(submit=1000, verify=2000, finalize=2300, observed=1500), "source"),
        # relay strictly largest (observed well before submission)
        (dict(submit=1000, verify=1100, finalize=1200, observed=100), "relay"),
        # destination strictly largest
        (dict(submit=1000, verify=1100, finalize=5000, observed=1050), "destination"),
        # source == relay tie (observation at submission) -> relay
        (dict(submit=1000, verify=1500, finalize=1600, observed=1000), "relay"),
        # relay == destination tie -> relay
        (dict(submit=1200, verify=1500, finalize=2000, observed=1000), "relay"),
        # all stages equal (all instants coincide) -> relay
        (dict(submit=1000, verify=1000, finalize=1000, observed=1000), "relay"),
        # negative relay (observation after verification) is ignored
        (dict(submit=1100, verify=1500, finalize=2400, observed=2000), "destination"),
    ],
)
def test_attribution(workspace, times, expected):
    event = make_event(
        observed_at=times["observed"],
        proof_submitted_at=times["submit"],
        proof_verified_at=times["verify"],
        finalized_at=times["finalize"],
    )
    write_events(workspace["input"], [event])
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert reports[0]["attribution"] == expected


def test_direct_root_equal_to_header_hash_verifies(workspace):
    event = make_event(trusted_root="0xdeadbeef")
    write_events(workspace["input"], [event])
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert reports[0]["proof_status"] == "verified"


def test_hex_casing_and_prefix_does_not_affect_verification(workspace):
    event = make_event(
        trusted_root=sorted(_trusted_roots("v1", "0xdeadbeef"))[1].upper(),
        header_hash="DEADBEEF",
        validator_set_hash="0X" + _validator_set_hash("v1", "chain-7", SIGS).upper(),
    )
    write_events(workspace["input"], [event])
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert reports[0]["proof_status"] == "verified"


# ---------------------------------------------------------------------------
# InvalidInputError
# ---------------------------------------------------------------------------


def expect_invalid(workspace, events):
    write_events(workspace["input"], events)
    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_malformed_json_is_invalid_input(workspace):
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_missing_top_level_field(workspace):
    event = make_event()
    del event["chain_id"]
    expect_invalid(workspace, [event])


def test_missing_proof_field(workspace):
    event = make_event()
    del event["proof"]["quorum"]
    expect_invalid(workspace, [event])


def test_null_proof_is_incomplete(workspace):
    expect_invalid(workspace, [make_event(proof=None)])


def test_non_integer_timestamp(workspace):
    expect_invalid(workspace, [make_event(observed_at="1000")])


def test_boolean_is_not_an_integer(workspace):
    expect_invalid(workspace, [make_event(sequence=True)])


def test_submit_after_verify_is_time_inversion(workspace):
    expect_invalid(
        workspace, [make_event(proof_submitted_at=1600, proof_verified_at=1500)]
    )


def test_verify_after_finalize_is_time_inversion(workspace):
    expect_invalid(
        workspace, [make_event(proof_verified_at=2500, finalized_at=2400)]
    )


def test_duplicate_sequence(workspace):
    expect_invalid(
        workspace,
        [make_event(event_id="A", sequence=1), make_event(event_id="B", sequence=1)],
    )


def test_timestamp_field_values_must_be_unique_across_events(workspace):
    # Two events sharing the same observed_at value violate column uniqueness.
    a = make_event(event_id="A", sequence=1)
    b = make_event(
        event_id="B",
        sequence=2,
        observed_at=1000,
        proof_submitted_at=3100,
        proof_verified_at=3500,
        finalized_at=4400,
    )
    expect_invalid(workspace, [a, b])


def test_distinct_time_fields_may_coincide_within_an_event(workspace):
    # observed_at == proof_submitted_at (a source/relay tie input) is valid.
    event = make_event(observed_at=1100)
    write_events(workspace["input"], [event])
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert reports[0]["proof_latency_ms"] == reports[0]["relay_latency_ms"]


def test_quorum_zero_is_structurally_invalid(workspace):
    expect_invalid(workspace, [make_event(quorum=0)])


def test_malformed_checkpoint_json_is_invalid_input(workspace):
    write_events(workspace["input"], [make_event()])
    workspace["checkpoint"].write_text("not-json", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_checkpoint_without_last_sequence_is_invalid_input(workspace):
    write_events(workspace["input"], [make_event()])
    workspace["checkpoint"].write_text("{}", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


# ---------------------------------------------------------------------------
# ProofVerificationError
# ---------------------------------------------------------------------------


def expect_proof_error(workspace, events):
    write_events(workspace["input"], events)
    with pytest.raises(ProofVerificationError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_signatures_below_quorum(workspace):
    expect_proof_error(workspace, [make_event(signatures=["0xaa11"], quorum=2)])


def test_duplicate_signatures_do_not_reach_quorum(workspace):
    expect_proof_error(
        workspace, [make_event(signatures=["0xaa11", "0xaa11"], quorum=2)]
    )


def test_validator_set_hash_mismatch(workspace):
    expect_proof_error(
        workspace, [make_event(validator_set_hash="0x" + "11" * 32)]
    )


def test_trusted_root_does_not_verify_header(workspace):
    expect_proof_error(
        workspace,
        [make_event(trusted_root="0x" + "22" * 32, header_hash="0xdeadbeef")],
    )


def test_root_must_conform_to_declared_light_client_version(workspace):
    # The root was produced for v1 but the proof declares v9: the commitments
    # are bound to the version, so it cannot verify.
    expect_proof_error(workspace, [make_event(light_client_version="v9")])


def test_consistent_non_v1_version_verifies(workspace):
    version = "v2"
    sigs = list(SIGS)
    event = make_event(
        light_client_version=version,
        trusted_root=sorted(_trusted_roots(version, "0xdeadbeef"))[1],
        validator_set_hash=_validator_set_hash(version, "chain-7", sigs),
    )
    write_events(workspace["input"], [event])
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert reports[0]["proof_status"] == "verified"


# ---------------------------------------------------------------------------
# CheckpointError
# ---------------------------------------------------------------------------


def expect_checkpoint_error(workspace, raw):
    write_events(workspace["input"], [make_event(sequence=2)])
    workspace["checkpoint"].write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_checkpoint_negative(workspace):
    expect_checkpoint_error(workspace, {"last_sequence": -1})


def test_checkpoint_non_integer_float(workspace):
    expect_checkpoint_error(workspace, {"last_sequence": 1.5})


def test_checkpoint_non_integer_string(workspace):
    expect_checkpoint_error(workspace, {"last_sequence": "1"})


def test_checkpoint_boolean(workspace):
    expect_checkpoint_error(workspace, {"last_sequence": True})


def test_checkpoint_above_input_maximum(workspace):
    expect_checkpoint_error(workspace, {"last_sequence": 99})


# ---------------------------------------------------------------------------
# Checkpoint resume semantics
# ---------------------------------------------------------------------------


def three_events():
    return [
        make_event(event_id="A", sequence=1),
        make_event(
            event_id="B",
            sequence=2,
            observed_at=2001,
            proof_submitted_at=2100,
            proof_verified_at=2500,
            finalized_at=3400,
        ),
        make_event(
            event_id="C",
            sequence=3,
            observed_at=4001,
            proof_submitted_at=4100,
            proof_verified_at=4500,
            finalized_at=5400,
        ),
    ]


def test_no_checkpoint_processes_from_first(workspace):
    write_events(workspace["input"], three_events())
    reports = run(workspace["input"], None, workspace["output"])
    assert [r["sequence"] for r in reports] == [1, 2, 3]
    assert not workspace["checkpoint"].exists()


def test_checkpoint_resume_processes_only_greater_sequences(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 1}), encoding="utf-8"
    )
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert [r["sequence"] for r in reports] == [2, 3]
    # Legacy single-chain checkpoint is upgraded straight to the v3 shape
    # (cursors plus input-prefix integrity fields).
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-7": 3}, 3, full_digest(workspace["input"])
    )


def test_resume_is_idempotent_no_duplicate_output(workspace):
    write_events(workspace["input"], three_events())
    first = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert [r["sequence"] for r in first] == [1, 2, 3]
    second = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert second == []
    # The output file holds only the last run's rows (the three), not six.
    lines = workspace["output"].read_text().splitlines()
    assert [json.loads(line)["sequence"] for line in lines] == [1, 2, 3]


def test_fresh_start_overwrites_stale_output(workspace):
    write_events(workspace["input"], three_events())
    workspace["output"].write_text('{"sequence": 999}\n', encoding="utf-8")
    # No checkpoint file exists, so this is a fresh start despite the stale
    # report; the stale row must not survive.
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert [r["sequence"] for r in reports] == [1, 2, 3]
    lines = workspace["output"].read_text().splitlines()
    assert [json.loads(line)["sequence"] for line in lines] == [1, 2, 3]


def test_last_sequence_equal_to_max_is_a_noop_success(workspace):
    write_events(workspace["input"], [make_event(sequence=2)])
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 2}), encoding="utf-8"
    )
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert reports == []
    assert json.loads(workspace["checkpoint"].read_text())["last_sequence"] == 2


def test_failure_leaves_no_output_and_unchanged_checkpoint(workspace):
    good = make_event(event_id="A", sequence=1)
    bad = make_event(
        event_id="B",
        sequence=2,
        observed_at=2001,
        proof_submitted_at=2100,
        proof_verified_at=2500,
        finalized_at=3400,
        signatures=["0xaa11"],
        quorum=2,
    )
    write_events(workspace["input"], [good, bad])
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 0}), encoding="utf-8"
    )
    workspace["output"].write_text("PRIOR-CONTENT\n", encoding="utf-8")

    with pytest.raises(ProofVerificationError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert workspace["output"].read_text() == "PRIOR-CONTENT\n"
    assert json.loads(workspace["checkpoint"].read_text())["last_sequence"] == 0


def test_failure_does_not_create_output(workspace):
    bad = make_event(signatures=["0xaa11"], quorum=2)
    write_events(workspace["input"], [bad])
    with pytest.raises(ProofVerificationError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert not workspace["output"].exists()


# ---------------------------------------------------------------------------
# Command line interface
# ---------------------------------------------------------------------------


def run_cli(*args, script=None):
    cmd = [sys.executable, "-m", "relay_watch", *args] if script is None else [script, *args]
    return subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=60
    )


def test_cli_success(workspace):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert workspace["output"].exists()


def test_cli_domain_error_fixed_json_nonzero_no_output(workspace):
    write_events(workspace["input"], [make_event(signatures=["0xaa11"], quorum=2)])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert payload["error"] == "ProofVerificationError"
    assert isinstance(payload["message"], str) and payload["message"]
    assert not workspace["output"].exists()


def test_cli_checkpoint_error(workspace):
    write_events(workspace["input"], [make_event(sequence=1)])
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": -5}), encoding="utf-8"
    )
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "CheckpointError"


def test_cli_invalid_input_error(workspace):
    workspace["input"].write_text("nope\n", encoding="utf-8")
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "InvalidInputError"


def test_cli_missing_argument_is_fixed_json_nonzero(workspace):
    result = run_cli("--input", str(workspace["input"]))
    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert set(payload.keys()) == {"error", "message"}


def test_module_help_exits_zero():
    result = run_cli("--help")
    assert result.returncode == 0
    assert "relay-watch" in result.stdout


def test_relay_watch_executable_entry_point(workspace):
    write_events(workspace["input"], [make_event()])
    script = os.path.join(REPO_ROOT, "relay-watch")
    assert os.access(script, os.X_OK)
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        script=script,
    )
    assert result.returncode == 0, result.stderr
    assert workspace["output"].exists()


# ---------------------------------------------------------------------------
# Multi-chain inputs: identity, ordering and reports
# ---------------------------------------------------------------------------


def test_multichain_report_has_chain_id_and_preserves_line_order(workspace):
    write_events(workspace["input"], interlocked_events())

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-a", 1),
        ("chain-b", 1),
        ("chain-a", 2),
        ("chain-b", 2),
        ("chain-a", 3),
        ("chain-b", 3),
    ]
    # Every report row carries its chain_id and the unchanged single-chain fields.
    for report in reports:
        assert set(report) == {
            "event_id",
            "chain_id",
            "sequence",
            "proof_status",
            "proof_latency_ms",
            "relay_latency_ms",
            "destination_latency_ms",
            "attribution",
            "finalized_at",
        }

    lines = workspace["output"].read_text(encoding="utf-8").splitlines()
    assert [
        (json.loads(line)["chain_id"], json.loads(line)["sequence"])
        for line in lines
    ] == [(r["chain_id"], r["sequence"]) for r in reports]


def test_same_sequence_on_different_chains_is_allowed(workspace):
    events = [
        chain_event("chain-a", 5, "A1", 1000),
        chain_event("chain-b", 5, "B1", 2000),
    ]
    write_events(workspace["input"], events)
    reports = run(workspace["input"], None, None)
    assert [r["event_id"] for r in reports] == ["A1", "B1"]


def test_duplicate_sequence_within_one_chain_rejected_even_with_other_chains(
    workspace,
):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-b", 1, "B1", 2000),
        chain_event("chain-a", 1, "A2", 3000),
    ]
    expect_invalid(workspace, events)


def test_timestamp_columns_remain_globally_unique_across_chains(workspace):
    # Same observed_at on two different chains still violates column uniqueness:
    # the numeric convention is unchanged by multi-chain support.
    a = on_chain("chain-a", event_id="A1", sequence=1)
    b = on_chain("chain-b", event_id="B1", sequence=2)
    expect_invalid(workspace, [a, b])


# ---------------------------------------------------------------------------
# Multi-chain checkpoint resume
# ---------------------------------------------------------------------------


def v2_checkpoint(mapping):
    return {"schema_version": 2, "last_sequence_by_chain": mapping}


def test_v2_resume_filters_per_chain_and_missing_chain_starts_from_first(
    workspace,
):
    write_events(workspace["input"], interlocked_events())
    # chain-a resumes after sequence 1; chain-b is absent -> starts at first.
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-a": 1})), encoding="utf-8"
    )

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-b", 1),
        ("chain-a", 2),
        ("chain-b", 2),
        ("chain-a", 3),
        ("chain-b", 3),
    ]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 3, "chain-b": 3}, 6, full_digest(workspace["input"])
    )


def test_v2_resume_advances_only_chains_with_selected_events(workspace):
    events = interlocked_events()
    write_events(workspace["input"], events)
    # chain-a already fully consumed; chain-b has work left. chain-a's cursor
    # must not move, chain-b advances to its own maximum.
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-a": 3, "chain-b": 0})),
        encoding="utf-8",
    )

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert {r["chain_id"] for r in reports} == {"chain-b"}
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 3, "chain-b": 3}, 6, full_digest(workspace["input"])
    )


def test_v2_resume_rerun_is_a_noop(workspace):
    write_events(workspace["input"], interlocked_events())
    first = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert len(first) == 6

    snapshot = workspace["checkpoint"].read_text()
    output_snapshot = workspace["output"].read_text()
    second = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert second == []
    assert workspace["checkpoint"].read_text() == snapshot
    assert workspace["output"].read_text() == output_snapshot
    rows = [json.loads(line) for line in output_snapshot.splitlines()]
    assert len(rows) == 6


def test_v2_resume_appends_only_higher_sequences(workspace):
    first_batch = [
        on_chain(
            "chain-a",
            event_id="A1",
            sequence=1,
            observed_at=1000,
            proof_submitted_at=1100,
            proof_verified_at=1500,
            finalized_at=1900,
        ),
        on_chain(
            "chain-b",
            event_id="B1",
            sequence=1,
            observed_at=2000,
            proof_submitted_at=2100,
            proof_verified_at=2500,
            finalized_at=2900,
        ),
    ]
    write_events(workspace["input"], first_batch)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    second_batch = first_batch + [
        on_chain(
            "chain-a",
            event_id="A2",
            sequence=2,
            observed_at=3000,
            proof_submitted_at=3100,
            proof_verified_at=3500,
            finalized_at=3900,
        ),
        on_chain(
            "chain-b",
            event_id="B2",
            sequence=2,
            observed_at=4000,
            proof_submitted_at=4100,
            proof_verified_at=4500,
            finalized_at=4900,
        ),
    ]
    write_events(workspace["input"], second_batch)
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-a", 2),
        ("chain-b", 2),
    ]
    rows = [
        json.loads(line)
        for line in workspace["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert [(r["chain_id"], r["sequence"]) for r in rows] == [
        ("chain-a", 1),
        ("chain-b", 1),
        ("chain-a", 2),
        ("chain-b", 2),
    ]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 2, "chain-b": 2}, 4, full_digest(workspace["input"])
    )


def test_shared_sequence_across_chains_does_not_dedupe_output(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-b", 1, "B1", 2000),
    ]
    write_events(workspace["input"], events)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])
    # Rerun: sequence 1 exists for both chains; neither row may be dropped or
    # treated as a duplicate of the other.
    run(workspace["input"], workspace["checkpoint"], workspace["output"])
    rows = [
        json.loads(line)
        for line in workspace["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert [(r["chain_id"], r["sequence"]) for r in rows] == [
        ("chain-a", 1),
        ("chain-b", 1),
    ]


def test_resume_introducing_a_new_chain_appends_its_events(workspace):
    first_batch = [
        on_chain(
            "chain-a",
            event_id="A1",
            sequence=1,
            observed_at=1000,
            proof_submitted_at=1100,
            proof_verified_at=1500,
            finalized_at=1900,
        )
    ]
    write_events(workspace["input"], first_batch)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    second_batch = first_batch + [
        on_chain(
            "chain-b",
            event_id="B1",
            sequence=1,
            observed_at=2000,
            proof_submitted_at=2100,
            proof_verified_at=2500,
            finalized_at=2900,
        )
    ]
    write_events(workspace["input"], second_batch)
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-b", 1)
    ]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 1, "chain-b": 1}, 2, full_digest(workspace["input"])
    )


# ---------------------------------------------------------------------------
# Legacy last_sequence checkpoint vs multi-chain input
# ---------------------------------------------------------------------------


def test_legacy_checkpoint_with_multichain_input_is_checkpoint_error(workspace):
    write_events(
        workspace["input"],
        [chain_event("chain-a", 1, "A1", 1000),
         chain_event("chain-b", 1, "B1", 2000)],
    )
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 0}), encoding="utf-8"
    )
    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_legacy_checkpoint_empty_input_still_noop(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 2}), encoding="utf-8"
    )
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert reports == []
    # No events processed -> checkpoint is left untouched (still legacy).
    assert json.loads(workspace["checkpoint"].read_text()) == {"last_sequence": 2}


# ---------------------------------------------------------------------------
# v2 checkpoint structural validation -> InvalidInputError
# ---------------------------------------------------------------------------


def write_v2_and_expect_invalid(workspace, raw, events=None):
    write_events(
        workspace["input"],
        events if events is not None else [make_event(sequence=1)],
    )
    workspace["checkpoint"].write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v2_checkpoint_requires_schema_version(workspace):
    write_v2_and_expect_invalid(
        workspace, {"last_sequence_by_chain": {"chain-7": 0}}
    )


def test_v2_checkpoint_requires_mapping(workspace):
    write_v2_and_expect_invalid(workspace, {"schema_version": 2})


def test_v2_checkpoint_rejects_unknown_field(workspace):
    write_v2_and_expect_invalid(
        workspace,
        {
            "schema_version": 2,
            "last_sequence_by_chain": {"chain-7": 0},
            "extra": 1,
        },
    )


def test_v2_checkpoint_rejects_wrong_schema_version(workspace):
    write_v2_and_expect_invalid(
        workspace,
        {"schema_version": 1, "last_sequence_by_chain": {"chain-7": 0}},
    )


def test_v2_checkpoint_rejects_null_schema_version(workspace):
    write_v2_and_expect_invalid(
        workspace,
        {"schema_version": None, "last_sequence_by_chain": {"chain-7": 0}},
    )


def test_v2_checkpoint_rejects_null_mapping(workspace):
    write_v2_and_expect_invalid(
        workspace, {"schema_version": 2, "last_sequence_by_chain": None}
    )


def test_v2_checkpoint_rejects_array_mapping(workspace):
    write_v2_and_expect_invalid(
        workspace, {"schema_version": 2, "last_sequence_by_chain": []}
    )


def test_v2_checkpoint_rejects_null_cursor(workspace):
    write_v2_and_expect_invalid(
        workspace,
        {"schema_version": 2, "last_sequence_by_chain": {"chain-7": None}},
    )


def test_v2_checkpoint_rejects_array_cursor(workspace):
    write_v2_and_expect_invalid(
        workspace,
        {"schema_version": 2, "last_sequence_by_chain": {"chain-7": [1]}},
    )


def test_v2_checkpoint_top_level_array_is_invalid(workspace):
    write_events(workspace["input"], [make_event(sequence=1)])
    workspace["checkpoint"].write_text("[]", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


# ---------------------------------------------------------------------------
# v2 checkpoint semantic validation -> CheckpointError
# ---------------------------------------------------------------------------


def write_v2_and_expect_checkpoint_error(workspace, mapping, events=None):
    write_events(
        workspace["input"],
        events if events is not None else [make_event(sequence=2)],
    )
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint(mapping)), encoding="utf-8"
    )
    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v2_checkpoint_negative_cursor(workspace):
    write_v2_and_expect_checkpoint_error(workspace, {"chain-7": -1})


def test_v2_checkpoint_float_cursor(workspace):
    write_v2_and_expect_checkpoint_error(workspace, {"chain-7": 1.5})


def test_v2_checkpoint_string_cursor(workspace):
    write_v2_and_expect_checkpoint_error(workspace, {"chain-7": "1"})


def test_v2_checkpoint_boolean_cursor(workspace):
    write_v2_and_expect_checkpoint_error(workspace, {"chain-7": True})


def test_v2_checkpoint_empty_chain_identifier(workspace):
    write_v2_and_expect_checkpoint_error(workspace, {"": 1})


def test_v2_checkpoint_cursor_above_per_chain_maximum(workspace):
    events = [
        chain_event("chain-a", 3, "A1", 1000),
        chain_event("chain-b", 9, "B1", 2000),
    ]
    # chain-a's cursor exceeds its own max (3) even though chain-b reaches 9.
    write_v2_and_expect_checkpoint_error(
        workspace, {"chain-a": 4, "chain-b": 9}, events=events
    )


def test_v2_checkpoint_cursor_for_unmentioned_chain_is_allowed(workspace):
    # A cursor for a chain absent from this input cannot exceed its maximum;
    # the present chain still resumes normally.
    events = [chain_event("chain-a", 2, "A1", 1000)]
    write_events(workspace["input"], events)
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-a": 1, "chain-other": 99})),
        encoding="utf-8",
    )
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-a", 2)
    ]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 2, "chain-other": 99},
        1,
        prefix_digest(workspace["input"], 1),
    )


# ---------------------------------------------------------------------------
# Multi-chain atomicity: failure leaves no half output / no advancement
# ---------------------------------------------------------------------------


def test_multichain_failure_leaves_prior_output_and_checkpoint_untouched(
    workspace,
):
    good = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-b", 1, "B1", 2000),
    ]
    write_events(workspace["input"], good)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    bad_batch = good + [
        chain_event(
            "chain-a",
            2,
            "A2",
            3000,
            signatures=["0xaa11"],
            quorum=2,
        )
    ]
    write_events(workspace["input"], bad_batch)
    prior_output = workspace["output"].read_text()
    prior_checkpoint = workspace["checkpoint"].read_text()

    with pytest.raises(ProofVerificationError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert workspace["output"].read_text() == prior_output
    assert workspace["checkpoint"].read_text() == prior_checkpoint


# ---------------------------------------------------------------------------
# Multi-chain command line interface
# ---------------------------------------------------------------------------


def test_cli_multichain_success_silent_stdout(workspace):
    write_events(workspace["input"], interlocked_events())
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rows = [
        json.loads(line)
        for line in workspace["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 6
    assert json.loads(workspace["checkpoint"].read_text())["schema_version"] == 3


def test_cli_multichain_then_rerun_is_noop(workspace):
    write_events(workspace["input"], interlocked_events())
    kwargs = dict(cwd=REPO_ROOT, capture_output=True, text=True, timeout=60)
    cmd = [
        sys.executable,
        "-m",
        "relay_watch",
        "--input",
        str(workspace["input"]),
        "--checkpoint",
        str(workspace["checkpoint"]),
        "--output",
        str(workspace["output"]),
    ]
    first = subprocess.run(cmd, **kwargs)
    assert first.returncode == 0, first.stderr

    output_before = workspace["output"].read_text()
    checkpoint_before = workspace["checkpoint"].read_text()
    second = subprocess.run(cmd, **kwargs)
    assert second.returncode == 0, second.stderr
    assert second.stdout == ""
    assert workspace["output"].read_text() == output_before
    assert workspace["checkpoint"].read_text() == checkpoint_before


def test_cli_legacy_checkpoint_multichain_input_is_checkpoint_error(workspace):
    write_events(
        workspace["input"],
        [chain_event("chain-a", 1, "A1", 1000),
         chain_event("chain-b", 1, "B1", 2000)],
    )
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 0}), encoding="utf-8"
    )
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "CheckpointError"
    assert not workspace["output"].exists()


def test_cli_malformed_v2_checkpoint_is_invalid_input_error(workspace):
    write_events(
        workspace["input"],
        [chain_event("chain-a", 1, "A1", 1000),
         chain_event("chain-b", 1, "B1", 2000)],
    )
    workspace["checkpoint"].write_text(
        json.dumps({"schema_version": 2, "last_sequence_by_chain": None}),
        encoding="utf-8",
    )
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "InvalidInputError"
    assert not workspace["output"].exists()


# ---------------------------------------------------------------------------
# Failure isolation: tolerate_failures=True (core)
# ---------------------------------------------------------------------------


def isolated_event(chain_id, sequence, event_id, base, *, failing=False):
    """A verifiable event (failing=False) or a below-quorum proof failure.

    base values are spaced >= 1000 apart so every time column stays unique.
    """
    overrides = (
        dict(signatures=["0xaa11"], quorum=2) if failing else {}
    )
    return chain_event(chain_id, sequence, event_id, base, **overrides)


def three_mixed_events():
    """good seq1, failing seq2, good seq3 on chain-a (unique time blocks)."""
    return [
        isolated_event("chain-a", 1, "A1", 1000),
        isolated_event("chain-a", 2, "A2", 2000, failing=True),
        isolated_event("chain-a", 3, "A3", 3000),
    ]


def test_tolerate_failures_failed_row_is_isolated_and_later_events_continue(
    workspace,
):
    write_events(workspace["input"], three_mixed_events())

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert [r["proof_status"] for r in reports] == [
        "verified",
        "failed",
        "verified",
    ]
    # The event after the failure still verifies: a prior failure does not stop
    # later processing on the same chain.
    assert reports[2]["event_id"] == "A3"


def test_failed_report_row_fields_and_numeric_convention(workspace):
    event = make_event(signatures=["0xaa11"], quorum=2)
    write_events(workspace["input"], [event])

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert reports == [
        {
            "event_id": "E1",
            "chain_id": "chain-7",
            "sequence": 1,
            "proof_status": "failed",
            "error_type": "ProofVerificationError",
            "error_message": (
                "event 'E1': 1 distinct signatures do not reach quorum 2"
            ),
            "proof_latency_ms": 400,
            "relay_latency_ms": 500,
            "destination_latency_ms": 900,
            "attribution": "destination",
            "finalized_at": 2400,
        }
    ]
    # The failed row is persisted verbatim.
    persisted = json.loads(workspace["output"].read_text())
    assert persisted == reports[0]


def test_failed_and_verified_rows_share_latency_convention(workspace):
    # Two identical time blocks (on distinct sequences); only the proof differs.
    good = isolated_event("chain-a", 1, "A1", 1000)
    bad = isolated_event("chain-a", 2, "A2", 2000, failing=True)
    write_events(workspace["input"], [good, bad])

    reports = run(
        workspace["input"],
        None,
        None,
        tolerate_failures=True,
    )

    # The three latency deltas and the attribution follow one convention on
    # both rows; finalized_at is an absolute timestamp and hence event-specific.
    for key in (
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
        "attribution",
    ):
        assert reports[0][key] == reports[1][key]
    assert reports[0]["proof_latency_ms"] == 400
    assert reports[0]["relay_latency_ms"] == 500
    assert reports[0]["destination_latency_ms"] == 400
    assert reports[0]["attribution"] == "relay"
    assert [r["finalized_at"] for r in reports] == [1900, 2900]


def test_tolerate_failures_advances_checkpoint_past_failed_events(workspace):
    write_events(workspace["input"], three_mixed_events())

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    assert [r["proof_status"] for r in reports] == [
        "verified",
        "failed",
        "verified",
    ]

    # Success and failure both count as processed: cursor reaches sequence 3.
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 3}, 3, full_digest(workspace["input"])
    )

    # Rerun selects nothing, including the previously failed row.
    second = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    assert second == []
    rows = [
        json.loads(line)
        for line in workspace["output"].read_text().splitlines()
    ]
    assert [(r["sequence"], r["proof_status"]) for r in rows] == [
        (1, "verified"),
        (2, "failed"),
        (3, "verified"),
    ]


def test_tolerate_failures_rerun_is_deterministic(workspace):
    write_events(workspace["input"], three_mixed_events())
    first = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    output_after = workspace["output"].read_text()
    cp_after = workspace["checkpoint"].read_text()

    second = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert second == []
    assert workspace["output"].read_text() == output_after
    assert workspace["checkpoint"].read_text() == cp_after
    assert [r["proof_status"] for r in first] == [
        "verified",
        "failed",
        "verified",
    ]


def test_tolerate_failures_fresh_start_overwrites_stale_output(workspace):
    write_events(workspace["input"], three_mixed_events())
    workspace["output"].write_text('{"sequence": 999}\n', encoding="utf-8")

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert len(reports) == 3
    rows = [json.loads(line) for line in workspace["output"].read_text().splitlines()]
    assert [r["sequence"] for r in rows] == [1, 2, 3]


def test_all_events_failing_still_processes_and_advances(workspace):
    events = [
        isolated_event("chain-a", 1, "A1", 1000, failing=True),
        isolated_event("chain-a", 2, "A2", 2000, failing=True),
    ]
    write_events(workspace["input"], events)

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert [r["proof_status"] for r in reports] == ["failed", "failed"]
    assert {r["error_type"] for r in reports} == {"ProofVerificationError"}
    assert read_checkpoint(workspace) == v3_checkpoint(
        {"chain-a": 2}, 2, full_digest(workspace["input"])
    )


# ---------------------------------------------------------------------------
# Failure isolation across multiple chains
# ---------------------------------------------------------------------------


def test_tolerate_failures_multichain_isolation_and_per_chain_cursors(workspace):
    events = [
        isolated_event("chain-a", 1, "A1", 1000),
        isolated_event("chain-b", 1, "B1", 2000),
        isolated_event("chain-a", 2, "A2", 3000, failing=True),
        isolated_event("chain-b", 2, "B2", 4000),
        isolated_event("chain-a", 3, "A3", 5000),
        isolated_event("chain-b", 3, "B3", 6000),
    ]
    write_events(workspace["input"], events)

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    # Strict input line order; only A2 failed, and neither A3 nor any chain-b
    # event is affected.
    assert [(r["chain_id"], r["sequence"], r["proof_status"]) for r in reports] == [
        ("chain-a", 1, "verified"),
        ("chain-b", 1, "verified"),
        ("chain-a", 2, "failed"),
        ("chain-b", 2, "verified"),
        ("chain-a", 3, "verified"),
        ("chain-b", 3, "verified"),
    ]
    checkpoint = read_checkpoint(workspace)
    # The failed A2 still advances chain-a's cursor through 3.
    assert checkpoint == v3_checkpoint(
        {"chain-a": 3, "chain-b": 3}, 6, full_digest(workspace["input"])
    )


def test_tolerate_failures_same_sequence_on_different_chains_independent(workspace):
    events = [
        isolated_event("chain-a", 5, "A1", 1000, failing=True),
        isolated_event("chain-b", 5, "B1", 2000),
    ]
    write_events(workspace["input"], events)

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert [(r["chain_id"], r["sequence"], r["proof_status"]) for r in reports] == [
        ("chain-a", 5, "failed"),
        ("chain-b", 5, "verified"),
    ]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 5, "chain-b": 5}, 2, full_digest(workspace["input"])
    )


# ---------------------------------------------------------------------------
# Failure isolation does not relax structural / checkpoint validation
# ---------------------------------------------------------------------------


def expect_invalid_isolated(workspace, events):
    write_events(workspace["input"], events)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )


def test_tolerate_failures_malformed_json_still_invalid(workspace):
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )
    assert not workspace["output"].exists()


def test_tolerate_failures_duplicate_sequence_still_invalid(workspace):
    expect_invalid_isolated(
        workspace,
        [
            make_event(event_id="A", sequence=1),
            make_event(event_id="B", sequence=1),
        ],
    )


def test_tolerate_failures_duplicate_timestamp_still_invalid(workspace):
    a = make_event(event_id="A", sequence=1)
    b = make_event(
        event_id="B",
        sequence=2,
        observed_at=1000,
        proof_submitted_at=3100,
        proof_verified_at=3500,
        finalized_at=4400,
    )
    expect_invalid_isolated(workspace, [a, b])


def test_tolerate_failures_time_inversion_still_invalid(workspace):
    expect_invalid_isolated(
        workspace,
        [make_event(proof_submitted_at=1600, proof_verified_at=1500)],
    )


def test_tolerate_failures_writes_nothing_on_structural_error(workspace):
    write_events(workspace["input"], three_mixed_events())
    # Start a valid checkpoint/output, then feed a structurally broken input.
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    cp_before = workspace["checkpoint"].read_text()
    out_before = workspace["output"].read_text()

    workspace["input"].write_text("nope\n", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )

    assert workspace["checkpoint"].read_text() == cp_before
    assert workspace["output"].read_text() == out_before


def test_tolerate_failures_checkpoint_cursor_error_still_raises(workspace):
    write_events(workspace["input"], three_mixed_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-a": 99})), encoding="utf-8"
    )
    with pytest.raises(CheckpointError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )
    assert not workspace["output"].exists()


def test_tolerate_failures_malformed_checkpoint_still_invalid(workspace):
    write_events(workspace["input"], three_mixed_events())
    workspace["checkpoint"].write_text(
        json.dumps({"schema_version": 2, "last_sequence_by_chain": None}),
        encoding="utf-8",
    )
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )
    assert not workspace["output"].exists()


# ---------------------------------------------------------------------------
# Strict mode remains the default and explicit
# ---------------------------------------------------------------------------


def test_strict_mode_explicit_false_raises_and_writes_nothing(workspace):
    write_events(workspace["input"], three_mixed_events())
    workspace["output"].write_text("PRIOR\n", encoding="utf-8")

    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=False,
        )

    assert workspace["output"].read_text() == "PRIOR\n"
    assert not workspace["checkpoint"].exists()


# ---------------------------------------------------------------------------
# Failure isolation with legacy checkpoints
# ---------------------------------------------------------------------------


def test_tolerate_failures_upgrades_legacy_single_chain_checkpoint(workspace):
    events = [
        make_event(event_id="A", sequence=1),
        make_event(
            event_id="B",
            sequence=2,
            observed_at=2001,
            proof_submitted_at=2100,
            proof_verified_at=2500,
            finalized_at=3400,
            signatures=["0xaa11"],
            quorum=2,
        ),
    ]
    write_events(workspace["input"], events)
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 0}), encoding="utf-8"
    )

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert [r["proof_status"] for r in reports] == ["verified", "failed"]
    # A failed event still triggers the legacy -> v3 upgrade.
    assert read_checkpoint(workspace) == v3_checkpoint(
        {"chain-7": 2}, 2, full_digest(workspace["input"])
    )


def test_tolerate_failures_legacy_checkpoint_multichain_still_rejected(workspace):
    write_events(
        workspace["input"],
        [
            isolated_event("chain-a", 1, "A1", 1000, failing=True),
            isolated_event("chain-b", 1, "B1", 2000),
        ],
    )
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 0}), encoding="utf-8"
    )
    with pytest.raises(CheckpointError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )
    assert not workspace["output"].exists()


# ---------------------------------------------------------------------------
# Failure isolation: command line interface
# ---------------------------------------------------------------------------


def test_cli_tolerate_failures_bare_flag_succeeds_with_failed_rows(workspace):
    write_events(workspace["input"], three_mixed_events())
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--tolerate-failures",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rows = [
        json.loads(line)
        for line in workspace["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert [r["proof_status"] for r in rows] == [
        "verified",
        "failed",
        "verified",
    ]
    failed = rows[1]
    assert failed["error_type"] == "ProofVerificationError"
    assert isinstance(failed["error_message"], str) and failed["error_message"]
    assert read_checkpoint(workspace) == v3_checkpoint(
        {"chain-a": 3}, 3, full_digest(workspace["input"])
    )


def test_cli_tolerate_failures_true_succeeds(workspace):
    write_events(workspace["input"], three_mixed_events())
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--tolerate-failures", "true",
    )
    assert result.returncode == 0, result.stderr
    rows = [
        json.loads(line)
        for line in workspace["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert [r["proof_status"] for r in rows] == [
        "verified",
        "failed",
        "verified",
    ]


def test_cli_tolerate_failures_false_is_strict(workspace):
    write_events(workspace["input"], three_mixed_events())
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--tolerate-failures", "false",
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not workspace["output"].exists()


def test_cli_tolerate_failures_default_absent_is_strict(workspace):
    write_events(workspace["input"], three_mixed_events())
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not workspace["output"].exists()


def test_cli_tolerate_failures_invalid_value_is_fixed_json_exit_2(workspace):
    write_events(workspace["input"], three_mixed_events())
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--tolerate-failures", "yes",
    )
    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert payload["error"] == "InvalidArgument"
    assert "true" in payload["message"] and "false" in payload["message"]
    assert not workspace["output"].exists()


# ---------------------------------------------------------------------------
# v3 checkpoint: emitted shape and digest conventions
# --------------------------------------------------------------------------- #


def test_first_run_writes_v3_checkpoint_with_full_prefix_digest(workspace):
    events = three_events()
    write_events(workspace["input"], events)

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [r["sequence"] for r in reports] == [1, 2, 3]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-7": 3}, len(events), full_digest(workspace["input"])
    )


def test_v3_digest_covers_every_byte_including_crlf(workspace):
    raw = "".join(json.dumps(e) + "\r\n" for e in three_events())
    workspace["input"].write_bytes(raw.encode("utf-8"))

    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    checkpoint = read_checkpoint(workspace)
    # The CR characters are part of the committed prefix and must be hashed.
    assert checkpoint["input_prefix_sha256"] == hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()
    assert checkpoint["processed_lines"] == 3


def test_v3_digest_for_final_line_without_trailing_newline(workspace):
    raw = "".join(json.dumps(e) + "\n" for e in three_events()[:-1])
    raw += json.dumps(three_events()[-1])  # no trailing newline
    workspace["input"].write_text(raw, encoding="utf-8")

    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    checkpoint = read_checkpoint(workspace)
    assert checkpoint["processed_lines"] == 3
    # No newline is appended for the digest: it covers the exact file bytes.
    assert checkpoint["input_prefix_sha256"] == hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()

    # An unchanged, newline-less file still resumes as a noop.
    again = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert again == []


def test_v3_processed_lines_counts_jsonl_rows_not_blank_lines(workspace):
    events = three_events()
    # Blank physical lines sit between JSONL rows; their bytes still live inside
    # the committed prefix even though processed_lines counts only JSONL rows.
    raw = (
        json.dumps(events[0]) + "\n\n"
        + json.dumps(events[1]) + "\n"
        + json.dumps(events[2]) + "\n\n"
    )
    workspace["input"].write_text(raw, encoding="utf-8")

    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    checkpoint = read_checkpoint(workspace)
    assert checkpoint["processed_lines"] == 3
    # The digest ends after the third JSONL line, so the trailing blank pair is
    # outside the committed prefix; the interior blank line is inside it.
    committed = (
        json.dumps(events[0]) + "\n\n"
        + json.dumps(events[1]) + "\n"
        + json.dumps(events[2]) + "\n"
    ).encode("utf-8")
    assert checkpoint["input_prefix_sha256"] == hashlib.sha256(committed).hexdigest()


def test_v3_resume_after_appended_lines_advances_lines_and_digest(workspace):
    first_batch = interlocked_events()[:3]  # a1 b1 a2
    write_events(workspace["input"], first_batch)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert read_checkpoint(workspace)["processed_lines"] == 3

    second_batch = interlocked_events()
    write_events(workspace["input"], second_batch)  # full file, same prefix
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-b", 2),
        ("chain-a", 3),
        ("chain-b", 3),
    ]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 3, "chain-b": 3}, 6, full_digest(workspace["input"])
    )
    rows = [
        json.loads(line)
        for line in workspace["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert [(r["chain_id"], r["sequence"]) for r in rows] == [
        ("chain-a", 1),
        ("chain-b", 1),
        ("chain-a", 2),
        ("chain-b", 2),
        ("chain-a", 3),
        ("chain-b", 3),
    ]


def test_v3_resume_keeps_cursors_of_chains_without_new_results(workspace):
    first_batch = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-b", 1, "B1", 2000),
    ]
    write_events(workspace["input"], first_batch)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    second_batch = first_batch + [chain_event("chain-b", 2, "B2", 3000)]
    write_events(workspace["input"], second_batch)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])

    checkpoint = read_checkpoint(workspace)
    # chain-a's cursor stays at 1; processed prefix reaches the last line.
    assert checkpoint["last_sequence_by_chain"] == {"chain-a": 1, "chain-b": 2}
    assert checkpoint["processed_lines"] == 3
    assert checkpoint["input_prefix_sha256"] == full_digest(workspace["input"])


# ---------------------------------------------------------------------------
# v3 resume integrity: history rewrites must not be skipped
# --------------------------------------------------------------------------- #


def _v3_after_first_run(workspace, events):
    write_events(workspace["input"], events)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])
    return read_checkpoint(workspace)


def test_v3_tampered_history_line_raises_checkpoint_error(workspace):
    events = interlocked_events()
    checkpoint = _v3_after_first_run(workspace, events)
    output_before = workspace["output"].read_text()

    # Rewrite a previously processed event (a new event_id keeps the input
    # structurally valid) but leave the appended tail untouched in shape.
    tampered = dict(events[0])
    tampered["event_id"] = "A1-REWRITE"
    rest = [json.dumps(e) + "\n" for e in events[1:]]
    workspace["input"].write_text(
        json.dumps(tampered) + "\n" + "".join(rest), encoding="utf-8"
    )

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])

    # Nothing is published or advanced on an integrity failure.
    assert workspace["output"].read_text() == output_before
    assert read_checkpoint(workspace) == checkpoint


def test_v3_tampered_history_is_rejected_even_if_cursor_would_skip_it(workspace):
    # The core threat model: an old (chain_id, sequence) row is rewritten after
    # its cursor advanced. The digest guard must reject the run instead of
    # silently skipping the changed row.
    events = three_events()
    _v3_after_first_run(workspace, events)
    output_before = workspace["output"].read_text()
    checkpoint_before = workspace["checkpoint"].read_text()
    changed = dict(events[0])
    changed["event_id"] = "A-rewritten"
    # Changing only the proof keeps timestamps/sequences structurally valid.
    changed["proof"] = dict(changed["proof"], quorum=99)
    workspace["input"].write_text(
        "".join(json.dumps(e) + "\n" for e in [changed, *events[1:]]),
        encoding="utf-8",
    )

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])

    # The previously published row for the old (chain-7, 1) is not replaced or
    # duplicated, and the checkpoint stays at its honest value.
    assert workspace["output"].read_text() == output_before
    assert workspace["checkpoint"].read_text() == checkpoint_before


def test_v3_digest_mismatch_via_edited_digest_raises_checkpoint_error(workspace):
    _v3_after_first_run(workspace, three_events())
    checkpoint = read_checkpoint(workspace)
    checkpoint["input_prefix_sha256"] = "0" * 64
    workspace["checkpoint"].write_text(json.dumps(checkpoint), encoding="utf-8")

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_processed_lines_zero_is_checkpoint_error(workspace):
    _v3_after_first_run(workspace, three_events())
    checkpoint = read_checkpoint(workspace)
    checkpoint["processed_lines"] = 0
    checkpoint["input_prefix_sha256"] = "0" * 64
    workspace["checkpoint"].write_text(json.dumps(checkpoint), encoding="utf-8")

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_processed_lines_negative_is_checkpoint_error(workspace):
    _v3_after_first_run(workspace, three_events())
    checkpoint = read_checkpoint(workspace)
    checkpoint["processed_lines"] = -3
    workspace["checkpoint"].write_text(json.dumps(checkpoint), encoding="utf-8")

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_processed_lines_beyond_input_is_checkpoint_error(workspace):
    _v3_after_first_run(workspace, three_events())
    checkpoint = read_checkpoint(workspace)
    checkpoint["processed_lines"] = 99
    workspace["checkpoint"].write_text(json.dumps(checkpoint), encoding="utf-8")

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_cursor_below_prefix_maximum_is_checkpoint_error(workspace):
    _v3_after_first_run(workspace, three_events())
    checkpoint = read_checkpoint(workspace)
    # Digest stays valid; only the cursor lies about how far chain-7 reached.
    checkpoint["last_sequence_by_chain"] = {"chain-7": 1}
    workspace["checkpoint"].write_text(json.dumps(checkpoint), encoding="utf-8")

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_cursor_above_prefix_maximum_is_checkpoint_error(workspace):
    events = interlocked_events()[:3]  # max chain-a = 2
    write_events(workspace["input"], events)
    digest = prefix_digest(workspace["input"], 3)
    workspace["checkpoint"].write_text(
        json.dumps(
            v3_checkpoint({"chain-a": 9, "chain-b": 1}, 3, digest)
        ),
        encoding="utf-8",
    )

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_missing_cursor_for_prefix_chain_is_checkpoint_error(workspace):
    events = interlocked_events()[:2]  # chain-a and chain-b both in prefix
    write_events(workspace["input"], events)
    digest = prefix_digest(workspace["input"], 2)
    workspace["checkpoint"].write_text(
        json.dumps(v3_checkpoint({"chain-a": 1}, 2, digest)), encoding="utf-8"
    )

    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_hand_built_midstream_checkpoint_resumes_tail(workspace):
    # Simulate a checkpoint committed after the first two physical lines of an
    # interleaved file (as if the process stopped mid-file): selection resumes
    # by (chain_id, sequence), output appends in line order, other chain cursor
    # preserved.
    events = interlocked_events()
    write_events(workspace["input"], events)
    digest = prefix_digest(workspace["input"], 2)
    workspace["checkpoint"].write_text(
        json.dumps(v3_checkpoint({"chain-a": 1, "chain-b": 1}, 2, digest)),
        encoding="utf-8",
    )
    workspace["output"].write_text(
        "".join(
            json.dumps(build_report_stub(e)) + "\n" for e in events[:2]
        ),
        encoding="utf-8",
    )

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-a", 2),
        ("chain-b", 2),
        ("chain-a", 3),
        ("chain-b", 3),
    ]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 3, "chain-b": 3}, 6, full_digest(workspace["input"])
    )


def build_report_stub(event):
    return {"chain_id": event["chain_id"], "sequence": event["sequence"]}


def test_v3_appended_incomplete_line_is_invalid_input(workspace):
    _v3_after_first_run(workspace, three_events())
    checkpoint_before = workspace["checkpoint"].read_text()
    output_before = workspace["output"].read_text()
    # Append bytes that do not form one complete JSON object line.
    workspace["input"].write_bytes(
        workspace["input"].read_bytes() + b'{"event_id":'
    )

    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert workspace["checkpoint"].read_text() == checkpoint_before
    assert workspace["output"].read_text() == output_before


def test_v3_appended_duplicate_sequence_is_invalid_input(workspace):
    events = three_events()
    _v3_after_first_run(workspace, events)
    dup = make_event(event_id="DUP", sequence=1)
    workspace["input"].write_text(
        "".join(json.dumps(e) + "\n" for e in events + [dup]),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_invalid_utf8_in_prefix_is_invalid_input(workspace):
    _v3_after_first_run(workspace, three_events())
    raw = bytearray(workspace["input"].read_bytes())
    raw[2] = 0xFF  # not valid UTF-8
    workspace["input"].write_bytes(bytes(raw))

    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


# ---------------------------------------------------------------------------
# v3 checkpoint structural validation -> InvalidInputError
# --------------------------------------------------------------------------- #


def write_v3_and_expect_invalid(workspace, raw, events=None):
    write_events(
        workspace["input"],
        events if events is not None else [make_event(sequence=1)],
    )
    workspace["checkpoint"].write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


def test_v3_checkpoint_requires_processed_lines(workspace):
    write_v3_and_expect_invalid(
        workspace,
        {
            "schema_version": 3,
            "last_sequence_by_chain": {"chain-7": 0},
            "input_prefix_sha256": "0" * 64,
        },
    )


def test_v3_checkpoint_requires_digest(workspace):
    write_v3_and_expect_invalid(
        workspace,
        {
            "schema_version": 3,
            "last_sequence_by_chain": {"chain-7": 0},
            "processed_lines": 1,
        },
    )


def test_v3_checkpoint_rejects_unknown_field(workspace):
    write_v3_and_expect_invalid(
        workspace,
        {
            "schema_version": 3,
            "last_sequence_by_chain": {"chain-7": 0},
            "processed_lines": 1,
            "input_prefix_sha256": "0" * 64,
            "extra": 1,
        },
    )


def test_v3_checkpoint_rejects_unknown_schema_version(workspace):
    write_v3_and_expect_invalid(
        workspace,
        {
            "schema_version": 4,
            "last_sequence_by_chain": {"chain-7": 0},
            "processed_lines": 1,
            "input_prefix_sha256": "0" * 64,
        },
    )


@pytest.mark.parametrize("bad_lines", [1.5, "1", True, False, None, [], {}])
def test_v3_checkpoint_rejects_non_integer_processed_lines(workspace, bad_lines):
    write_v3_and_expect_invalid(
        workspace,
        {
            "schema_version": 3,
            "last_sequence_by_chain": {"chain-7": 0},
            "processed_lines": bad_lines,
            "input_prefix_sha256": "0" * 64,
        },
    )


@pytest.mark.parametrize(
    "bad_digest",
    [
        "0" * 63,                       # too short
        "0" * 65,                       # too long
        ("A" + "0" * 63),               # uppercase
        ("g" + "0" * 63),               # non-hex character
        "0x" + "0" * 62,                # 0x prefix
        "",                             # empty
        123,                            # number
        None,                           # null
        ["0" * 64],                     # array
        {"digest": "0" * 64},           # object
    ],
)
def test_v3_checkpoint_rejects_non_lowercase_hex64_digest(workspace, bad_digest):
    write_v3_and_expect_invalid(
        workspace,
        {
            "schema_version": 3,
            "last_sequence_by_chain": {"chain-7": 0},
            "processed_lines": 1,
            "input_prefix_sha256": bad_digest,
        },
    )


def test_v3_checkpoint_still_rejects_bad_cursor_shapes(workspace):
    # v3 keeps the v2 split: null/array cursors are structural errors ...
    write_v3_and_expect_invalid(
        workspace,
        {
            "schema_version": 3,
            "last_sequence_by_chain": {"chain-7": None},
            "processed_lines": 1,
            "input_prefix_sha256": "0" * 64,
        },
    )


def test_v3_checkpoint_float_cursor_is_checkpoint_error(workspace):
    write_events(workspace["input"], [make_event(sequence=2)])
    workspace["checkpoint"].write_text(
        json.dumps(
            {
                "schema_version": 3,
                "last_sequence_by_chain": {"chain-7": 1.5},
                "processed_lines": 1,
                "input_prefix_sha256": "0" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


# ---------------------------------------------------------------------------
# v2 / legacy checkpoints remain readable; upgrade only on new results
# --------------------------------------------------------------------------- #


def test_v2_checkpoint_noop_is_left_untouched_without_forged_digest(workspace):
    write_events(workspace["input"], interlocked_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-a": 3, "chain-b": 3})),
        encoding="utf-8",
    )
    before = workspace["checkpoint"].read_text()

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert reports == []
    # No new results -> no upgrade, no fabricated integrity fields.
    assert workspace["checkpoint"].read_text() == before
    assert read_checkpoint(workspace)["schema_version"] == 2


def test_v2_checkpoint_upgrades_to_v3_only_after_new_results(workspace):
    events = interlocked_events()
    write_events(workspace["input"], events)
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-a": 3})), encoding="utf-8"
    )

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    # chain-a is fully consumed; only chain-b events produce new results.
    assert {r["chain_id"] for r in reports} == {"chain-b"}
    checkpoint = read_checkpoint(workspace)
    assert checkpoint["schema_version"] == 3
    assert checkpoint["last_sequence_by_chain"] == {"chain-a": 3, "chain-b": 3}
    assert checkpoint["processed_lines"] == 6
    assert checkpoint["input_prefix_sha256"] == full_digest(workspace["input"])


def test_v2_upgrade_commit_prefix_covers_cursor_only_lines_after_selected(
    workspace,
):
    # v2 knows only chain-b's cursor; chain-a is missing so all its events are
    # selected. The last physical line (chain-b seq 3) is covered solely by the
    # retained cursor and sits AFTER the last selected event. The upgraded v3
    # must nevertheless commit the whole valid file, otherwise its own cursor
    # for chain-b would disagree with its verified prefix on the next run.
    events = interlocked_events()  # a1 b1 a2 b2 a3 b3
    write_events(workspace["input"], events)
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-b": 3})), encoding="utf-8"
    )

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-a", 1),
        ("chain-a", 2),
        ("chain-a", 3),
    ]
    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 3, "chain-b": 3}, 6, full_digest(workspace["input"])
    )
    # The very next run must accept this checkpoint as a valid noop resume.
    assert run(workspace["input"], workspace["checkpoint"], workspace["output"]) == []


def test_v2_checkpoint_upgrades_under_tolerate_failures_with_failed_rows(
    workspace,
):
    write_events(workspace["input"], three_mixed_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-a": 0})), encoding="utf-8"
    )

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    checkpoint = read_checkpoint(workspace)
    assert checkpoint == v3_checkpoint(
        {"chain-a": 3}, 3, full_digest(workspace["input"])
    )


def test_legacy_checkpoint_noop_still_untouched(workspace):
    # Empty input against a legacy checkpoint: no results, still a noop and no
    # v3 fields fabricated.
    workspace["input"].write_text("", encoding="utf-8")
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 2}), encoding="utf-8"
    )
    before = workspace["checkpoint"].read_text()

    assert run(workspace["input"], workspace["checkpoint"], workspace["output"]) == []
    assert workspace["checkpoint"].read_text() == before


def test_v2_checkpoint_cursor_above_maximum_still_checkpoint_error(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-7": 99})), encoding="utf-8"
    )
    with pytest.raises(CheckpointError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])


# ---------------------------------------------------------------------------
# v3 integrity errors via the command line
# --------------------------------------------------------------------------- #


def test_cli_v3_digest_mismatch_is_fixed_json_nonzero_and_writes_nothing(
    workspace,
):
    events = three_events()
    write_events(workspace["input"], events)
    run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    output_before = workspace["output"].read_text()
    checkpoint_before = workspace["checkpoint"].read_text()

    tampered = dict(events[0])
    tampered["event_id"] = "A1-REWRITE"
    workspace["input"].write_text(
        "".join(json.dumps(e) + "\n" for e in [tampered, *events[1:]]),
        encoding="utf-8",
    )
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )

    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert payload["error"] == "CheckpointError"
    assert isinstance(payload["message"], str) and payload["message"]
    assert workspace["output"].read_text() == output_before
    assert workspace["checkpoint"].read_text() == checkpoint_before


def test_cli_v3_structural_checkpoint_error_is_invalid_input_error(workspace):
    write_events(workspace["input"], [make_event(sequence=1)])
    workspace["checkpoint"].write_text(
        json.dumps(
            {
                "schema_version": 3,
                "last_sequence_by_chain": {"chain-7": 0},
                "processed_lines": 1,
                "input_prefix_sha256": "NOT-HEX",
            }
        ),
        encoding="utf-8",
    )
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "InvalidInputError"
    assert not workspace["output"].exists()


def test_cli_first_run_writes_v3_checkpoint(workspace):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode == 0, result.stderr
    assert read_checkpoint(workspace)["schema_version"] == 3
    assert set(read_checkpoint(workspace)) == {
        "schema_version",
        "last_sequence_by_chain",
        "processed_lines",
        "input_prefix_sha256",
    }


# ---------------------------------------------------------------------------
# Sequence continuity inventory (--continuity-output)
# --------------------------------------------------------------------------- #


def read_continuity(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def test_continuity_single_chain_gaps_closed_intervals(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 2, "A2", 2000),
        chain_event("chain-a", 5, "A5", 3000),
        chain_event("chain-a", 6, "A6", 4000),
        chain_event("chain-a", 10, "A10", 5000),
    ]
    write_events(workspace["input"], events)
    continuity = workspace["output"].with_name("continuity.jsonl")

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )

    assert read_continuity(continuity) == [
        {
            "chain_id": "chain-a",
            "event_count": 5,
            "min_sequence": 1,
            "max_sequence": 10,
            "missing_ranges": [
                {"start": 3, "end": 4},
                {"start": 7, "end": 9},
            ],
            "missing_count": 5,
        }
    ]


def test_continuity_multichain_first_appearance_order_and_shared_sequences(
    workspace,
):
    # Both chains reuse sequence 2; gaps are computed per chain, rows follow
    # first appearance in the interleaved input.
    events = [
        chain_event("chain-b", 2, "B2", 1000),
        chain_event("chain-a", 2, "A2", 2000),
        chain_event("chain-b", 4, "B4", 3000),
        chain_event("chain-a", 3, "A3", 4000),
    ]
    write_events(workspace["input"], events)
    continuity = workspace["output"].with_name("continuity.jsonl")

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )

    assert read_continuity(continuity) == [
        {
            "chain_id": "chain-b",
            "event_count": 2,
            "min_sequence": 2,
            "max_sequence": 4,
            "missing_ranges": [{"start": 3, "end": 3}],
            "missing_count": 1,
        },
        {
            "chain_id": "chain-a",
            "event_count": 2,
            "min_sequence": 2,
            "max_sequence": 3,
            "missing_ranges": [],
            "missing_count": 0,
        },
    ]


def test_continuity_sequence_may_start_above_zero_without_gap(workspace):
    write_events(
        workspace["input"],
        [
            chain_event("chain-a", 7, "A7", 1000),
            chain_event("chain-a", 8, "A8", 2000),
        ],
    )
    continuity = workspace["output"].with_name("continuity.jsonl")

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )

    rows = read_continuity(continuity)
    assert rows[0]["min_sequence"] == 7
    assert rows[0]["missing_ranges"] == []
    assert rows[0]["missing_count"] == 0


def test_continuity_single_event_has_empty_ranges(workspace):
    write_events(workspace["input"], [make_event(sequence=4)])
    continuity = workspace["output"].with_name("continuity.jsonl")

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )

    assert read_continuity(continuity) == [
        {
            "chain_id": "chain-7",
            "event_count": 1,
            "min_sequence": 4,
            "max_sequence": 4,
            "missing_ranges": [],
            "missing_count": 0,
        }
    ]


def test_continuity_empty_input_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    continuity = workspace["output"].with_name("continuity.jsonl")

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )

    assert continuity.exists()
    assert continuity.read_text(encoding="utf-8") == ""


def test_continuity_omitted_writes_nothing_and_behavior_unchanged(workspace):
    write_events(workspace["input"], three_events())
    continuity = workspace["output"].with_name("continuity.jsonl")

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [r["sequence"] for r in reports] == [1, 2, 3]
    assert not continuity.exists()
    assert read_checkpoint(workspace) == v3_checkpoint(
        {"chain-7": 3}, 3, full_digest(workspace["input"])
    )


def test_continuity_covers_whole_input_across_resume_and_append(workspace):
    first_batch = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 4, "A4", 2000),
    ]
    write_events(workspace["input"], first_batch)
    continuity = workspace["output"].with_name("continuity.jsonl")
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )

    # Append a later event; the resumed run inventories the whole file, not
    # just the newly selected tail.
    second_batch = first_batch + [chain_event("chain-a", 7, "A7", 3000)]
    write_events(workspace["input"], second_batch)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )
    assert [r["sequence"] for r in reports] == [7]

    expected = [
        {
            "chain_id": "chain-a",
            "event_count": 3,
            "min_sequence": 1,
            "max_sequence": 7,
            "missing_ranges": [
                {"start": 2, "end": 3},
                {"start": 5, "end": 6},
            ],
            "missing_count": 4,
        }
    ]
    assert read_continuity(continuity) == expected

    # A no-op rerun rewrites the identical inventory.
    again = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )
    assert again == []
    assert read_continuity(continuity) == expected


def test_continuity_tolerate_failures_failed_event_still_occupies_sequence(
    workspace,
):
    write_events(workspace["input"], three_mixed_events())  # good, bad, good
    continuity = workspace["output"].with_name("continuity.jsonl")

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
        continuity_output=continuity,
    )

    # The failed seq-2 event still holds its sequence: no gap is reported.
    assert read_continuity(continuity) == [
        {
            "chain_id": "chain-a",
            "event_count": 3,
            "min_sequence": 1,
            "max_sequence": 3,
            "missing_ranges": [],
            "missing_count": 0,
        }
    ]


def test_continuity_strict_proof_failure_writes_nothing(workspace):
    write_events(workspace["input"], three_mixed_events())
    continuity = workspace["output"].with_name("continuity.jsonl")

    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            continuity_output=continuity,
        )

    assert not continuity.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_continuity_invalid_input_writes_nothing(workspace):
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    continuity = workspace["output"].with_name("continuity.jsonl")

    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            continuity_output=continuity,
        )

    assert not continuity.exists()


def test_continuity_checkpoint_error_writes_nothing(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-7": 99})), encoding="utf-8"
    )
    continuity = workspace["output"].with_name("continuity.jsonl")

    with pytest.raises(CheckpointError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            continuity_output=continuity,
        )

    assert not continuity.exists()
    assert not workspace["output"].exists()


def test_continuity_does_not_participate_in_cursor_or_report(workspace):
    write_events(workspace["input"], three_events())
    continuity = workspace["output"].with_name("continuity.jsonl")

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
    )

    # Report rows keep their exact field set; the checkpoint is plain v3.
    row = json.loads(workspace["output"].read_text().splitlines()[0])
    assert set(row) == {
        "event_id",
        "chain_id",
        "sequence",
        "proof_status",
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
        "attribution",
        "finalized_at",
    }
    assert set(read_checkpoint(workspace)) == {
        "schema_version",
        "last_sequence_by_chain",
        "processed_lines",
        "input_prefix_sha256",
    }


def test_cli_continuity_output_success(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 3, "A3", 2000),
    ]
    write_events(workspace["input"], events)
    continuity = workspace["output"].with_name("continuity.jsonl")

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--continuity-output", str(continuity),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert read_continuity(continuity) == [
        {
            "chain_id": "chain-a",
            "event_count": 2,
            "min_sequence": 1,
            "max_sequence": 3,
            "missing_ranges": [{"start": 2, "end": 2}],
            "missing_count": 1,
        }
    ]


def test_cli_continuity_output_omitted_is_unchanged(workspace):
    write_events(workspace["input"], [make_event()])
    continuity = workspace["output"].with_name("continuity.jsonl")
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode == 0, result.stderr
    assert workspace["output"].exists()
    assert not continuity.exists()


def test_cli_continuity_output_unwritable_path_is_oserror_json(workspace):
    write_events(workspace["input"], [make_event()])
    missing_dir = workspace["output"].with_name("no-such-dir")
    # Block makedirs by placing a regular file where the directory must be.
    missing_dir.write_text("not a directory", encoding="utf-8")
    continuity = missing_dir / "continuity.jsonl"

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--continuity-output", str(continuity),
    )

    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert payload["error"] in {"OSError", "FileExistsError", "NotADirectoryError"}
    assert isinstance(payload["message"], str) and payload["message"]


def test_cli_continuity_domain_error_leaves_no_continuity_file(workspace):
    write_events(workspace["input"], three_mixed_events())
    continuity = workspace["output"].with_name("continuity.jsonl")

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--continuity-output", str(continuity),
    )

    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not continuity.exists()
    assert not workspace["output"].exists()

# ---------------------------------------------------------------------------
# Latency breach inventory (latency_thresholds / latency_breach_output)
# --------------------------------------------------------------------------- #


def read_breaches(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def write_thresholds(path, payload):
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")


DEFAULT_THRESHOLDS = {
    "proof_latency_ms": 0,
    "relay_latency_ms": 0,
    "destination_latency_ms": 0,
}


def run_breaches(workspace, thresholds=DEFAULT_THRESHOLDS, **kwargs):
    breach = workspace["output"].with_name("breach.jsonl")
    thresholds_path = workspace["output"].with_name("thresholds.json")
    write_thresholds(thresholds_path, thresholds)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_thresholds=thresholds_path,
        latency_breach_output=breach,
        **kwargs,
    )
    return reports, breach


def test_breach_rows_strict_greater_than_and_stage_order(workspace):
    # three_events latencies:
    # seq1: proof 400, relay 500, destination 900
    # seq2: proof 400, relay 499, destination 900
    # seq3: proof 400, relay 499, destination 900
    write_events(workspace["input"], three_events())
    thresholds = {
        "proof_latency_ms": 399,
        "relay_latency_ms": 499,   # equal to seq2/seq3 relay -> no breach
        "destination_latency_ms": 899,
    }
    reports, breach = run_breaches(workspace, thresholds)
    assert len(reports) == 3

    rows = read_breaches(breach)
    assert rows == [
        {
            "event_id": "A",
            "chain_id": "chain-7",
            "sequence": 1,
            "proof_status": "verified",
            "breached_stages": [
                "proof_latency_ms",
                "relay_latency_ms",
                "destination_latency_ms",
            ],
            "attribution": "destination",
            "finalized_at": 2400,
        },
        {
            "event_id": "B",
            "chain_id": "chain-7",
            "sequence": 2,
            "proof_status": "verified",
            "breached_stages": ["proof_latency_ms", "destination_latency_ms"],
            "attribution": "destination",
            "finalized_at": 3400,
        },
        {
            "event_id": "C",
            "chain_id": "chain-7",
            "sequence": 3,
            "proof_status": "verified",
            "breached_stages": ["proof_latency_ms", "destination_latency_ms"],
            "attribution": "destination",
            "finalized_at": 5400,
        },
    ]
    # Exact field set on every row.
    for row in rows:
        assert set(row) == {
            "event_id",
            "chain_id",
            "sequence",
            "proof_status",
            "breached_stages",
            "attribution",
            "finalized_at",
        }


def test_breach_equal_threshold_is_not_a_breach(workspace):
    # Latencies are exactly 400/500/900; thresholds equal to them -> empty file.
    write_events(workspace["input"], [make_event()])
    thresholds = {
        "proof_latency_ms": 400,
        "relay_latency_ms": 500,
        "destination_latency_ms": 900,
    }
    _reports, breach = run_breaches(workspace, thresholds)
    assert breach.exists()
    assert breach.read_text(encoding="utf-8") == ""


def test_breach_zero_thresholds_lists_every_positive_stage(workspace):
    write_events(workspace["input"], [make_event()])
    _reports, breach = run_breaches(workspace, DEFAULT_THRESHOLDS)
    rows = read_breaches(breach)
    assert len(rows) == 1
    assert rows[0]["breached_stages"] == [
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
    ]


def test_breach_preserves_input_line_order(workspace):
    write_events(workspace["input"], interlocked_events())
    _reports, breach = run_breaches(workspace, DEFAULT_THRESHOLDS)
    rows = read_breaches(breach)
    assert [(r["chain_id"], r["sequence"]) for r in rows] == [
        ("chain-a", 1),
        ("chain-b", 1),
        ("chain-a", 2),
        ("chain-b", 2),
        ("chain-a", 3),
        ("chain-b", 3),
    ]


def test_breach_failed_report_rows_participate_in_isolation_mode(workspace):
    # seq 2 fails proof verification but still has latencies 400/499/900.
    write_events(workspace["input"], three_mixed_events())
    _reports, breach = run_breaches(
        workspace, DEFAULT_THRESHOLDS, tolerate_failures=True
    )
    rows = read_breaches(breach)
    assert [r["sequence"] for r in rows] == [1, 2, 3]
    failed = rows[1]
    assert failed["proof_status"] == "failed"
    assert failed["breached_stages"] == [
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
    ]


def test_breach_no_new_events_on_resume_writes_empty_file(workspace):
    write_events(workspace["input"], three_events())
    _first, breach = run_breaches(workspace, DEFAULT_THRESHOLDS)
    assert len(read_breaches(breach)) == 3
    # Rerun selects nothing: previously published breaches are not rechecked.
    second, breach2 = run_breaches(workspace, DEFAULT_THRESHOLDS)
    assert second == []
    assert breach2.read_text(encoding="utf-8") == ""


def test_breach_resume_covers_only_newly_produced_report_rows(workspace):
    events = three_events()
    write_events(workspace["input"], events)
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    write_thresholds(thresholds_path, DEFAULT_THRESHOLDS)
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_thresholds=thresholds_path,
        latency_breach_output=breach,
    )
    assert len(read_breaches(breach)) == 3

    appended = events + [
        make_event(
            event_id="D",
            sequence=4,
            observed_at=6001,
            proof_submitted_at=6100,
            proof_verified_at=6500,
            finalized_at=7400,
        )
    ]
    write_events(workspace["input"], appended)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_thresholds=thresholds_path,
        latency_breach_output=breach,
    )
    assert [r["sequence"] for r in reports] == [4]
    # The atomic rewrite holds only this run's breaches (the new seq-4 row),
    # not the three historical rows already in the accumulated report.
    rows = read_breaches(breach)
    assert [(r["sequence"], r["proof_status"]) for r in rows] == [(4, "verified")]


def test_breach_does_not_change_report_or_checkpoint_fields(workspace):
    write_events(workspace["input"], [make_event()])
    run_breaches(workspace, DEFAULT_THRESHOLDS)
    row = json.loads(workspace["output"].read_text().splitlines()[0])
    assert set(row) == {
        "event_id",
        "chain_id",
        "sequence",
        "proof_status",
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
        "attribution",
        "finalized_at",
    }
    assert set(read_checkpoint(workspace)) == {
        "schema_version",
        "last_sequence_by_chain",
        "processed_lines",
        "input_prefix_sha256",
    }


@pytest.mark.parametrize(
    "payload",
    [
        "nope",                                       # malformed JSON
        "[]",                                         # not an object
        "{}",                                         # missing all fields
        json.dumps(                                    # missing one field
            {"proof_latency_ms": 1, "relay_latency_ms": 1}
        ),
        json.dumps(                                    # unknown field
            {
                "proof_latency_ms": 1,
                "relay_latency_ms": 1,
                "destination_latency_ms": 1,
                "extra": 1,
            }
        ),
        json.dumps(                                    # negative
            {
                "proof_latency_ms": -1,
                "relay_latency_ms": 1,
                "destination_latency_ms": 1,
            }
        ),
        json.dumps(                                    # float
            {
                "proof_latency_ms": 1.5,
                "relay_latency_ms": 1,
                "destination_latency_ms": 1,
            }
        ),
        json.dumps(                                    # boolean
            {
                "proof_latency_ms": True,
                "relay_latency_ms": 1,
                "destination_latency_ms": 1,
            }
        ),
        json.dumps(                                    # null
            {
                "proof_latency_ms": None,
                "relay_latency_ms": 1,
                "destination_latency_ms": 1,
            }
        ),
        json.dumps(                                    # string
            {
                "proof_latency_ms": "1",
                "relay_latency_ms": 1,
                "destination_latency_ms": 1,
            }
        ),
    ],
)
def test_breach_invalid_thresholds_raise_invalid_input(workspace, payload):
    write_events(workspace["input"], [make_event()])
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    write_thresholds(thresholds_path, payload)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_thresholds=thresholds_path,
            latency_breach_output=breach,
        )
    assert not breach.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_breach_zero_is_a_valid_threshold(workspace):
    write_events(workspace["input"], [make_event()])
    # No exception: zero thresholds are accepted (covered via run_breaches).
    run_breaches(workspace, DEFAULT_THRESHOLDS)


def test_breach_invalid_utf8_thresholds_raise_invalid_input(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    thresholds_path.write_bytes(b"\xff\xfe{")
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_thresholds=thresholds_path,
            latency_breach_output=breach,
        )
    assert not breach.exists()


def test_breach_arguments_must_be_paired_in_api(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    write_thresholds(thresholds_path, DEFAULT_THRESHOLDS)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_thresholds=thresholds_path,
        )
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_breach_output=breach,
        )
    assert not breach.exists()


def test_breach_strict_proof_failure_writes_nothing(workspace):
    write_events(workspace["input"], three_mixed_events())
    with pytest.raises(ProofVerificationError):
        run_breaches(workspace, DEFAULT_THRESHOLDS)
    breach = workspace["output"].with_name("breach.jsonl")
    assert not breach.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_breach_invalid_input_writes_nothing(workspace):
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    write_thresholds(thresholds_path, DEFAULT_THRESHOLDS)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_thresholds=thresholds_path,
            latency_breach_output=breach,
        )
    assert not breach.exists()


def test_breach_checkpoint_error_writes_nothing(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-7": 99})), encoding="utf-8"
    )
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    write_thresholds(thresholds_path, DEFAULT_THRESHOLDS)
    with pytest.raises(CheckpointError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_thresholds=thresholds_path,
            latency_breach_output=breach,
        )
    assert not breach.exists()
    assert not workspace["output"].exists()


def test_breach_omitted_writes_nothing_and_behavior_unchanged(workspace):
    write_events(workspace["input"], three_events())
    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert [r["sequence"] for r in reports] == [1, 2, 3]
    assert not workspace["output"].with_name("breach.jsonl").exists()
    assert read_checkpoint(workspace) == v3_checkpoint(
        {"chain-7": 3}, 3, full_digest(workspace["input"])
    )


def test_cli_breach_output_success(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    write_thresholds(thresholds, DEFAULT_THRESHOLDS)
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-thresholds", str(thresholds),
        "--latency-breach-output", str(breach),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rows = read_breaches(breach)
    assert len(rows) == 1
    assert rows[0]["event_id"] == "E1"
    assert rows[0]["breached_stages"] == [
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
    ]


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--latency-thresholds", "thresholds.json"],
        ["--latency-breach-output", "breach.jsonl"],
    ],
)
def test_cli_breach_arguments_must_be_paired(workspace, extra_args):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        *extra_args,
    )
    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert set(payload.keys()) == {"error", "message"}
    assert payload["error"] == "InvalidArgument"
    assert not workspace["output"].exists()


def test_cli_breach_invalid_thresholds_is_invalid_input_error(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    thresholds.write_text("nope", encoding="utf-8")
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-thresholds", str(thresholds),
        "--latency-breach-output", str(breach),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "InvalidInputError"
    assert not breach.exists()
    assert not workspace["output"].exists()


def test_cli_breach_missing_thresholds_file_is_oserror(workspace):
    write_events(workspace["input"], [make_event()])
    breach = workspace["output"].with_name("breach.jsonl")
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-thresholds", str(workspace["output"].with_name("missing.json")),
        "--latency-breach-output", str(breach),
    )
    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert payload["error"] == "FileNotFoundError"
    assert isinstance(payload["message"], str) and payload["message"]
    assert not breach.exists()


def test_cli_breach_unwritable_output_is_oserror_json(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds = workspace["output"].with_name("thresholds.json")
    write_thresholds(thresholds, DEFAULT_THRESHOLDS)
    blocked = workspace["output"].with_name("not-a-dir")
    blocked.write_text("not a directory", encoding="utf-8")
    breach = blocked / "breach.jsonl"
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-thresholds", str(thresholds),
        "--latency-breach-output", str(breach),
    )
    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert payload["error"] in {"OSError", "FileExistsError", "NotADirectoryError"}
    assert isinstance(payload["message"], str) and payload["message"]


def test_cli_breach_strict_failure_leaves_no_breach_file(workspace):
    write_events(workspace["input"], three_mixed_events())
    thresholds = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    write_thresholds(thresholds, DEFAULT_THRESHOLDS)
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-thresholds", str(thresholds),
        "--latency-breach-output", str(breach),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not breach.exists()
    assert not workspace["output"].exists()


# ---------------------------------------------------------------------------
# Chain-level latency profile (latency_profile_output)
# --------------------------------------------------------------------------- #


def read_profile(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def latency_event(chain_id, sequence, event_id, base, proof, relay, destination):
    """A verifiable event with exact proof/relay/destination latencies.

    base values are spaced far apart (>= 1_000_000) so every timestamp column
    stays globally unique even with sizeable latency offsets. The observed
    instant is derived as verify - relay (it may sit anywhere relative to the
    on-chain instants; only submit <= verify <= finalize is enforced).
    """
    submit = base + 100
    verify = submit + proof
    finalize = verify + destination
    observed = verify - relay
    return on_chain(
        chain_id,
        event_id=event_id,
        sequence=sequence,
        observed_at=observed,
        proof_submitted_at=submit,
        proof_verified_at=verify,
        finalized_at=finalize,
    )


PROFILE_PATH_NAME = "profile.jsonl"


def run_profile(workspace, events=None, **kwargs):
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)
    if events is not None:
        write_events(workspace["input"], events)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_profile_output=profile,
        **kwargs,
    )
    return reports, profile


@pytest.mark.parametrize(
    "n,quantile,expected_value",
    [
        (1, 0.50, 1),     # rank max(1, ceil(0.5)) = 1
        (1, 0.95, 1),
        (2, 0.50, 1),     # rank ceil(1.0) = 1 (smaller of the two)
        (3, 0.50, 2),     # rank ceil(1.5) = 2
        (4, 0.50, 2),
        (20, 0.95, 19),   # rank ceil(19.0) = 19, not the maximum
        (40, 0.95, 38),
        (10, 0.95, 10),   # rank ceil(9.5) = 10
    ],
)
def test_profile_nearest_rank(n, quantile, expected_value):
    values = list(range(1, n + 1))
    assert _nearest_rank(values, quantile) == expected_value


def test_profile_single_chain_distribution_and_field_sets(workspace):
    events = [
        latency_event("chain-a", 1, "A1", 1_000_000, 100, 500, 50),
        latency_event("chain-a", 2, "A2", 2_000_000, 400, 600, 90),
        latency_event("chain-a", 3, "A3", 3_000_000, 200, 700, 20),
        latency_event("chain-a", 4, "A4", 4_000_000, 300, 800, 70),
    ]
    _reports, profile = run_profile(workspace, events)

    rows = read_profile(profile)
    assert rows == [
        {
            "chain_id": "chain-a",
            "event_count": 4,
            "proof_latency_ms": {"min": 100, "p50": 200, "p95": 400, "max": 400},
            "relay_latency_ms": {"min": 500, "p50": 600, "p95": 800, "max": 800},
            "destination_latency_ms": {
                "min": 20,
                "p50": 50,
                "p95": 90,
                "max": 90,
            },
            "attribution_counts": {"source": 0, "relay": 4, "destination": 0},
        }
    ]
    assert set(rows[0]) == {
        "chain_id",
        "event_count",
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
        "attribution_counts",
    }
    for name in (
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
    ):
        assert set(rows[0][name]) == {"min", "p50", "p95", "max"}
    assert set(rows[0]["attribution_counts"]) == {
        "source",
        "relay",
        "destination",
    }


def test_profile_p95_is_nearest_rank_not_max_at_n20(workspace):
    events = [
        latency_event(
            "chain-a", i, f"A{i}", (i + 1) * 10_000_000,
            proof=i * 10, relay=100, destination=5,
        )
        for i in range(1, 21)
    ]
    _reports, profile = run_profile(workspace, events)

    rows = read_profile(profile)
    assert len(rows) == 1
    row = rows[0]
    assert row["event_count"] == 20
    # proof latencies are exactly 10..200 ms.
    assert row["proof_latency_ms"] == {"min": 10, "p50": 100, "p95": 190, "max": 200}
    # Constant columns collapse: all four stats coincide.
    assert row["relay_latency_ms"] == {"min": 100, "p50": 100, "p95": 100, "max": 100}
    assert row["destination_latency_ms"] == {"min": 5, "p50": 5, "p95": 5, "max": 5}


def test_profile_single_event_four_stats_coincide(workspace):
    _reports, profile = run_profile(workspace, [make_event()])

    rows = read_profile(profile)
    assert rows == [
        {
            "chain_id": "chain-7",
            "event_count": 1,
            "proof_latency_ms": {"min": 400, "p50": 400, "p95": 400, "max": 400},
            "relay_latency_ms": {"min": 500, "p50": 500, "p95": 500, "max": 500},
            "destination_latency_ms": {
                "min": 900,
                "p50": 900,
                "p95": 900,
                "max": 900,
            },
            "attribution_counts": {"source": 0, "relay": 0, "destination": 1},
        }
    ]


def test_profile_multichain_first_appearance_order_and_per_chain_stats(
    workspace,
):
    # Both chains reuse sequences 1 and 2; chain-b appears first in line order.
    events = [
        latency_event("chain-b", 1, "B1", 1_000_000, 100, 500, 50),
        latency_event("chain-a", 1, "A1", 2_000_000, 400, 600, 90),
        latency_event("chain-b", 2, "B2", 3_000_000, 300, 700, 20),
        latency_event("chain-a", 2, "A2", 4_000_000, 200, 800, 70),
    ]
    _reports, profile = run_profile(workspace, events)

    assert read_profile(profile) == [
        {
            "chain_id": "chain-b",
            "event_count": 2,
            "proof_latency_ms": {"min": 100, "p50": 100, "p95": 300, "max": 300},
            "relay_latency_ms": {"min": 500, "p50": 500, "p95": 700, "max": 700},
            "destination_latency_ms": {
                "min": 20,
                "p50": 20,
                "p95": 50,
                "max": 50,
            },
            "attribution_counts": {"source": 0, "relay": 2, "destination": 0},
        },
        {
            "chain_id": "chain-a",
            "event_count": 2,
            "proof_latency_ms": {"min": 200, "p50": 200, "p95": 400, "max": 400},
            "relay_latency_ms": {"min": 600, "p50": 600, "p95": 800, "max": 800},
            "destination_latency_ms": {
                "min": 70,
                "p50": 70,
                "p95": 90,
                "max": 90,
            },
            "attribution_counts": {"source": 0, "relay": 2, "destination": 0},
        },
    ]


def test_profile_attribution_counts_follow_existing_attribution(workspace):
    # source wins twice, relay once, destination once; absent attributions are 0.
    events = [
        latency_event("chain-a", 1, "A1", 1_000_000, 100, 50, 40),   # source
        latency_event("chain-a", 2, "A2", 2_000_000, 50, 200, 60),   # relay
        latency_event("chain-a", 3, "A3", 3_000_000, 50, 60, 300),   # destination
        latency_event("chain-a", 4, "A4", 4_000_000, 100, 50, 40),   # source
    ]
    _reports, profile = run_profile(workspace, events)

    rows = read_profile(profile)
    assert rows[0]["attribution_counts"] == {
        "source": 2,
        "relay": 1,
        "destination": 1,
    }


def test_profile_isolation_mode_failed_rows_are_counted(workspace):
    # three_mixed_events: verified seq1, failed seq2, verified seq3; all share
    # the 400/500/400 latency block and a relay attribution.
    _reports, profile = run_profile(
        workspace, three_mixed_events(), tolerate_failures=True
    )

    rows = read_profile(profile)
    assert rows == [
        {
            "chain_id": "chain-a",
            "event_count": 3,
            "proof_latency_ms": {"min": 400, "p50": 400, "p95": 400, "max": 400},
            "relay_latency_ms": {"min": 500, "p50": 500, "p95": 500, "max": 500},
            "destination_latency_ms": {
                "min": 400,
                "p50": 400,
                "p95": 400,
                "max": 400,
            },
            "attribution_counts": {"source": 0, "relay": 3, "destination": 0},
        }
    ]


def test_profile_empty_input_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    _reports, profile = run_profile(workspace)

    assert profile.exists()
    assert profile.read_text(encoding="utf-8") == ""


def test_profile_omitted_writes_nothing_and_behavior_unchanged(workspace):
    write_events(workspace["input"], three_events())
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [r["sequence"] for r in reports] == [1, 2, 3]
    assert not profile.exists()
    assert read_checkpoint(workspace) == v3_checkpoint(
        {"chain-7": 3}, 3, full_digest(workspace["input"])
    )


def test_profile_covers_whole_input_across_resume_and_append(workspace):
    first_batch = [
        latency_event("chain-a", 1, "A1", 1_000_000, 400, 500, 400),
        latency_event("chain-a", 4, "A4", 2_000_000, 400, 500, 400),
    ]
    write_events(workspace["input"], first_batch)
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_profile_output=profile,
    )
    assert read_profile(profile)[0]["event_count"] == 2

    second_batch = first_batch + [
        latency_event("chain-a", 7, "A7", 3_000_000, 400, 500, 400)
    ]
    write_events(workspace["input"], second_batch)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_profile_output=profile,
    )
    # Only the appended event is selected, yet the profile covers all three.
    assert [r["sequence"] for r in reports] == [7]
    expected = [
        {
            "chain_id": "chain-a",
            "event_count": 3,
            "proof_latency_ms": {"min": 400, "p50": 400, "p95": 400, "max": 400},
            "relay_latency_ms": {"min": 500, "p50": 500, "p95": 500, "max": 500},
            "destination_latency_ms": {
                "min": 400,
                "p50": 400,
                "p95": 400,
                "max": 400,
            },
            "attribution_counts": {"source": 0, "relay": 3, "destination": 0},
        }
    ]
    assert read_profile(profile) == expected

    # A no-op rerun (no newly selected rows) rewrites the identical profile.
    again = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_profile_output=profile,
    )
    assert again == []
    assert read_profile(profile) == expected


def test_profile_atomically_replaces_stale_file(workspace):
    write_events(workspace["input"], [make_event()])
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)
    profile.write_text("STALE\n", encoding="utf-8")

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_profile_output=profile,
    )

    rows = read_profile(profile)
    assert len(rows) == 1
    assert rows[0]["chain_id"] == "chain-7"


def test_profile_strict_proof_failure_writes_nothing(workspace):
    write_events(workspace["input"], three_mixed_events())
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_profile_output=profile,
        )

    assert not profile.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_profile_invalid_input_writes_nothing(workspace):
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_profile_output=profile,
        )

    assert not profile.exists()


def test_profile_checkpoint_error_writes_nothing(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-7": 99})), encoding="utf-8"
    )
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    with pytest.raises(CheckpointError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_profile_output=profile,
        )

    assert not profile.exists()
    assert not workspace["output"].exists()


def test_profile_does_not_change_report_checkpoint_or_breach(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    write_thresholds(thresholds_path, DEFAULT_THRESHOLDS)
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_thresholds=thresholds_path,
        latency_breach_output=breach,
        latency_profile_output=profile,
    )

    # Every artifact is published and keeps its exact established field set.
    row = json.loads(workspace["output"].read_text().splitlines()[0])
    assert set(row) == {
        "event_id",
        "chain_id",
        "sequence",
        "proof_status",
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
        "attribution",
        "finalized_at",
    }
    assert set(read_checkpoint(workspace)) == {
        "schema_version",
        "last_sequence_by_chain",
        "processed_lines",
        "input_prefix_sha256",
    }
    assert set(read_breaches(breach)[0]) == {
        "event_id",
        "chain_id",
        "sequence",
        "proof_status",
        "breached_stages",
        "attribution",
        "finalized_at",
    }
    assert len(read_profile(profile)) == 1


def test_profile_unwritable_path_raises_oserror_after_publish(workspace):
    write_events(workspace["input"], [make_event()])
    blocked = workspace["output"].with_name("not-a-dir")
    blocked.write_text("not a directory", encoding="utf-8")
    profile = blocked / PROFILE_PATH_NAME

    with pytest.raises(OSError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            latency_profile_output=profile,
        )

    # The profile is published last-but-one; report and checkpoint are already
    # safely on disk when its write fails.
    assert not profile.exists()
    assert workspace["output"].exists()
    assert read_checkpoint(workspace)["schema_version"] == 3


def test_cli_profile_output_success(workspace):
    events = [
        latency_event("chain-a", 1, "A1", 1_000_000, 100, 500, 50),
        latency_event("chain-a", 2, "A2", 2_000_000, 400, 800, 90),
    ]
    write_events(workspace["input"], events)
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-profile-output", str(profile),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rows = read_profile(profile)
    assert rows == [
        {
            "chain_id": "chain-a",
            "event_count": 2,
            "proof_latency_ms": {"min": 100, "p50": 100, "p95": 400, "max": 400},
            "relay_latency_ms": {"min": 500, "p50": 500, "p95": 800, "max": 800},
            "destination_latency_ms": {
                "min": 50,
                "p50": 50,
                "p95": 90,
                "max": 90,
            },
            "attribution_counts": {"source": 0, "relay": 2, "destination": 0},
        }
    ]


def test_cli_profile_output_omitted_is_unchanged(workspace):
    write_events(workspace["input"], [make_event()])
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode == 0, result.stderr
    assert workspace["output"].exists()
    assert not profile.exists()


def test_cli_profile_unwritable_path_is_oserror_json(workspace):
    write_events(workspace["input"], [make_event()])
    blocked = workspace["output"].with_name("no-such-dir")
    blocked.write_text("not a directory", encoding="utf-8")
    profile = blocked / PROFILE_PATH_NAME

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-profile-output", str(profile),
    )

    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert set(payload.keys()) == {"error", "message"}
    assert payload["error"] in {"OSError", "FileExistsError", "NotADirectoryError"}
    assert isinstance(payload["message"], str) and payload["message"]


def test_cli_profile_isolation_mode_counts_failed_rows(workspace):
    write_events(workspace["input"], three_mixed_events())
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--tolerate-failures",
        "--latency-profile-output", str(profile),
    )

    assert result.returncode == 0, result.stderr
    rows = read_profile(profile)
    assert len(rows) == 1
    assert rows[0]["event_count"] == 3
    assert rows[0]["attribution_counts"] == {
        "source": 0,
        "relay": 3,
        "destination": 0,
    }


def test_cli_profile_strict_failure_leaves_no_profile_file(workspace):
    write_events(workspace["input"], three_mixed_events())
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-profile-output", str(profile),
    )

    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not profile.exists()
    assert not workspace["output"].exists()


def test_cli_profile_empty_input_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--latency-profile-output", str(profile),
    )

    assert result.returncode == 0, result.stderr
    assert profile.exists()
    assert profile.read_text(encoding="utf-8") == ""

# ---------------------------------------------------------------------------
# Chain-level SLO summary (chain_slo_thresholds / chain_health_output)
# --------------------------------------------------------------------------- #


CHAIN_SLO_PATH_NAME = "health.jsonl"

# Every metric exactly at its threshold: a healthy chain produces [].
CHAIN_SLO_ZERO_THRESHOLDS = {
    "proof_failure_rate_permille": 0,
    "missing_sequence_rate_permille": 0,
    "proof_latency_ms_p95": 0,
    "relay_latency_ms_p95": 0,
    "destination_latency_ms_p95": 0,
}


def read_health(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def write_slo(path, payload):
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")


def run_slo(workspace, thresholds=CHAIN_SLO_ZERO_THRESHOLDS, **kwargs):
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    slo_path = workspace["output"].with_name("slo.json")
    write_slo(slo_path, thresholds)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        chain_slo_thresholds=slo_path,
        chain_health_output=health,
        **kwargs,
    )
    return reports, health


def test_chain_health_single_chain_rates_p95_and_violations(workspace):
    # 3 verified events, sequences 1/3/4 -> one missing sequence (2).
    # proof latencies 100/400/200 -> p95 nearest rank ceil(2.85)=3 -> 400
    # relay latencies 500/600/700 -> p95 700
    # destination latencies 50/90/20 -> p95 90
    events = [
        latency_event("chain-a", 1, "A1", 1_000_000, 100, 500, 50),
        latency_event("chain-a", 3, "A3", 2_000_000, 400, 600, 90),
        latency_event("chain-a", 4, "A4", 3_000_000, 200, 700, 20),
    ]
    write_events(workspace["input"], events)
    thresholds = {
        "proof_failure_rate_permille": 0,
        "missing_sequence_rate_permille": 100,   # 250 violates
        "proof_latency_ms_p95": 399,             # 400 violates
        "relay_latency_ms_p95": 700,             # equal -> no violation
        "destination_latency_ms_p95": 90,        # equal -> no violation
    }

    _reports, health = run_slo(workspace, thresholds)

    assert read_health(health) == [
        {
            "chain_id": "chain-a",
            "event_count": 3,
            "proof_failure_rate_permille": 0,
            # ceil(1 / 4 * 1000) = 250
            "missing_sequence_rate_permille": 250,
            "latency_p95_ms": {
                "proof_latency_ms": 400,
                "relay_latency_ms": 700,
                "destination_latency_ms": 90,
            },
            "violations": [
                "missing_sequence_rate_permille",
                "proof_latency_ms_p95",
            ],
        }
    ]
    row = read_health(health)[0]
    assert set(row) == {
        "chain_id",
        "event_count",
        "proof_failure_rate_permille",
        "missing_sequence_rate_permille",
        "latency_p95_ms",
        "violations",
    }
    assert set(row["latency_p95_ms"]) == {
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
    }


def test_chain_health_failure_rate_counts_failed_rows_in_isolation(workspace):
    # three_mixed_events: verified, failed, verified -> 1/3 failure.
    # ceil(1 / 3 * 1000) = 334; no sequence gaps.
    write_events(workspace["input"], three_mixed_events())
    thresholds = {
        "proof_failure_rate_permille": 333,
        "missing_sequence_rate_permille": 1000,
        "proof_latency_ms_p95": 10_000,
        "relay_latency_ms_p95": 10_000,
        "destination_latency_ms_p95": 10_000,
    }

    _reports, health = run_slo(
        workspace, thresholds, tolerate_failures=True
    )

    rows = read_health(health)
    assert rows == [
        {
            "chain_id": "chain-a",
            "event_count": 3,
            "proof_failure_rate_permille": 334,
            "missing_sequence_rate_permille": 0,
            "latency_p95_ms": {
                "proof_latency_ms": 400,
                "relay_latency_ms": 500,
                "destination_latency_ms": 400,
            },
            "violations": ["proof_failure_rate_permille"],
        }
    ]


def test_chain_health_all_failing_rate_is_one_thousand(workspace):
    events = [
        isolated_event("chain-a", 1, "A1", 1000, failing=True),
        isolated_event("chain-a", 2, "A2", 2000, failing=True),
    ]
    write_events(workspace["input"], events)
    thresholds = dict(CHAIN_SLO_ZERO_THRESHOLDS)
    thresholds["proof_failure_rate_permille"] = 999

    _reports, health = run_slo(
        workspace, thresholds, tolerate_failures=True
    )

    row = read_health(health)[0]
    assert row["proof_failure_rate_permille"] == 1000
    assert row["violations"] == [
        "proof_failure_rate_permille",
        "proof_latency_ms_p95",
        "relay_latency_ms_p95",
        "destination_latency_ms_p95",
    ]


def test_chain_health_rate_one_thousand_is_inclusive_bound(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds = {
        "proof_failure_rate_permille": 1000,
        "missing_sequence_rate_permille": 1000,
        "proof_latency_ms_p95": 10_000,
        "relay_latency_ms_p95": 10_000,
        "destination_latency_ms_p95": 10_000,
    }
    _reports, health = run_slo(workspace, thresholds)
    # Verified single event: rate 0, missing 0, latencies below thresholds.
    assert read_health(health)[0]["violations"] == []


def test_chain_health_failure_rate_rounds_up_not_to_nearest(workspace):
    # 1 failure out of 200 events -> 5 permille exactly; build 1 failed + 199
    # verified with unique time blocks. Assert ceil via 1/3 = 334 (not 333).
    events = [
        isolated_event("chain-a", 2, "A2", 2_000_000, failing=True),
        isolated_event("chain-a", 1, "A1", 1_000_000),
        isolated_event("chain-a", 3, "A3", 3_000_000),
    ]
    write_events(workspace["input"], events)
    thresholds = {
        "proof_failure_rate_permille": 1000,
        "missing_sequence_rate_permille": 1000,
        "proof_latency_ms_p95": 10_000,
        "relay_latency_ms_p95": 10_000,
        "destination_latency_ms_p95": 10_000,
    }
    _reports, health = run_slo(
        workspace, thresholds, tolerate_failures=True
    )
    assert read_health(health)[0]["proof_failure_rate_permille"] == 334


def test_chain_health_missing_rate_uses_gaps_only_and_rounds_up(workspace):
    # Sequences 1, 4 -> 2 missing (2, 3); rate = ceil(2 / 4 * 1000) = 500.
    events = [
        latency_event("chain-a", 1, "A1", 1_000_000, 100, 500, 50),
        latency_event("chain-a", 4, "A4", 2_000_000, 400, 600, 90),
    ]
    write_events(workspace["input"], events)
    thresholds = {
        "proof_failure_rate_permille": 1000,
        "missing_sequence_rate_permille": 499,
        "proof_latency_ms_p95": 10_000,
        "relay_latency_ms_p95": 10_000,
        "destination_latency_ms_p95": 10_000,
    }
    _reports, health = run_slo(workspace, thresholds)
    row = read_health(health)[0]
    assert row["missing_sequence_rate_permille"] == 500
    assert row["violations"] == ["missing_sequence_rate_permille"]


def test_chain_health_p95_uses_nearest_rank(workspace):
    # 20 events, proof latencies 10..200 ms: nearest-rank p95 is rank 19 -> 190.
    events = [
        latency_event(
            "chain-a", i, f"A{i}", (i + 1) * 10_000_000,
            proof=i * 10, relay=100, destination=5,
        )
        for i in range(1, 21)
    ]
    write_events(workspace["input"], events)
    thresholds = {
        "proof_failure_rate_permille": 1000,
        "missing_sequence_rate_permille": 1000,
        "proof_latency_ms_p95": 189,     # 190 violates (not the max 200)
        "relay_latency_ms_p95": 100,    # equal -> fine
        "destination_latency_ms_p95": 5,
    }
    _reports, health = run_slo(workspace, thresholds)
    row = read_health(health)[0]
    assert row["latency_p95_ms"]["proof_latency_ms"] == 190
    assert row["violations"] == ["proof_latency_ms_p95"]


def test_chain_health_multichain_first_appearance_order(workspace):
    # chain-b appears first; both chains reuse sequences 1 and 2.
    events = [
        latency_event("chain-b", 1, "B1", 1_000_000, 100, 500, 50),
        latency_event("chain-a", 1, "A1", 2_000_000, 400, 600, 90),
        latency_event("chain-b", 2, "B2", 3_000_000, 300, 700, 20),
        latency_event("chain-a", 2, "A2", 4_000_000, 200, 800, 70),
    ]
    write_events(workspace["input"], events)
    _reports, health = run_slo(workspace, CHAIN_SLO_ZERO_THRESHOLDS)

    rows = read_health(health)
    assert [r["chain_id"] for r in rows] == ["chain-b", "chain-a"]
    assert [r["event_count"] for r in rows] == [2, 2]


def test_chain_health_equal_threshold_is_not_a_violation(workspace):
    # Latencies are exactly 400/500/90; p95 of one event equals that value.
    write_events(workspace["input"], [make_event()])
    thresholds = {
        "proof_failure_rate_permille": 0,
        "missing_sequence_rate_permille": 0,
        "proof_latency_ms_p95": 400,
        "relay_latency_ms_p95": 500,
        "destination_latency_ms_p95": 900,
    }
    _reports, health = run_slo(workspace, thresholds)
    assert read_health(health)[0]["violations"] == []


def test_chain_health_empty_input_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    _reports, health = run_slo(workspace, CHAIN_SLO_ZERO_THRESHOLDS)
    assert health.exists()
    assert health.read_text(encoding="utf-8") == ""


def test_chain_health_omitted_writes_nothing_and_behavior_unchanged(workspace):
    write_events(workspace["input"], three_events())
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert [r["sequence"] for r in reports] == [1, 2, 3]
    assert not health.exists()
    assert read_checkpoint(workspace) == v3_checkpoint(
        {"chain-7": 3}, 3, full_digest(workspace["input"])
    )


def test_chain_health_covers_whole_input_across_resume(workspace):
    # First run processes seq 1 and 4 (gap 2,3); an appended rerun selects only
    # seq 7, yet the summary covers all three events.
    first_batch = [
        latency_event("chain-a", 1, "A1", 1_000_000, 400, 500, 400),
        latency_event("chain-a", 4, "A4", 2_000_000, 400, 500, 400),
    ]
    write_events(workspace["input"], first_batch)
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    slo_path = workspace["output"].with_name("slo.json")
    write_slo(
        slo_path,
        {
            "proof_failure_rate_permille": 1000,
            "missing_sequence_rate_permille": 1000,
            "proof_latency_ms_p95": 10_000,
            "relay_latency_ms_p95": 10_000,
            "destination_latency_ms_p95": 10_000,
        },
    )
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        chain_slo_thresholds=slo_path,
        chain_health_output=health,
    )
    assert read_health(health)[0]["event_count"] == 2

    second_batch = first_batch + [
        latency_event("chain-a", 7, "A7", 3_000_000, 400, 500, 400)
    ]
    write_events(workspace["input"], second_batch)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        chain_slo_thresholds=slo_path,
        chain_health_output=health,
    )
    assert [r["sequence"] for r in reports] == [7]
    row = read_health(health)[0]
    assert row["event_count"] == 3
    # Gaps are 2,3 and 5,6 -> 4 missing; ceil(4 / 7 * 1000) = 572.
    assert row["missing_sequence_rate_permille"] == 572

    # A no-op rerun rewrites the identical summary.
    again = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        chain_slo_thresholds=slo_path,
        chain_health_output=health,
    )
    assert again == []
    assert read_health(health)[0] == row


def test_chain_health_atomically_replaces_stale_file(workspace):
    write_events(workspace["input"], [make_event()])
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    health.write_text("STALE\n", encoding="utf-8")
    _reports, health2 = run_slo(workspace, CHAIN_SLO_ZERO_THRESHOLDS)
    rows = read_health(health2)
    assert len(rows) == 1
    assert rows[0]["chain_id"] == "chain-7"


def test_chain_health_does_not_change_report_checkpoint_profile_or_breach(
    workspace,
):
    write_events(workspace["input"], [make_event()])
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)
    write_thresholds(thresholds_path, DEFAULT_THRESHOLDS)
    slo_path = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo_path, CHAIN_SLO_ZERO_THRESHOLDS)

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        latency_thresholds=thresholds_path,
        latency_breach_output=breach,
        latency_profile_output=profile,
        chain_slo_thresholds=slo_path,
        chain_health_output=health,
    )

    row = json.loads(workspace["output"].read_text().splitlines()[0])
    assert set(row) == {
        "event_id",
        "chain_id",
        "sequence",
        "proof_status",
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
        "attribution",
        "finalized_at",
    }
    assert set(read_checkpoint(workspace)) == {
        "schema_version",
        "last_sequence_by_chain",
        "processed_lines",
        "input_prefix_sha256",
    }
    assert len(read_breaches(breach)) == 1
    assert len(read_profile(profile)) == 1
    assert len(read_health(health)) == 1


def test_chain_health_arguments_must_be_paired_in_api(workspace):
    write_events(workspace["input"], [make_event()])
    slo_path = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo_path, CHAIN_SLO_ZERO_THRESHOLDS)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            chain_slo_thresholds=slo_path,
        )
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            chain_health_output=health,
        )
    assert not health.exists()


@pytest.mark.parametrize(
    "payload",
    [
        "nope",                                       # malformed JSON
        "[]",                                         # not an object
        "{}",                                         # missing all fields
        json.dumps(                                    # missing one field
            {
                "proof_failure_rate_permille": 1,
                "missing_sequence_rate_permille": 1,
                "proof_latency_ms_p95": 1,
                "relay_latency_ms_p95": 1,
            }
        ),
        json.dumps(                                    # unknown field
            {
                "proof_failure_rate_permille": 0,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": 0,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
                "extra": 1,
            }
        ),
        json.dumps(                                    # rate above 1000
            {
                "proof_failure_rate_permille": 1001,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": 0,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # rate negative
            {
                "proof_failure_rate_permille": -1,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": 0,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # rate float
            {
                "proof_failure_rate_permille": 1.5,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": 0,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # rate boolean
            {
                "proof_failure_rate_permille": True,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": 0,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # rate null
            {
                "proof_failure_rate_permille": None,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": 0,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # rate string
            {
                "proof_failure_rate_permille": "0",
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": 0,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # p95 negative
            {
                "proof_failure_rate_permille": 0,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": -1,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # p95 float
            {
                "proof_failure_rate_permille": 0,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": 1.5,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # p95 boolean
            {
                "proof_failure_rate_permille": 0,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": False,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # p95 null
            {
                "proof_failure_rate_permille": 0,
                "missing_sequence_rate_permille": 0,
                "proof_latency_ms_p95": None,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
        json.dumps(                                    # missing-rate above 1000
            {
                "proof_failure_rate_permille": 0,
                "missing_sequence_rate_permille": 1001,
                "proof_latency_ms_p95": 0,
                "relay_latency_ms_p95": 0,
                "destination_latency_ms_p95": 0,
            }
        ),
    ],
)
def test_chain_slo_invalid_thresholds_raise_invalid_input(workspace, payload):
    write_events(workspace["input"], [make_event()])
    slo_path = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo_path, payload)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            chain_slo_thresholds=slo_path,
            chain_health_output=health,
        )
    assert not health.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_chain_slo_boundary_values_are_valid(workspace):
    # 0 and 1000 for rates, 0 for p95 must all be accepted.
    write_events(workspace["input"], [make_event()])
    _reports, health = run_slo(workspace, CHAIN_SLO_ZERO_THRESHOLDS)
    assert health.exists()


def test_chain_slo_invalid_utf8_thresholds_raise_invalid_input(workspace):
    write_events(workspace["input"], [make_event()])
    slo_path = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    slo_path.write_bytes(b"\xff\xfe{")
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            chain_slo_thresholds=slo_path,
            chain_health_output=health,
        )
    assert not health.exists()


def test_chain_health_strict_proof_failure_writes_nothing(workspace):
    write_events(workspace["input"], three_mixed_events())
    with pytest.raises(ProofVerificationError):
        run_slo(workspace, CHAIN_SLO_ZERO_THRESHOLDS)
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    assert not health.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_chain_health_invalid_input_writes_nothing(workspace):
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run_slo(workspace, CHAIN_SLO_ZERO_THRESHOLDS)
    assert not workspace["output"].with_name(CHAIN_SLO_PATH_NAME).exists()


def test_chain_health_checkpoint_error_writes_nothing(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-7": 99})), encoding="utf-8"
    )
    with pytest.raises(CheckpointError):
        run_slo(workspace, CHAIN_SLO_ZERO_THRESHOLDS)
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    assert not health.exists()
    assert not workspace["output"].exists()


def test_chain_health_failed_rows_participate_in_p95(workspace):
    # All three events share the 400/500/400 latency block; the failed middle
    # row must still contribute to the p95 values.
    write_events(workspace["input"], three_mixed_events())
    thresholds = {
        "proof_failure_rate_permille": 1000,
        "missing_sequence_rate_permille": 1000,
        "proof_latency_ms_p95": 399,
        "relay_latency_ms_p95": 499,
        "destination_latency_ms_p95": 399,
    }
    _reports, health = run_slo(
        workspace, thresholds, tolerate_failures=True
    )
    row = read_health(health)[0]
    assert row["latency_p95_ms"] == {
        "proof_latency_ms": 400,
        "relay_latency_ms": 500,
        "destination_latency_ms": 400,
    }
    assert row["violations"] == [
        "proof_latency_ms_p95",
        "relay_latency_ms_p95",
        "destination_latency_ms_p95",
    ]


def test_cli_chain_health_output_success(workspace):
    write_events(workspace["input"], [make_event()])
    slo = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo, CHAIN_SLO_ZERO_THRESHOLDS)
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--chain-slo-thresholds", str(slo),
        "--chain-health-output", str(health),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rows = read_health(health)
    assert len(rows) == 1
    assert rows[0]["chain_id"] == "chain-7"
    assert rows[0]["proof_failure_rate_permille"] == 0


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--chain-slo-thresholds", "slo.json"],
        ["--chain-health-output", "health.jsonl"],
    ],
)
def test_cli_chain_slo_arguments_must_be_paired(workspace, extra_args):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        *extra_args,
    )
    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert set(payload.keys()) == {"error", "message"}
    assert payload["error"] == "InvalidArgument"
    assert not workspace["output"].exists()


def test_cli_chain_slo_invalid_thresholds_is_invalid_input_error(workspace):
    write_events(workspace["input"], [make_event()])
    slo = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    slo.write_text("nope", encoding="utf-8")
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--chain-slo-thresholds", str(slo),
        "--chain-health-output", str(health),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "InvalidInputError"
    assert not health.exists()
    assert not workspace["output"].exists()


def test_cli_chain_slo_missing_thresholds_file_is_oserror(workspace):
    write_events(workspace["input"], [make_event()])
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--chain-slo-thresholds", str(workspace["output"].with_name("missing.json")),
        "--chain-health-output", str(health),
    )
    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert payload["error"] == "FileNotFoundError"
    assert isinstance(payload["message"], str) and payload["message"]
    assert not health.exists()


def test_cli_chain_health_unwritable_output_is_oserror_json(workspace):
    write_events(workspace["input"], [make_event()])
    slo = workspace["output"].with_name("slo.json")
    write_slo(slo, CHAIN_SLO_ZERO_THRESHOLDS)
    blocked = workspace["output"].with_name("not-a-dir")
    blocked.write_text("not a directory", encoding="utf-8")
    health = blocked / CHAIN_SLO_PATH_NAME
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--chain-slo-thresholds", str(slo),
        "--chain-health-output", str(health),
    )
    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert set(payload.keys()) == {"error", "message"}
    assert payload["error"] in {"OSError", "FileExistsError", "NotADirectoryError"}
    assert isinstance(payload["message"], str) and payload["message"]
    # The summary is published last: every earlier artifact already exists.
    assert workspace["output"].exists()
    assert read_checkpoint(workspace)["schema_version"] == 3


def test_cli_chain_health_strict_failure_leaves_no_health_file(workspace):
    write_events(workspace["input"], three_mixed_events())
    slo = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo, CHAIN_SLO_ZERO_THRESHOLDS)
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--chain-slo-thresholds", str(slo),
        "--chain-health-output", str(health),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not health.exists()
    assert not workspace["output"].exists()


def test_cli_chain_health_empty_input_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    slo = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo, CHAIN_SLO_ZERO_THRESHOLDS)
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--chain-slo-thresholds", str(slo),
        "--chain-health-output", str(health),
    )
    assert result.returncode == 0, result.stderr
    assert health.exists()
    assert health.read_text(encoding="utf-8") == ""


def test_cli_chain_health_isolation_mode_counts_failed_rows(workspace):
    write_events(workspace["input"], three_mixed_events())
    slo = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(
        slo,
        {
            "proof_failure_rate_permille": 1000,
            "missing_sequence_rate_permille": 1000,
            "proof_latency_ms_p95": 10_000,
            "relay_latency_ms_p95": 10_000,
            "destination_latency_ms_p95": 10_000,
        },
    )
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--tolerate-failures",
        "--chain-slo-thresholds", str(slo),
        "--chain-health-output", str(health),
    )
    assert result.returncode == 0, result.stderr
    rows = read_health(health)
    assert len(rows) == 1
    assert rows[0]["event_count"] == 3
    assert rows[0]["proof_failure_rate_permille"] == 334


def test_chain_health_strict_rerun_over_isolated_history_raises_before_publish(
    workspace,
):
    # First run in isolation mode commits a failed row and advances the cursor.
    write_events(workspace["input"], three_mixed_events())
    slo_path = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo_path, CHAIN_SLO_ZERO_THRESHOLDS)
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
        chain_slo_thresholds=slo_path,
        chain_health_output=health,
    )
    output_before = workspace["output"].read_text()
    health_before = health.read_text()

    # A later STRICT run (even with nothing newly selected) must surface the
    # historically failed proof before publishing anything: it raises and must
    # not replace the previously published report or chain health summary.
    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=False,
            chain_slo_thresholds=slo_path,
            chain_health_output=health,
        )
    assert health.read_text() == health_before
    # The previously published report is left untouched on the failure.
    assert workspace["output"].read_text() == output_before


# ---------------------------------------------------------------------------
# Chain-level time-window trend profile (trend_window_ms / trend_output)
# --------------------------------------------------------------------------- #


TREND_PATH_NAME = "trend.jsonl"


def read_trend(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def trend_event(
    chain_id,
    sequence,
    event_id,
    finalized_at,
    *,
    proof=400,
    relay=500,
    destination=400,
    failing=False,
):
    """A verifiable event pinned to an exact finalized_at and latencies.

    verify/finalize and submit/verify order is enforced (proof, destination
    >= 0); observed may sit anywhere. Constant latency offsets keep every
    timestamp column globally unique as long as finalized_at values differ.
    """
    verify = finalized_at - destination
    submit = verify - proof
    observed = verify - relay
    overrides = (
        dict(signatures=["0xaa11"], quorum=2) if failing else {}
    )
    return on_chain(
        chain_id,
        event_id=event_id,
        sequence=sequence,
        observed_at=observed,
        proof_submitted_at=submit,
        proof_verified_at=verify,
        finalized_at=finalized_at,
        **overrides,
    )


def run_trend(workspace, window_ms, events=None, **kwargs):
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    if events is not None:
        write_events(workspace["input"], events)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        trend_window_ms=window_ms,
        trend_output=trend,
        **kwargs,
    )
    return reports, trend


def test_trend_single_window_fields_counts_and_p95(workspace):
    events = [
        trend_event("chain-a", 1, "A1", 11_500),
        trend_event("chain-a", 2, "A2", 12_500),
    ]
    _reports, trend = run_trend(workspace, 10_000, events)

    rows = read_trend(trend)
    assert rows == [
        {
            "chain_id": "chain-a",
            "window_start_ms": 10_000,
            "event_count": 2,
            "proof_failure_count": 0,
            "attribution_counts": {
                "source": 0,
                "relay": 2,
                "destination": 0,
            },
            "latency_p95_ms": {
                "proof_latency_ms": 400,
                "relay_latency_ms": 500,
                "destination_latency_ms": 400,
            },
        }
    ]
    assert set(rows[0]) == {
        "chain_id",
        "window_start_ms",
        "event_count",
        "proof_failure_count",
        "attribution_counts",
        "latency_p95_ms",
    }
    assert set(rows[0]["attribution_counts"]) == {
        "source",
        "relay",
        "destination",
    }
    assert set(rows[0]["latency_p95_ms"]) == {
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
    }


def test_trend_window_start_is_floor_multiple_including_boundaries(workspace):
    # -1 floors to -10000 (the greatest multiple not greater than finalized_at);
    # 10000 and 19999 both belong to the window starting at 10000.
    finals = [-1, 9_999, 10_000, 10_001, 19_999, 20_000]
    events = [
        trend_event("chain-a", i + 1, f"A{i + 1}", final)
        for i, final in enumerate(finals)
    ]
    _reports, trend = run_trend(workspace, 10_000, events)

    rows = read_trend(trend)
    assert [r["window_start_ms"] for r in rows] == [
        -10_000,
        0,
        10_000,
        20_000,
    ]
    assert [r["event_count"] for r in rows] == [1, 1, 3, 1]
    assert all(r["chain_id"] == "chain-a" for r in rows)


def test_trend_empty_windows_are_not_emitted(workspace):
    events = [
        trend_event("chain-a", 1, "A1", 500),
        trend_event("chain-a", 2, "A2", 2_500),
    ]
    _reports, trend = run_trend(workspace, 1_000, events)

    rows = read_trend(trend)
    # The window starting at 1000 carries no event and must not appear.
    assert [r["window_start_ms"] for r in rows] == [0, 2_000]


def test_trend_merges_by_chain_and_window_start(workspace):
    events = [
        trend_event("chain-a", 1, "A1", 11_500),
        trend_event("chain-b", 1, "B1", 10_500),
        trend_event("chain-a", 2, "A2", 12_500),
        trend_event("chain-b", 2, "B2", 20_500),
    ]
    _reports, trend = run_trend(workspace, 10_000, events)

    rows = read_trend(trend)
    assert [
        (r["chain_id"], r["window_start_ms"], r["event_count"]) for r in rows
    ] == [
        ("chain-a", 10_000, 2),
        ("chain-b", 10_000, 1),
        ("chain-b", 20_000, 1),
    ]


def test_trend_order_is_chain_first_appearance_then_window_start(workspace):
    events = [
        trend_event("chain-b", 1, "B1", 11_500),
        trend_event("chain-a", 1, "A1", 11_600),
        trend_event("chain-b", 2, "B2", 21_500),
        trend_event("chain-a", 2, "A2", 500),
    ]
    _reports, trend = run_trend(workspace, 10_000, events)

    rows = read_trend(trend)
    assert [(r["chain_id"], r["window_start_ms"]) for r in rows] == [
        ("chain-b", 10_000),
        ("chain-b", 20_000),
        ("chain-a", 0),
        ("chain-a", 10_000),
    ]


def test_trend_p95_uses_nearest_rank_max_1_ceil_point95_n(workspace):
    # 20 events in one window; proof latencies 10..200 ms, p95 rank 19 = 190.
    events = [
        trend_event(
            "chain-a",
            i + 1,
            f"A{i + 1}",
            2_000_000 + i * 50,
            proof=(i + 1) * 10,
            relay=100,
        )
        for i in range(20)
    ]
    _reports, trend = run_trend(workspace, 1_000_000, events)

    rows = read_trend(trend)
    assert len(rows) == 1
    row = rows[0]
    assert row["window_start_ms"] == 2_000_000
    assert row["event_count"] == 20
    assert row["latency_p95_ms"] == {
        "proof_latency_ms": 190,
        "relay_latency_ms": 100,
        "destination_latency_ms": 400,
    }


def test_trend_attribution_counts_follow_single_event_convention(workspace):
    events = [
        trend_event("chain-a", 1, "A1", 500, proof=300, relay=100,
                    destination=50),    # source
        trend_event("chain-a", 2, "A2", 600, proof=60, relay=50,
                    destination=400),   # destination
        trend_event("chain-a", 3, "A3", 2_500, proof=10, relay=300,
                    destination=20),    # relay
    ]
    _reports, trend = run_trend(workspace, 1_000, events)

    rows = read_trend(trend)
    assert [r["window_start_ms"] for r in rows] == [0, 2_000]
    assert rows[0]["attribution_counts"] == {
        "source": 1,
        "relay": 0,
        "destination": 1,
    }
    assert rows[1]["attribution_counts"] == {
        "source": 0,
        "relay": 1,
        "destination": 0,
    }


def test_trend_isolation_mode_failed_rows_counted_per_window(workspace):
    # three_mixed_events finalize at 1900/2900/3900 -> one window at 0 with
    # N=10000; verified, failed, verified share the 400/500/400 block.
    write_events(workspace["input"], three_mixed_events())
    _reports, trend = run_trend(
        workspace, 10_000, tolerate_failures=True
    )

    rows = read_trend(trend)
    assert rows == [
        {
            "chain_id": "chain-a",
            "window_start_ms": 0,
            "event_count": 3,
            "proof_failure_count": 1,
            "attribution_counts": {
                "source": 0,
                "relay": 3,
                "destination": 0,
            },
            "latency_p95_ms": {
                "proof_latency_ms": 400,
                "relay_latency_ms": 500,
                "destination_latency_ms": 400,
            },
        }
    ]


def test_trend_empty_input_atomically_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    trend.write_text("STALE\n", encoding="utf-8")

    _reports, trend = run_trend(workspace, 10_000)

    assert trend.exists()
    assert trend.read_text(encoding="utf-8") == ""


def test_trend_omitted_writes_nothing_and_behavior_unchanged(workspace):
    write_events(workspace["input"], three_events())
    trend = workspace["output"].with_name(TREND_PATH_NAME)

    reports = run(
        workspace["input"], workspace["checkpoint"], workspace["output"]
    )

    assert [r["sequence"] for r in reports] == [1, 2, 3]
    assert not trend.exists()
    assert read_checkpoint(workspace) == v3_checkpoint(
        {"chain-7": 3}, 3, full_digest(workspace["input"])
    )


def test_trend_covers_whole_input_across_resume_append_and_rerun(workspace):
    first_batch = [
        trend_event("chain-a", 1, "A1", 11_500),
        trend_event("chain-a", 4, "A4", 12_500),
    ]
    write_events(workspace["input"], first_batch)
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        trend_window_ms=10_000,
        trend_output=trend,
    )
    assert read_trend(trend) == [
        {
            "chain_id": "chain-a",
            "window_start_ms": 10_000,
            "event_count": 2,
            "proof_failure_count": 0,
            "attribution_counts": {
                "source": 0,
                "relay": 2,
                "destination": 0,
            },
            "latency_p95_ms": {
                "proof_latency_ms": 400,
                "relay_latency_ms": 500,
                "destination_latency_ms": 400,
            },
        }
    ]

    second_batch = first_batch + [
        trend_event("chain-a", 7, "A7", 21_500)
    ]
    write_events(workspace["input"], second_batch)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        trend_window_ms=10_000,
        trend_output=trend,
    )
    # Only the appended event is selected; the trend covers all three.
    assert [r["sequence"] for r in reports] == [7]
    expected = read_trend(trend)
    assert [
        (r["window_start_ms"], r["event_count"]) for r in expected
    ] == [(10_000, 2), (20_000, 1)]

    # A no-op rerun rewrites the identical trend.
    again = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        trend_window_ms=10_000,
        trend_output=trend,
    )
    assert again == []
    assert read_trend(trend) == expected


def test_trend_atomically_replaces_stale_file(workspace):
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    trend.write_text("STALE\n", encoding="utf-8")
    _reports, trend = run_trend(
        workspace, 10_000, [trend_event("chain-7", 1, "E1", 11_500)]
    )
    rows = read_trend(trend)
    assert len(rows) == 1
    assert rows[0]["chain_id"] == "chain-7"


def test_trend_arguments_must_be_paired_in_api(workspace):
    write_events(workspace["input"], [make_event()])
    trend = workspace["output"].with_name(TREND_PATH_NAME)

    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            trend_window_ms=10_000,
        )
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            trend_output=trend,
        )
    assert not trend.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


@pytest.mark.parametrize("width", [0, -1, 1.5, 1.0, True, "10000"])
def test_trend_invalid_window_width_raises_invalid_input(workspace, width):
    write_events(workspace["input"], [make_event()])
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            trend_window_ms=width,
            trend_output=trend,
        )
    assert not trend.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_trend_window_width_one_is_valid(workspace):
    # With N=1 every unique finalized_at lands in its own singleton window.
    events = [
        trend_event("chain-a", 1, "A1", 1_001),
        trend_event("chain-a", 2, "A2", 1_002),
    ]
    _reports, trend = run_trend(workspace, 1, events)
    rows = read_trend(trend)
    assert [r["window_start_ms"] for r in rows] == [1_001, 1_002]
    assert all(r["event_count"] == 1 for r in rows)


def test_trend_strict_proof_failure_writes_nothing(workspace):
    write_events(workspace["input"], three_mixed_events())
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            trend_window_ms=10_000,
            trend_output=trend,
        )
    assert not trend.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_trend_invalid_input_writes_nothing(workspace):
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            trend_window_ms=10_000,
            trend_output=trend,
        )
    assert not trend.exists()


def test_trend_checkpoint_error_writes_nothing(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-7": 99})), encoding="utf-8"
    )
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    with pytest.raises(CheckpointError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            trend_window_ms=10_000,
            trend_output=trend,
        )
    assert not trend.exists()
    assert not workspace["output"].exists()


def test_trend_unwritable_path_raises_oserror_after_publish(workspace):
    write_events(
        workspace["input"],
        [trend_event("chain-7", 1, "E1", 11_500)],
    )
    blocked = workspace["output"].with_name("not-a-dir")
    blocked.write_text("not a directory", encoding="utf-8")
    trend = blocked / TREND_PATH_NAME

    with pytest.raises(OSError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            trend_window_ms=10_000,
            trend_output=trend,
        )

    # The trend is published last: report and checkpoint are already safe.
    assert not trend.exists()
    assert workspace["output"].exists()
    assert read_checkpoint(workspace)["schema_version"] == 3


def test_trend_strict_rerun_over_isolated_history_raises_before_publish(
    workspace,
):
    # First run in isolation mode commits a failed row and writes the trend.
    write_events(workspace["input"], three_mixed_events())
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
        trend_window_ms=10_000,
        trend_output=trend,
    )
    output_before = workspace["output"].read_text()
    trend_before = trend.read_text()

    # A later STRICT run must surface the historically failed proof before
    # publishing anything; the trend and report are left byte-for-byte intact.
    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=False,
            trend_window_ms=10_000,
            trend_output=trend,
        )
    assert trend.read_text() == trend_before
    assert workspace["output"].read_text() == output_before


def test_trend_does_not_change_any_other_output(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)
    write_thresholds(thresholds_path, DEFAULT_THRESHOLDS)
    slo_path = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo_path, CHAIN_SLO_ZERO_THRESHOLDS)
    trend = workspace["output"].with_name(TREND_PATH_NAME)

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=workspace["output"].with_name("continuity.jsonl"),
        latency_thresholds=thresholds_path,
        latency_breach_output=breach,
        latency_profile_output=profile,
        chain_slo_thresholds=slo_path,
        chain_health_output=health,
        trend_window_ms=10_000,
        trend_output=trend,
    )

    assert workspace["output"].exists()
    assert read_checkpoint(workspace)["schema_version"] == 3
    assert len(read_breaches(breach)) == 1
    assert len(read_profile(profile)) == 1
    assert len(read_health(health)) == 1
    trend_rows = read_trend(trend)
    assert len(trend_rows) == 1
    # make_event finalizes at 2400 -> window starts at 0.
    assert trend_rows[0]["window_start_ms"] == 0
    assert trend_rows[0]["event_count"] == 1
    assert trend_rows[0]["proof_failure_count"] == 0


# ---------------------------------------------------------------------------
# Trend profile CLI
# --------------------------------------------------------------------------- #


def test_cli_trend_output_success(workspace):
    events = [
        trend_event("chain-a", 1, "A1", 11_500),
        trend_event("chain-a", 2, "A2", 12_500),
    ]
    write_events(workspace["input"], events)
    trend = workspace["output"].with_name(TREND_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--trend-window-ms", "10000",
        "--trend-output", str(trend),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rows = read_trend(trend)
    assert rows == [
        {
            "chain_id": "chain-a",
            "window_start_ms": 10_000,
            "event_count": 2,
            "proof_failure_count": 0,
            "attribution_counts": {
                "source": 0,
                "relay": 2,
                "destination": 0,
            },
            "latency_p95_ms": {
                "proof_latency_ms": 400,
                "relay_latency_ms": 500,
                "destination_latency_ms": 400,
            },
        }
    ]


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--trend-window-ms", "10000"],
        ["--trend-output", "trend.jsonl"],
    ],
)
def test_cli_trend_arguments_must_be_paired(workspace, extra_args):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        *extra_args,
    )
    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert set(payload.keys()) == {"error", "message"}
    assert payload["error"] == "InvalidArgument"
    assert not workspace["output"].with_name(TREND_PATH_NAME).exists()
    assert not workspace["output"].exists()


@pytest.mark.parametrize(
    "width",
    ["0", "-1", "1.5", "1e3", "abc", "+1", " 100", "0x10"],
)
def test_cli_trend_invalid_width_is_invalid_argument(workspace, width):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--trend-window-ms", width,
        "--trend-output", str(workspace["output"].with_name(TREND_PATH_NAME)),
    )
    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert payload["error"] == "InvalidArgument"
    assert not workspace["output"].exists()


def test_cli_trend_unknown_argument_is_invalid_argument(workspace):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--trend-width-ms", "10000",
        "--trend-output", str(workspace["output"].with_name(TREND_PATH_NAME)),
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "InvalidArgument"
    assert not workspace["output"].exists()


def test_cli_trend_missing_width_value_is_invalid_argument(workspace):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--trend-window-ms",
        "--trend-output", str(workspace["output"].with_name(TREND_PATH_NAME)),
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "InvalidArgument"


def test_cli_trend_strict_failure_leaves_no_trend_file(workspace):
    write_events(workspace["input"], three_mixed_events())
    trend = workspace["output"].with_name(TREND_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--trend-window-ms", "10000",
        "--trend-output", str(trend),
    )

    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not trend.exists()
    assert not workspace["output"].exists()


def test_cli_trend_empty_input_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    trend = workspace["output"].with_name(TREND_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--trend-window-ms", "10000",
        "--trend-output", str(trend),
    )

    assert result.returncode == 0, result.stderr
    assert trend.exists()
    assert trend.read_text(encoding="utf-8") == ""


def test_cli_trend_isolation_mode_counts_failed_rows(workspace):
    write_events(workspace["input"], three_mixed_events())
    trend = workspace["output"].with_name(TREND_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--tolerate-failures",
        "--trend-window-ms", "10000",
        "--trend-output", str(trend),
    )

    assert result.returncode == 0, result.stderr
    rows = read_trend(trend)
    assert len(rows) == 1
    assert rows[0]["event_count"] == 3
    assert rows[0]["proof_failure_count"] == 1


def test_cli_trend_unwritable_path_is_oserror_json(workspace):
    write_events(
        workspace["input"],
        [trend_event("chain-7", 1, "E1", 11_500)],
    )
    blocked = workspace["output"].with_name("not-a-dir")
    blocked.write_text("not a directory", encoding="utf-8")
    trend = blocked / TREND_PATH_NAME

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--trend-window-ms", "10000",
        "--trend-output", str(trend),
    )

    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert set(payload.keys()) == {"error", "message"}
    assert payload["error"] in {"OSError", "FileExistsError", "NotADirectoryError"}
    assert isinstance(payload["message"], str) and payload["message"]
    # The trend is published last: every earlier artifact already exists.
    assert workspace["output"].exists()
    assert read_checkpoint(workspace)["schema_version"] == 3
    assert not trend.exists()

# ---------------------------------------------------------------------------
# Light-client proof verification audit profile (proof_audit_output)
# ---------------------------------------------------------------------------


AUDIT_PATH_NAME = "proof-audit.jsonl"


def read_audit(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def audit_event(chain_id, sequence, event_id, base, **proof_overrides):
    """A structure-valid event on chain_id with a globally-unique time block.

    Proof bits (e.g. quorum, signatures, hashes) pass through to make_event;
    a bad proof yields a structurally valid but failing event.
    """
    return chain_event(chain_id, sequence, event_id, base, **proof_overrides)


def run_audit(workspace, events=None, **kwargs):
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    if events is not None:
        write_events(workspace["input"], events)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        proof_audit_output=audit,
        **kwargs,
    )
    return reports, audit


def test_audit_verified_row_fields_and_checks(workspace):
    write_events(workspace["input"], [audit_event("chain-7", 1, "E1", 1000)])
    _reports, audit = run_audit(workspace)

    rows = read_audit(audit)
    assert rows == [
        {
            "event_id": "E1",
            "chain_id": "chain-7",
            "sequence": 1,
            "proof_status": "verified",
            "light_client_version": "v1",
            "provided_signature_count": 3,
            "unique_signature_count": 3,
            "quorum": 2,
            "checks": {
                "quorum_sufficient": True,
                "validator_set_hash_matches": True,
                "trusted_root_matches_header": True,
            },
            "failed_checks": [],
            "finalized_at": 1900,
        }
    ]
    assert set(rows[0]) == {
        "event_id",
        "chain_id",
        "sequence",
        "proof_status",
        "light_client_version",
        "provided_signature_count",
        "unique_signature_count",
        "quorum",
        "checks",
        "failed_checks",
        "finalized_at",
    }
    assert list(rows[0]["checks"]) == [
        "quorum_sufficient",
        "validator_set_hash_matches",
        "trusted_root_matches_header",
    ]
    assert list(rows[0]["failed_checks"]) == []


def test_audit_signature_counts_raw_length_and_distinct(workspace):
    # Duplicated raw signatures inflate the raw length but not the distinct
    # count (which is exactly the set verify_proof uses for the quorum rule).
    good_dup = on_chain(
        "chain-7",
        event_id="D1",
        sequence=1,
        signatures=["0xaa11", "0xbb22", "0xbb22", "0xcc33"],
        quorum=3,
        validator_set_hash=_validator_set_hash(
            "v1",
            "chain-7",
            ["0xaa11", "0xbb22", "0xbb22", "0xcc33"],
        ),
    )
    write_events(workspace["input"], [good_dup])
    _reports, audit = run_audit(workspace)

    row = read_audit(audit)[0]
    assert row["provided_signature_count"] == 4
    assert row["unique_signature_count"] == 3
    assert row["quorum"] == 3
    assert row["proof_status"] == "verified"

    # Same raw/distinct convention for a failing event:
    fail_dup = on_chain(
        "chain-7",
        event_id="D2",
        sequence=2,
        observed_at=2001,
        proof_submitted_at=2100,
        proof_verified_at=2500,
        finalized_at=3400,
        signatures=["0xaa11", "00aa11", "00aa11"],
        quorum=3,
    )
    # Raw strings "0xaa11" vs "00aa11" differ as strings -> distinct as per
    # verify_proof's raw-string set, even though they normalize alike.
    write_events(workspace["input"], [good_dup, fail_dup])
    _reports, audit = run_audit(workspace, tolerate_failures=True)
    rows = read_audit(audit)
    assert rows[1]["provided_signature_count"] == 3
    assert rows[1]["unique_signature_count"] == 2
    assert rows[1]["checks"]["quorum_sufficient"] is False
    assert rows[1]["proof_status"] == "failed"


def test_audit_failed_row_lists_only_false_checks_in_order(workspace):
    # Quorum failure only: hash/root checks still independently true.
    below_quorum = audit_event(
        "chain-a", 1, "A1", 1000, signatures=["0xaa11"], quorum=2
    )
    # Hash mismatch only: quorum sufficient (3 sigs, quorum 2), root fine.
    hash_bad = audit_event(
        "chain-a", 2, "A2", 2000, validator_set_hash="0x" + "11" * 32
    )
    # Root mismatch only: quorum and hash fine, bad trusted_root.
    root_bad = audit_event(
        "chain-a",
        3,
        "A3",
        3000,
        trusted_root="0x" + "22" * 32,
        header_hash="0xdeadbeef",
    )
    # Version mismatch: on_chain recomputed the validator-set hash for the
    # overridden version v9, so only the v1-pinned trusted root fails.
    version_bad = audit_event(
        "chain-a", 4, "A4", 4000, light_client_version="v9"
    )
    # All three checks fail: below quorum, wrong hash, wrong root.
    all_bad = audit_event(
        "chain-a",
        5,
        "A5",
        5000,
        signatures=["0xaa11"],
        quorum=2,
        validator_set_hash="0x" + "11" * 32,
        trusted_root="0x" + "22" * 32,
        header_hash="0xdeadbeef",
    )
    events = [below_quorum, hash_bad, root_bad, version_bad, all_bad]
    write_events(workspace["input"], events)
    _reports, audit = run_audit(workspace, tolerate_failures=True)

    rows = read_audit(audit)
    assert [r["event_id"] for r in rows] == ["A1", "A2", "A3", "A4", "A5"]
    assert all(r["proof_status"] == "failed" for r in rows)
    assert rows[0]["failed_checks"] == ["quorum_sufficient"]
    assert rows[0]["checks"]["validator_set_hash_matches"] is True
    assert rows[0]["checks"]["trusted_root_matches_header"] is True
    assert rows[1]["failed_checks"] == ["validator_set_hash_matches"]
    assert rows[1]["checks"]["quorum_sufficient"] is True
    assert rows[1]["checks"]["trusted_root_matches_header"] is True
    assert rows[2]["failed_checks"] == ["trusted_root_matches_header"]
    assert rows[2]["checks"]["quorum_sufficient"] is True
    assert rows[2]["checks"]["validator_set_hash_matches"] is True
    assert rows[3]["failed_checks"] == [
        "trusted_root_matches_header",
    ]
    assert rows[3]["checks"]["quorum_sufficient"] is True
    assert rows[3]["checks"]["validator_set_hash_matches"] is True
    assert rows[4]["failed_checks"] == [
        "quorum_sufficient",
        "validator_set_hash_matches",
        "trusted_root_matches_header",
    ]


def test_audit_multiple_chains_preserve_input_order(workspace):
    events = interlocked_events()
    write_events(workspace["input"], events)
    _reports, audit = run_audit(workspace)

    rows = read_audit(audit)
    assert [
        (r["chain_id"], r["sequence"], r["proof_status"]) for r in rows
    ] == [
        ("chain-a", 1, "verified"),
        ("chain-b", 1, "verified"),
        ("chain-a", 2, "verified"),
        ("chain-b", 2, "verified"),
        ("chain-a", 3, "verified"),
        ("chain-b", 3, "verified"),
    ]
    assert [r["event_id"] for r in rows] == [
        "A1",
        "B1",
        "A2",
        "B2",
        "A3",
        "B3",
    ]
    assert all(r["failed_checks"] == [] for r in rows)


def test_audit_isolation_mode_includes_verified_and_failed(workspace):
    write_events(workspace["input"], three_mixed_events())
    reports, audit = run_audit(workspace, tolerate_failures=True)

    assert [r["proof_status"] for r in reports] == [
        "verified",
        "failed",
        "verified",
    ]
    rows = read_audit(audit)
    assert [r["proof_status"] for r in rows] == [
        "verified",
        "failed",
        "verified",
    ]
    assert rows[1]["failed_checks"] == ["quorum_sufficient"]
    # The audit row carries no report-specific error fields.
    assert "error_type" not in rows[1]
    assert "error_message" not in rows[1]


def test_audit_empty_input_atomically_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    audit.write_text("STALE\n", encoding="utf-8")
    _reports, audit = run_audit(workspace)
    assert audit.exists()
    assert audit.read_text(encoding="utf-8") == ""


def test_audit_omitted_writes_nothing(workspace):
    write_events(workspace["input"], [make_event()])
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert not audit.exists()
    assert workspace["output"].exists()


def test_audit_covers_whole_input_across_resume_append_and_rerun(workspace):
    first_batch = [
        audit_event("chain-a", 1, "A1", 1000),
        audit_event("chain-a", 4, "A4", 2000),
    ]
    write_events(workspace["input"], first_batch)
    _reports, audit = run_audit(workspace)
    assert [r["sequence"] for r in read_audit(audit)] == [1, 4]

    second_batch = first_batch + [audit_event("chain-a", 7, "A7", 3000)]
    write_events(workspace["input"], second_batch)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        proof_audit_output=audit,
    )
    # Only the appended event is selected for the report; the audit covers
    # all three.
    assert [r["sequence"] for r in reports] == [7]
    expected = read_audit(audit)
    assert [r["sequence"] for r in expected] == [1, 4, 7]
    assert all(r["proof_status"] == "verified" for r in expected)

    # A no-op rerun rewrites the identical audit.
    again = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        proof_audit_output=audit,
    )
    assert again == []
    assert read_audit(audit) == expected


def test_audit_atomically_replaces_stale_file(workspace):
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    audit.write_text("STALE\n", encoding="utf-8")
    _reports, audit = run_audit(
        workspace, [audit_event("chain-7", 1, "E1", 1000)]
    )
    rows = read_audit(audit)
    assert len(rows) == 1
    assert rows[0]["event_id"] == "E1"
    assert "STALE" not in audit.read_text(encoding="utf-8")


def test_audit_strict_proof_failure_writes_nothing(workspace):
    write_events(workspace["input"], three_mixed_events())
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            proof_audit_output=audit,
        )
    assert not audit.exists()
    assert not workspace["output"].exists()
    assert not workspace["checkpoint"].exists()


def test_audit_strict_rerun_over_isolated_history_raises_before_publish(
    workspace,
):
    # First run in isolation mode commits a failed row and writes the audit.
    write_events(workspace["input"], three_mixed_events())
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
        proof_audit_output=audit,
    )
    output_before = workspace["output"].read_text()
    audit_before = audit.read_text()

    # A later STRICT run must surface the historically failed proof before
    # publishing anything; the audit and report stay byte-for-byte intact.
    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=False,
            proof_audit_output=audit,
        )
    assert audit.read_text() == audit_before
    assert workspace["output"].read_text() == output_before


def test_audit_malformed_input_writes_nothing(workspace):
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            proof_audit_output=audit,
        )
    assert not audit.exists()
    assert not workspace["output"].exists()


def test_audit_duplicate_sequence_writes_nothing(workspace):
    events = [
        audit_event("chain-a", 1, "A1", 1000),
        audit_event("chain-a", 1, "A2", 2000),
    ]
    write_events(workspace["input"], events)
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            proof_audit_output=audit,
        )
    assert not audit.exists()
    assert not workspace["output"].exists()


def test_audit_time_order_error_writes_nothing(workspace):
    bad = make_event(
        observed_at=1000,
        proof_submitted_at=2600,
        proof_verified_at=1500,
        finalized_at=2400,
    )
    write_events(workspace["input"], [bad])
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            proof_audit_output=audit,
        )
    assert not audit.exists()


def test_audit_checkpoint_error_writes_nothing(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps(v2_checkpoint({"chain-7": 99})), encoding="utf-8"
    )
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)
    with pytest.raises(CheckpointError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            proof_audit_output=audit,
        )
    assert not audit.exists()
    assert not workspace["output"].exists()


def test_audit_unwritable_path_raises_oserror_after_publish(workspace):
    write_events(
        workspace["input"],
        [audit_event("chain-7", 1, "E1", 1000)],
    )
    blocked = workspace["output"].with_name("not-a-dir")
    blocked.write_text("not a directory", encoding="utf-8")
    audit = blocked / AUDIT_PATH_NAME

    with pytest.raises(OSError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            proof_audit_output=audit,
        )

    # The audit is published last: report and checkpoint are already safe.
    assert not audit.exists()
    assert workspace["output"].exists()
    assert read_checkpoint(workspace)["schema_version"] == 3


def test_audit_does_not_change_any_other_output(workspace):
    write_events(workspace["input"], [make_event()])
    thresholds_path = workspace["output"].with_name("thresholds.json")
    breach = workspace["output"].with_name("breach.jsonl")
    profile = workspace["output"].with_name(PROFILE_PATH_NAME)
    write_thresholds(thresholds_path, DEFAULT_THRESHOLDS)
    slo_path = workspace["output"].with_name("slo.json")
    health = workspace["output"].with_name(CHAIN_SLO_PATH_NAME)
    write_slo(slo_path, CHAIN_SLO_ZERO_THRESHOLDS)
    trend = workspace["output"].with_name(TREND_PATH_NAME)
    continuity = workspace["output"].with_name("continuity.jsonl")
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)

    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        continuity_output=continuity,
        latency_thresholds=thresholds_path,
        latency_breach_output=breach,
        latency_profile_output=profile,
        chain_slo_thresholds=slo_path,
        chain_health_output=health,
        trend_window_ms=10_000,
        trend_output=trend,
        proof_audit_output=audit,
    )

    assert workspace["output"].exists()
    assert read_checkpoint(workspace)["schema_version"] == 3
    assert continuity.exists()
    assert len(read_breaches(breach)) == 1
    assert len(read_profile(profile)) == 1
    assert len(read_health(health)) == 1
    assert len(read_trend(trend)) == 1
    audit_rows = read_audit(audit)
    assert len(audit_rows) == 1
    assert audit_rows[0]["proof_status"] == "verified"
    assert audit_rows[0]["finalized_at"] == 2400


# ---------------------------------------------------------------------------
# Proof audit CLI
# ---------------------------------------------------------------------------


def test_cli_audit_output_success(workspace):
    write_events(
        workspace["input"],
        [audit_event("chain-a", 1, "A1", 1000), audit_event("chain-a", 2, "A2", 2000)],
    )
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--proof-audit-output", str(audit),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rows = read_audit(audit)
    assert [r["sequence"] for r in rows] == [1, 2]
    assert all(r["proof_status"] == "verified" for r in rows)


def test_cli_audit_empty_input_writes_empty_file(workspace):
    workspace["input"].write_text("", encoding="utf-8")
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--proof-audit-output", str(audit),
    )

    assert result.returncode == 0, result.stderr
    assert audit.exists()
    assert audit.read_text(encoding="utf-8") == ""


def test_cli_audit_isolation_mode_includes_failed_rows(workspace):
    write_events(workspace["input"], three_mixed_events())
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--tolerate-failures",
        "--proof-audit-output", str(audit),
    )

    assert result.returncode == 0, result.stderr
    rows = read_audit(audit)
    assert [r["proof_status"] for r in rows] == [
        "verified",
        "failed",
        "verified",
    ]
    failed = rows[1]
    assert failed["failed_checks"] == ["quorum_sufficient"]
    assert "error_type" not in failed
    assert "error_message" not in failed


def test_cli_audit_strict_failure_leaves_no_audit_file(workspace):
    write_events(workspace["input"], three_mixed_events())
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--proof-audit-output", str(audit),
    )

    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not audit.exists()
    assert not workspace["output"].exists()


def test_cli_audit_invalid_input_is_invalid_input_error(workspace):
    workspace["input"].write_text("nope\n", encoding="utf-8")
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--proof-audit-output", str(audit),
    )

    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert payload["error"] == "InvalidInputError"
    assert not audit.exists()
    assert not workspace["output"].exists()


def test_cli_audit_checkpoint_error_is_checkpoint_error(workspace):
    write_events(workspace["input"], three_events())
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": -5}), encoding="utf-8"
    )
    audit = workspace["output"].with_name(AUDIT_PATH_NAME)

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--proof-audit-output", str(audit),
    )

    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "CheckpointError"
    assert not audit.exists()


def test_cli_audit_unwritable_path_is_oserror_json(workspace):
    write_events(
        workspace["input"],
        [audit_event("chain-7", 1, "E1", 1000)],
    )
    blocked = workspace["output"].with_name("not-a-dir")
    blocked.write_text("not a directory", encoding="utf-8")
    audit = blocked / AUDIT_PATH_NAME

    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
        "--proof-audit-output", str(audit),
    )

    assert result.returncode != 0
    payload = json.loads(result.stderr)
    assert set(payload.keys()) == {"error", "message"}
    assert payload["error"] in {"OSError", "FileExistsError", "NotADirectoryError"}
    assert isinstance(payload["message"], str) and payload["message"]
    # The audit is published last: every earlier artifact already exists.
    assert workspace["output"].exists()
    assert read_checkpoint(workspace)["schema_version"] == 3
    assert not audit.exists()


def test_cli_audit_omitted_keeps_behavior(workspace):
    write_events(workspace["input"], [make_event()])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode == 0, result.stderr
    assert not workspace["output"].with_name(AUDIT_PATH_NAME).exists()
