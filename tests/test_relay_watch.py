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
from relay_watch.core import _trusted_roots, _validator_set_hash

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
