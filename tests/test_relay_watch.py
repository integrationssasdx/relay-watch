"""Tests for the offline relay reliability monitor."""

from __future__ import annotations

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
    verify_proof,
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
    # Legacy single-chain checkpoint is upgraded to the v2 per-chain shape.
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == {
        "schema_version": 2,
        "last_sequence_by_chain": {"chain-7": 3},
    }


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
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == v2_checkpoint({"chain-a": 3, "chain-b": 3})


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
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == v2_checkpoint({"chain-a": 3, "chain-b": 3})


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
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == v2_checkpoint({"chain-a": 2, "chain-b": 2})


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
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == v2_checkpoint({"chain-a": 1, "chain-b": 1})


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
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == v2_checkpoint({"chain-a": 2, "chain-other": 99})


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
    assert json.loads(workspace["checkpoint"].read_text())["schema_version"] == 2


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
# Tolerate-failures isolation mode
# ---------------------------------------------------------------------------


def failing_event(chain_id="chain-7", sequence=1, event_id="F1", base=1000):
    """A structurally valid event whose proof cannot verify (below quorum)."""
    return chain_event(
        chain_id,
        sequence,
        event_id,
        base,
        signatures=["0xaa11"],
        quorum=2,
    )


def proof_error_text(event):
    """The exact message verify_proof raises for this structurally valid event."""
    with pytest.raises(ProofVerificationError) as excinfo:
        verify_proof(event)
    return str(excinfo.value)


def test_strict_mode_is_the_default_and_still_raises(workspace):
    bad = failing_event(event_id="F1", sequence=1)
    write_events(workspace["input"], [bad])
    with pytest.raises(ProofVerificationError):
        run(workspace["input"], workspace["checkpoint"], workspace["output"])
    assert not workspace["output"].exists()


def test_strict_mode_explicit_false_matches_default(workspace):
    bad = failing_event(event_id="F1", sequence=1)
    write_events(workspace["input"], [bad])
    with pytest.raises(ProofVerificationError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=False,
        )


def test_tolerate_failures_returns_failed_row_with_error_fields(workspace):
    bad = failing_event(event_id="F1", sequence=1)
    write_events(workspace["input"], [bad])

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert len(reports) == 1
    row = reports[0]
    assert row["proof_status"] == "failed"
    assert row["error_type"] == "ProofVerificationError"
    assert row["error_message"] == proof_error_text(bad)
    # Identity, latencies, attribution and finalized_at are still emitted and
    # use the same numeric convention as a verified row.
    assert row["event_id"] == "F1"
    assert row["chain_id"] == "chain-7"
    assert row["sequence"] == 1
    assert row["proof_latency_ms"] == 400
    assert row["relay_latency_ms"] == 500
    assert row["destination_latency_ms"] == 400
    assert row["attribution"] == "relay"
    assert row["finalized_at"] == 1900
    assert set(row) == {
        "event_id",
        "chain_id",
        "sequence",
        "proof_status",
        "error_type",
        "error_message",
        "proof_latency_ms",
        "relay_latency_ms",
        "destination_latency_ms",
        "attribution",
        "finalized_at",
    }
    # The failed row is persisted to the report.
    lines = workspace["output"].read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0]) == row


def test_tolerate_failures_isolates_a_failure_between_good_events(workspace):
    good1 = chain_event("chain-7", 1, "A1", 1000)
    bad = failing_event(event_id="B2", sequence=2, base=2000)
    good3 = chain_event("chain-7", 3, "A3", 3000)
    write_events(workspace["input"], [good1, bad, good3])

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert [r["sequence"] for r in reports] == [1, 2, 3]
    assert [r["proof_status"] for r in reports] == ["verified", "failed", "verified"]
    # The event after the failure is fully verified, not affected by the failure.
    assert "error_type" not in reports[0] and "error_type" not in reports[2]
    assert reports[1]["error_message"] == proof_error_text(bad)

    checkpoint = json.loads(workspace["checkpoint"].read_text())
    # Both success and failure count as processed: cursor reaches the max.
    assert checkpoint == v2_checkpoint({"chain-7": 3})


def test_tolerate_failures_advances_per_chain_through_failures(workspace):
    # chain-a fails at seq 2, chain-b is fine; interleaved input.
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-b", 1, "B1", 2000),
        chain_event("chain-a", 2, "A2", 3000, signatures=["0xaa11"], quorum=2),
        chain_event("chain-b", 2, "B2", 4000),
        chain_event("chain-a", 3, "A3", 5000),
    ]
    write_events(workspace["input"], events)

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    assert [(r["chain_id"], r["sequence"], r["proof_status"]) for r in reports] == [
        ("chain-a", 1, "verified"),
        ("chain-b", 1, "verified"),
        ("chain-a", 2, "failed"),
        ("chain-b", 2, "verified"),
        ("chain-a", 3, "verified"),
    ]
    # A later event on the same chain as the failure is unaffected.
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == v2_checkpoint({"chain-a": 3, "chain-b": 2})


def test_tolerate_failures_dedupes_on_resume_and_rerun_is_deterministic(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 2, "A2", 2000, signatures=["0xaa11"], quorum=2),
        chain_event("chain-b", 1, "B1", 3000),
    ]
    write_events(workspace["input"], events)

    first = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    output_after_first = workspace["output"].read_text()
    checkpoint_after_first = workspace["checkpoint"].read_text()

    # Identical rerun: nothing selected, no duplicated rows.
    second = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    assert second == []
    assert workspace["output"].read_text() == output_after_first
    assert workspace["checkpoint"].read_text() == checkpoint_after_first

    rows = [json.loads(line) for line in output_after_first.splitlines()]
    assert [(r["chain_id"], r["sequence"], r["proof_status"]) for r in rows] == [
        ("chain-a", 1, "verified"),
        ("chain-a", 2, "failed"),
        ("chain-b", 1, "verified"),
    ]


def test_tolerate_failures_resume_appends_new_results_after_prior_failure(
    workspace,
):
    first_batch = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 2, "A2", 2000, signatures=["0xaa11"], quorum=2),
    ]
    write_events(workspace["input"], first_batch)
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )

    second_batch = first_batch + [
        chain_event("chain-a", 3, "A3", 3000),
        chain_event("chain-b", 1, "B1", 4000),
    ]
    write_events(workspace["input"], second_batch)
    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    # The failed seq-2 row is not re-selected or re-appended.
    assert [(r["chain_id"], r["sequence"]) for r in reports] == [
        ("chain-a", 3),
        ("chain-b", 1),
    ]
    rows = [
        json.loads(line)
        for line in workspace["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert [(r["chain_id"], r["sequence"], r["proof_status"]) for r in rows] == [
        ("chain-a", 1, "verified"),
        ("chain-a", 2, "failed"),
        ("chain-a", 3, "verified"),
        ("chain-b", 1, "verified"),
    ]
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == v2_checkpoint({"chain-a": 3, "chain-b": 1})


def test_tolerate_failures_fresh_start_atomically_replaces_stale_report(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 2, "A2", 2000, signatures=["0xaa11"], quorum=2),
    ]
    write_events(workspace["input"], events)
    workspace["output"].write_text('{"sequence": 999}\n', encoding="utf-8")

    reports = run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    assert [r["sequence"] for r in reports] == [1, 2]
    lines = workspace["output"].read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["sequence"] for line in lines] == [1, 2]


def test_tolerate_failures_legacy_single_chain_checkpoint_is_upgraded(workspace):
    events = [
        chain_event("chain-7", 1, "A1", 1000),
        chain_event("chain-7", 2, "A2", 2000, signatures=["0xaa11"], quorum=2),
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
    assert json.loads(workspace["checkpoint"].read_text()) == v2_checkpoint(
        {"chain-7": 2}
    )


def test_tolerate_failures_legacy_checkpoint_multichain_still_errors(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-b", 1, "B1", 2000),
    ]
    write_events(workspace["input"], events)
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


def test_tolerate_failures_structural_errors_still_raise_invalid_input(workspace):
    # A malformed line is an InvalidInputError even in isolation mode.
    workspace["input"].write_text("{not json\n", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )
    assert not workspace["output"].exists()


def test_tolerate_failures_duplicate_sequence_still_raises(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 1, "A2", 2000),
    ]
    write_events(workspace["input"], events)
    with pytest.raises(InvalidInputError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )
    assert not workspace["output"].exists()


def test_tolerate_failures_checkpoint_cursor_error_still_raises(workspace):
    write_events(workspace["input"], [chain_event("chain-a", 1, "A1", 1000)])
    workspace["checkpoint"].write_text(
        json.dumps({"last_sequence": 99}), encoding="utf-8"
    )
    with pytest.raises(CheckpointError):
        run(
            workspace["input"],
            workspace["checkpoint"],
            workspace["output"],
            tolerate_failures=True,
        )
    assert not workspace["output"].exists()


def test_tolerate_failures_output_is_deterministic_across_runs(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 2, "A2", 2000, signatures=["0xaa11"], quorum=2),
        chain_event("chain-b", 1, "B1", 3000),
    ]
    write_events(workspace["input"], events)
    run(
        workspace["input"],
        workspace["checkpoint"],
        workspace["output"],
        tolerate_failures=True,
    )
    first_output = workspace["output"].read_text(encoding="utf-8")

    # Replay from a fresh checkpoint/output over the same input.
    cp2 = workspace["checkpoint"].with_name("cp2.json")
    out2 = workspace["output"].with_name("report2.jsonl")
    run(workspace["input"], cp2, out2, tolerate_failures=True)
    assert out2.read_text(encoding="utf-8") == first_output


def test_cli_tolerate_failures_writes_failed_rows_and_exits_zero(workspace):
    events = [
        chain_event("chain-a", 1, "A1", 1000),
        chain_event("chain-a", 2, "A2", 2000, signatures=["0xaa11"], quorum=2),
        chain_event("chain-b", 1, "B1", 3000),
    ]
    write_events(workspace["input"], events)
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
    assert [(r["chain_id"], r["sequence"], r["proof_status"]) for r in rows] == [
        ("chain-a", 1, "verified"),
        ("chain-a", 2, "failed"),
        ("chain-b", 1, "verified"),
    ]
    failed = rows[1]
    assert failed["error_type"] == "ProofVerificationError"
    assert isinstance(failed["error_message"], str) and failed["error_message"]
    checkpoint = json.loads(workspace["checkpoint"].read_text())
    assert checkpoint == v2_checkpoint({"chain-a": 2, "chain-b": 1})


def test_cli_default_without_flag_keeps_strict_failure(workspace):
    bad = failing_event(event_id="F1", sequence=1)
    write_events(workspace["input"], [bad])
    result = run_cli(
        "--input", str(workspace["input"]),
        "--checkpoint", str(workspace["checkpoint"]),
        "--output", str(workspace["output"]),
    )
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "ProofVerificationError"
    assert not workspace["output"].exists()
