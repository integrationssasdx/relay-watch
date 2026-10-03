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


# ---------------------------------------------------------------------------
# Happy path / report contents
# ---------------------------------------------------------------------------


def test_verified_report_fields_and_latencies(workspace):
    write_events(workspace["input"], [make_event()])

    reports = run(workspace["input"], workspace["checkpoint"], workspace["output"])

    assert reports == [
        {
            "event_id": "E1",
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
    assert json.loads(workspace["checkpoint"].read_text())["last_sequence"] == 3


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
