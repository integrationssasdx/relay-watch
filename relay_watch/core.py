"""Core implementation of the offline relay reliability monitor.

The data model is intentionally self contained (standard library only) and
derives every check from fields present on the event: there is no network or
chain lookup.

Event (one JSON object per JSONL line)::

    event_id, chain_id, sequence, observed_at, proof_submitted_at,
    proof_verified_at, finalized_at, proof

``proof`` contains ``light_client_version``, ``trusted_root``,
``header_hash``, ``validator_set_hash``, ``signatures`` and ``quorum``.

A proof is ``verified`` only when the signature set reaches ``quorum``, the
declared validator set hash agrees with the signatures, the trusted root
authenticates the header hash and the light client version is accepted.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from typing import Any, Iterable, Optional, Union

PathLike = Union[str, os.PathLike[str]]

EVENT_FIELDS = (
    "event_id",
    "chain_id",
    "sequence",
    "observed_at",
    "proof_submitted_at",
    "proof_verified_at",
    "finalized_at",
    "proof",
)

TIME_FIELDS = (
    "observed_at",
    "proof_submitted_at",
    "proof_verified_at",
    "finalized_at",
)

PROOF_FIELDS = (
    "light_client_version",
    "trusted_root",
    "header_hash",
    "validator_set_hash",
    "signatures",
    "quorum",
)

# The offline input carries no external version registry, so a proof is not
# rejected merely for naming an unfamiliar version: conformance is enforced by
# binding ``light_client_version`` into every trusted-root commitment, so a
# root produced under one version never verifies a header declared under
# another.  An empty/non-string version is rejected structurally up front.

# Names of the three latency stages, ordered for tie resolution.
_SOURCE = "source"
_RELAY = "relay"
_DESTINATION = "destination"


class RelayWatchError(Exception):
    """Base class for every error raised by :mod:`relay_watch`."""


class InvalidInputError(RelayWatchError):
    """The JSONL input (or checkpoint) cannot be parsed or is inconsistent."""


class ProofVerificationError(RelayWatchError):
    """A structurally complete event fails the light client proof rules."""


class CheckpointError(RelayWatchError):
    """The checkpoint ``last_sequence`` is unusable for this input."""


# ---------------------------------------------------------------------------
# Small structural helpers
# ---------------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    """Return True for genuine integers (JSON numbers without a fraction).

    ``bool`` is an ``int`` subclass in Python but must never be accepted as a
    millisecond timestamp or sequence number.
    """

    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex_string(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    body = value[2:] if value[:2].lower() == "0x" else value
    if not body or len(body) % 2:
        return False
    try:
        int(body, 16)
    except ValueError:
        return False
    return True


def _normalize_hash(value: Any) -> str:
    if not _is_hex_string(value):
        raise InvalidInputError("hash field must be a 0x-prefixed hex string")
    return value[2:].lower() if value[:2].lower() == "0x" else value.lower()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Parsing / validation
# ---------------------------------------------------------------------------


def _parse_json_line(line: str, lineno: int) -> dict:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"line {lineno}: malformed JSON: {exc.msg}"
        ) from exc
    if not isinstance(obj, dict):
        raise InvalidInputError(f"line {lineno}: event must be a JSON object")
    return obj


def _validate_proof(proof: Any, event_id: Any) -> dict:
    if not isinstance(proof, dict):
        raise InvalidInputError(f"event {event_id!r}: proof must be an object")
    missing = [name for name in PROOF_FIELDS if name not in proof]
    if missing:
        raise InvalidInputError(
            f"event {event_id!r}: proof missing field(s): {', '.join(missing)}"
        )
    for name in PROOF_FIELDS:
        if proof[name] is None:
            raise InvalidInputError(
                f"event {event_id!r}: proof field {name} must not be null"
            )

    version = proof["light_client_version"]
    if not isinstance(version, str) or not version:
        raise InvalidInputError(
            f"event {event_id!r}: light_client_version must be a non-empty string"
        )
    for name in ("trusted_root", "header_hash", "validator_set_hash"):
        if not _is_hex_string(proof[name]):
            raise InvalidInputError(
                f"event {event_id!r}: proof.{name} must be a hex string"
            )

    signatures = proof["signatures"]
    if not isinstance(signatures, list):
        raise InvalidInputError(
            f"event {event_id!r}: proof.signatures must be a list"
        )
    for sig in signatures:
        if not _is_hex_string(sig):
            raise InvalidInputError(
                f"event {event_id!r}: every signature must be a hex string"
            )

    quorum = proof["quorum"]
    if not _is_int(quorum):
        raise InvalidInputError(
            f"event {event_id!r}: proof.quorum must be an integer"
        )
    if quorum < 1:
        raise InvalidInputError(
            f"event {event_id!r}: proof.quorum must be a positive integer"
        )
    return proof


def _validate_event(raw: dict, lineno: int) -> dict:
    event_id = raw.get("event_id", f"line {lineno}")

    missing = [name for name in EVENT_FIELDS if name not in raw]
    if missing:
        raise InvalidInputError(
            f"event {event_id!r}: missing field(s): {', '.join(missing)}"
        )

    if not isinstance(raw["event_id"], str) or not raw["event_id"]:
        raise InvalidInputError(f"line {lineno}: event_id must be a non-empty string")
    if not isinstance(raw["chain_id"], str) or not raw["chain_id"]:
        raise InvalidInputError(
            f"event {raw['event_id']!r}: chain_id must be a non-empty string"
        )
    if not _is_int(raw["sequence"]):
        raise InvalidInputError(
            f"event {raw['event_id']!r}: sequence must be an integer"
        )

    for name in TIME_FIELDS:
        if not _is_int(raw[name]):
            raise InvalidInputError(
                f"event {raw['event_id']!r}: {name} must be an integer "
                "number of milliseconds"
            )

    proof = _validate_proof(raw["proof"], raw["event_id"])

    event = {name: raw[name] for name in EVENT_FIELDS}
    event["proof"] = proof
    return event


def _check_time_order(events: Iterable[dict]) -> None:
    """Each event's clocks must be ordered submit <= verify <= finalize.

    Observation happens off-chain and may legitimately precede or follow
    submission, so it is not forced into the chain ordering; latency stages
    simply report the signed differences and attribution ignores negatives.
    """

    for event in events:
        eid = event["event_id"]
        submit = event["proof_submitted_at"]
        verify = event["proof_verified_at"]
        finalize = event["finalized_at"]
        if submit > verify:
            raise InvalidInputError(
                f"event {eid!r}: proof_submitted_at is after proof_verified_at"
            )
        if verify > finalize:
            raise InvalidInputError(
                f"event {eid!r}: proof_verified_at is after finalized_at"
            )


def load_events(source: Union[PathLike, str]) -> list[dict]:
    """Parse and structurally validate a UTF-8 JSONL event file."""

    events: list[dict] = []
    seen_sequences: set[int] = set()
    seen_timestamps: dict[str, set[int]] = {name: set() for name in TIME_FIELDS}
    try:
        with open(source, "r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                raw = _parse_json_line(text, lineno)
                event = _validate_event(raw, lineno)
                if event["sequence"] in seen_sequences:
                    raise InvalidInputError(
                        f"event {event['event_id']!r}: duplicate sequence "
                        f"{event['sequence']}"
                    )
                seen_sequences.add(event["sequence"])
                for name in TIME_FIELDS:
                    stamp = event[name]
                    if stamp in seen_timestamps[name]:
                        raise InvalidInputError(
                            f"event {event['event_id']!r}: {name} value {stamp} "
                            "is not unique"
                        )
                    seen_timestamps[name].add(stamp)
                events.append(event)
    except OSError as exc:
        raise InvalidInputError(f"cannot read input {str(source)!r}: {exc}") from exc

    _check_time_order(events)
    return events


# ---------------------------------------------------------------------------
# Light client proof verification
# ---------------------------------------------------------------------------
#
# The input is self describing, so every commitment is recomputed solely from
# fields carried by the event - no chain lookup is performed.  Hex values are
# compared case-insensitively and may use or omit the ``0x`` prefix.
#
# Canonical encoding is compact JSON (sorted keys, no whitespace) of the hex
# strings exactly as present after lower-casing, so casing never changes a
# commitment.
#
# * The validator set is represented offline by the distinct signers recovered
#   from ``signatures``; ``validator_set_hash`` must equal the SHA-256 of the
#   canonical encoding of the sorted signer list.
# * The trusted root authenticates a header for a given light client version:
#   it must equal the SHA-256 of the canonical
#   ``{"header_hash": ..., "light_client_version": ...}`` object, or be the
#   header commitment itself (a root pinned directly to that header).


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _sha256_hex(payload)


def _signers(signatures: list[str]) -> list[str]:
    return sorted({_normalize_hash(sig) for sig in signatures})


def _validator_set_hash(version: str, chain_id: str, signatures: list[str]) -> str:
    # version and chain bind the commitment to the light client context so the
    # same signer set cannot be replayed across chains or rule versions.
    document = {
        "chain_id": chain_id,
        "light_client_version": version,
        "signers": _signers(signatures),
    }
    return _canonical_hash(document)


def _trusted_roots(version: str, header_hash: str) -> set[str]:
    header = _normalize_hash(header_hash)
    versioned = _canonical_hash(
        {"header_hash": header, "light_client_version": version}
    )
    return {header, versioned}


def verify_proof(event: dict) -> None:
    """Apply the light client rules.

    Raises :class:`ProofVerificationError` when the structurally complete proof
    does not satisfy every rule; returns normally for a verified proof.
    """

    proof = event["proof"]
    eid = event["event_id"]
    version = proof["light_client_version"]
    signatures: list[str] = proof["signatures"]
    quorum = proof["quorum"]

    # One validator contributes at most one signature; duplicates must not
    # inflate the tally past quorum.
    distinct_signatures = set(signatures)
    if len(distinct_signatures) < quorum:
        raise ProofVerificationError(
            f"event {eid!r}: {len(distinct_signatures)} distinct signatures "
            f"do not reach quorum {quorum}"
        )

    declared = _normalize_hash(proof["validator_set_hash"])
    computed = _validator_set_hash(version, event["chain_id"], signatures)
    if declared != computed:
        raise ProofVerificationError(
            f"event {eid!r}: validator_set_hash does not match the signing set"
        )

    trusted_root = _normalize_hash(proof["trusted_root"])
    if trusted_root not in _trusted_roots(version, proof["header_hash"]):
        raise ProofVerificationError(
            f"event {eid!r}: trusted_root does not verify header_hash for "
            f"light_client_version {version}"
        )


# ---------------------------------------------------------------------------
# Latencies and attribution
# ---------------------------------------------------------------------------


def _attribution(source_ms: int, relay_ms: int, destination_ms: int) -> str:
    """Name of the largest non-negative stage; ties resolve to ``relay``."""

    candidates = [
        (_SOURCE, source_ms),
        (_RELAY, relay_ms),
        (_DESTINATION, destination_ms),
    ]
    non_negative = [(name, value) for name, value in candidates if value >= 0]
    best_value = max(value for _, value in non_negative)
    winners = [name for name, value in non_negative if value == best_value]
    if len(winners) == 1:
        return winners[0]
    # Any tie (including the all-equal case) resolves to relay.
    return _RELAY


def build_report(event: dict) -> dict:
    proof_latency = event["proof_verified_at"] - event["proof_submitted_at"]
    relay_latency = event["proof_verified_at"] - event["observed_at"]
    destination_latency = event["finalized_at"] - event["proof_verified_at"]

    return {
        "event_id": event["event_id"],
        "sequence": event["sequence"],
        "proof_status": "verified",
        "proof_latency_ms": proof_latency,
        "relay_latency_ms": relay_latency,
        "destination_latency_ms": destination_latency,
        "attribution": _attribution(proof_latency, relay_latency, destination_latency),
        "finalized_at": event["finalized_at"],
    }


# ---------------------------------------------------------------------------
# Checkpoint
# ---------------------------------------------------------------------------


def load_checkpoint(path: PathLike) -> Optional[int]:
    """Return ``last_sequence`` from CP, or None when the file is absent."""

    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InvalidInputError(
            f"cannot read checkpoint {str(path)!r}: {exc}"
        ) from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(f"checkpoint is not valid JSON: {exc.msg}") from exc

    if not isinstance(data, dict) or "last_sequence" not in data:
        raise InvalidInputError(
            "checkpoint must be a JSON object containing last_sequence"
        )

    last_sequence = data["last_sequence"]
    if not _is_int(last_sequence):
        # Booleans, floats, strings and null are all "not an integer".
        raise CheckpointError("checkpoint last_sequence must be an integer")
    if last_sequence < 0:
        raise CheckpointError("checkpoint last_sequence must not be negative")
    return last_sequence


def _validate_against_input(last_sequence: int, events: list[dict]) -> None:
    if not events:
        # Nothing to process: a non-negative checkpoint cannot exceed the
        # maximum of an empty stream, so leave it to a successful no-op.
        return
    max_sequence = max(event["sequence"] for event in events)
    if last_sequence > max_sequence:
        raise CheckpointError(
            f"checkpoint last_sequence {last_sequence} exceeds input maximum "
            f"sequence {max_sequence}"
        )


# ---------------------------------------------------------------------------
# Atomic output
# ---------------------------------------------------------------------------


def _atomic_write(path: PathLike, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".relay-watch-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _render_reports(reports: list[dict]) -> str:
    return "".join(
        json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n"
        for report in reports
    )


def _read_report_rows(path: PathLike) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise InvalidInputError(f"cannot read report {str(path)!r}: {exc}") from exc

    rows: list[dict] = []
    for lineno, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InvalidInputError(
                f"existing report {str(path)!r} line {lineno}: malformed JSON"
            ) from exc
        if not isinstance(row, dict):
            raise InvalidInputError(
                f"existing report {str(path)!r} line {lineno}: not a JSON object"
            )
        rows.append(row)
    return rows


def _publish_resumed(path: PathLike, reports: list[dict]) -> None:
    """Append new rows to a cumulative report without ever duplicating one.

    De-duplicating by sequence makes publication idempotent even if a previous
    run wrote the report but crashed before advancing the checkpoint: a re-run
    selects the same events but cannot emit them twice.
    """

    existing = _read_report_rows(path)
    known = {row.get("sequence") for row in existing}
    fresh = [row for row in reports if row["sequence"] not in known]
    if not fresh and existing:
        return
    _atomic_write(path, _render_reports(existing + fresh))


# ---------------------------------------------------------------------------
# Public pipeline
# ---------------------------------------------------------------------------


def watch(
    input_path: PathLike,
    checkpoint: Optional[PathLike] = None,
    output_path: Optional[PathLike] = None,
) -> list[dict]:
    """Run the monitor and return per-event report rows.

    When ``output_path`` is given the JSONL report is written atomically and
    the checkpoint (when given) is advanced atomically only after all selected
    events have been verified successfully.
    """

    events = load_events(input_path)

    last_sequence: Optional[int] = None
    resuming = False
    if checkpoint is not None:
        # Resume only when a checkpoint file actually exists.  An absent file
        # is a fresh start that must fully (re)publish the input rather than
        # merge into a possibly stale report.
        resuming = os.path.exists(checkpoint)
        last_sequence = load_checkpoint(checkpoint)

    if last_sequence is None:
        selected = list(events)
    else:
        _validate_against_input(last_sequence, events)
        selected = [
            event for event in events if event["sequence"] > last_sequence
        ]

    reports: list[dict] = []
    for event in selected:
        verify_proof(event)
        reports.append(build_report(event))

    # Publish output first, then advance the checkpoint, so a crash in between
    # can only re-select rows on the next run, never silently drop events.  On
    # resume the cumulative publisher de-duplicates by sequence, so even that
    # re-selection never writes an event twice.  A fresh start always writes a
    # complete report, replacing any stale file at the output path.
    if output_path is not None:
        if resuming:
            _publish_resumed(output_path, reports)
        else:
            _atomic_write(output_path, _render_reports(reports))

    if checkpoint is not None and selected:
        new_last = max(event["sequence"] for event in selected)
        _atomic_write(
            checkpoint,
            json.dumps({"last_sequence": new_last}, separators=(",", ":")) + "\n",
        )

    return reports


# Friendly keyword name matching the command line surface.
def run(
    input: PathLike,
    checkpoint: Optional[PathLike] = None,
    output: Optional[PathLike] = None,
) -> list[dict]:
    """Module API mirroring ``relay-watch --input --checkpoint --output``."""

    return watch(input, checkpoint, output)
