"""Command line interface for the relay-watch command.

relay-watch --input IN --checkpoint CP --output OUT

All processing happens offline.  On any domain error the command writes a
single fixed-shape JSON object ``{"error": ..., "message": ...}`` to standard
error, exits non-zero and never leaves a partially written report.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .core import (
    CheckpointError,
    InvalidInputError,
    ProofVerificationError,
    run,
)


class _JsonArgumentParser(argparse.ArgumentParser):
    """Argparse parser that reports usage errors as the fixed JSON object."""

    def error(self, message: str) -> None:  # type: ignore[override]
        emit_error("InvalidArgument", message)
        raise SystemExit(2)


def emit_error(error: str, message: str) -> None:
    """Write the fixed error object as one JSON line on standard error."""

    sys.stderr.write(
        json.dumps({"error": error, "message": message}, ensure_ascii=False) + "\n"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        prog="relay-watch",
        description=(
            "Offline cross-chain relay reliability monitor: validates "
            "light-client proofs, attributes latency and resumes from a "
            "checkpoint."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        metavar="IN",
        help="UTF-8 JSONL file of relay events",
    )
    parser.add_argument(
        "--checkpoint",
        required=True,
        metavar="CP",
        help=(
            "checkpoint JSON file carrying last_sequence; an absent file "
            "means start from the first event"
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        metavar="OUT",
        help="destination JSONL report (written atomically)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        run(args.input, args.checkpoint, args.output)
    except ProofVerificationError as exc:
        emit_error("ProofVerificationError", str(exc))
        return 1
    except CheckpointError as exc:
        emit_error("CheckpointError", str(exc))
        return 1
    except InvalidInputError as exc:
        emit_error("InvalidInputError", str(exc))
        return 1
    except OSError as exc:
        emit_error(type(exc).__name__, str(exc))
        return 1
    return 0
