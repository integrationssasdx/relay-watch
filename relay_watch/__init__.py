"""Offline cross-chain relay reliability monitoring.

The package validates light-client proofs carried by JSONL events, attributes
per-phase latency and supports resumable processing through a checkpoint.

Public entry points:

* ``relay_watch.run(input, checkpoint=None, output=None)`` -> list[dict]
  module API using the same path arguments as the command line;
* ``python -m relay_watch --input IN --checkpoint CP --output OUT``;
* the ``relay-watch`` executable.
"""

from .core import (
    CheckpointError,
    InvalidInputError,
    ProofVerificationError,
    RelayWatchError,
    run,
    watch,
)

__all__ = [
    "run",
    "watch",
    "RelayWatchError",
    "InvalidInputError",
    "ProofVerificationError",
    "CheckpointError",
]

__version__ = "1.0.0"
