"""离线跨链中继可靠性监控。

该包校验 JSONL 事件携带的轻客户端证明、对各阶段延迟归因，并通过检查点支持
断点续传。单个输入可承载多个 chain_id：续传与报告去重身份为
(chain_id, sequence)，同一链内 sequence 唯一，不同链可复用同一 sequence；
事件按输入行序处理与返回。检查点为 schema_version 2 的
``{"schema_version": 2, "last_sequence_by_chain": {...}}``，旧版
last_sequence 检查点仍可读（仅限单链输入，成功后升级）。

默认严格处理：首个 ProofVerificationError 立即失败，不写报告、不推进检查
点。传入 tolerate_failures=True（CLI 为 --tolerate-failures）进入隔离
模式：单条证明失败转成 proof_status="failed"（带 error_type 与
error_message）的报告行，不影响后续事件，成功与失败都推进检查点。

公共入口：

* ``relay_watch.run(input, checkpoint=None, output=None,
  tolerate_failures=False)`` -> list[dict]
  与命令行同参的模块 API；tolerate_failures=True 进入逐事件失败隔离模式，
  单条证明失败转成 proof_status="failed" 报告行而不抛出；
* ``python -m relay_watch --input IN --checkpoint CP --output OUT
  [--tolerate-failures]``；
* ``relay-watch`` 可执行文件。
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
