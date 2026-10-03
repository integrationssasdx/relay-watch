"""离线跨链中继可靠性监控。

该包校验 JSONL 事件携带的轻客户端证明、对各阶段延迟归因，并通过检查点支持
断点续传。单个输入可承载多个 chain_id：续传与报告去重身份为
(chain_id, sequence)，同一链内 sequence 唯一，不同链可复用同一 sequence；
事件按输入行序处理与返回。检查点为 schema_version 2 的
``{"schema_version": 2, "last_sequence_by_chain": {...}}``，旧版
last_sequence 检查点仍可读（仅限单链输入，成功后升级）。

严格处理为默认：首个结构合法但证明失败的事件立即抛 ProofVerificationError，
不写报告、不推进检查点。传入 ``tolerate_failures=True``（CLI：
``--tolerate-failures``）进入逐事件失败隔离模式：每条结构合法事件独立处理，
成功行为 ``proof_status="verified"``，失败行为 ``proof_status="failed"`` 并
携带 ``error_type="ProofVerificationError"`` 与原异常文本 ``error_message``；
失败行的延迟、归因、finalized_at 口径与成功行一致，成功与失败都算已处理并
推进检查点。结构性输入错误与检查点错误在两种模式下都直接抛出、不写报告、不
推进检查点。

公共入口：

* ``relay_watch.run(input, checkpoint=None, output=None,
  tolerate_failures=False)`` -> list[dict]
  与命令行同参的模块 API；
* ``python -m relay_watch --input IN --checkpoint CP --output OUT
  [--tolerate-failures [{true,false}]]``；
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
