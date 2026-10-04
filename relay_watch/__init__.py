"""离线跨链中继可靠性监控。

该包校验 JSONL 事件携带的轻客户端证明、对各阶段延迟归因，并通过检查点支持
断点续传。单个输入可承载多个 chain_id：续传与报告去重身份为
(chain_id, sequence)，同一链内 sequence 唯一，不同链可复用同一 sequence；
事件按输入行序处理与返回。检查点为 schema_version 3 的
``{"schema_version": 3, "last_sequence_by_chain": {...}, "processed_lines": N,
"input_prefix_sha256": "..."}``：processed_lines 为已读取且结构有效的 JSONL
物理行数，input_prefix_sha256 为首字节到该行行末原始 UTF-8 字节的摘要；
续传时此前缀须逐字节复算一致、其后仅可追加完整 JSONL 行，且各链游标须等于
前缀内最大 sequence，防止历史事件被改写后仍被游标跳过。schema_version 2
与旧版 last_sequence 检查点仍可读（旧版仅限单链输入），只在确有新事件产生
结果后升级为 v3，无新事件保持空操作。

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
