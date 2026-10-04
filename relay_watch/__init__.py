"""离线跨链中继可靠性监控。

该包校验 JSONL 事件携带的轻客户端证明、对各阶段延迟归因，并通过检查点支持
断点续传。单个输入可承载多个 chain_id：续传与报告去重身份为
(chain_id, sequence)，同一链内 sequence 唯一，不同链可复用同一 sequence；
事件按输入行序处理与返回。检查点当前为 schema_version 3：
``{"schema_version": 3, "last_sequence_by_chain": {...}, "processed_lines": N,
"input_prefix_sha256": "..."}``；processed_lines 是已读取且结构有效的 JSONL
物理行数，input_prefix_sha256 是首字节到第 processed_lines 行行末原始 UTF-8
字节的 SHA-256（64 位小写十六进制，末行无换行不补）。续传时此前处理的前缀
必须与摘要逐字节一致、其后仅可追加完整 JSONL 行，且各链游标必须等于前缀内
最大 sequence，否则抛 CheckpointError。schema_version 2 与旧版
last_sequence 检查点仍按原规则读取，仅在确有新事件完成后升级 v3，无新事件
时空操作且不伪造摘要。

严格处理为默认：首个结构合法但证明失败的事件立即抛 ProofVerificationError，
不写报告、不推进检查点。传入 ``tolerate_failures=True``（CLI：
``--tolerate-failures``）进入逐事件失败隔离模式：每条结构合法事件独立处理，
成功行为 ``proof_status="verified"``，失败行为 ``proof_status="failed"`` 并
携带 ``error_type="ProofVerificationError"`` 与原异常文本 ``error_message``；
失败行的延迟、归因、finalized_at 口径与成功行一致，成功与失败都算已处理并
推进检查点。结构性输入错误与检查点错误在两种模式下都直接抛出、不写报告、不
推进检查点。

可选的序列连续性盘点（``run``/``watch`` 的 ``continuity_output``，CLI 的
``--continuity-output``）仅在整批成功（报告与检查点安全发布）后原子替换一份
UTF-8 JSONL：每条 chain_id 一行并按该链在输入中首次出现排序，字段为
chain_id、event_count、min_sequence、max_sequence、missing_ranges、
missing_count；盘点覆盖整份当前输入而非游标之后，最小值之前不算缺口，空输入
写出空文件。该文件不参与游标，也不改变报告 JSONL 字段；省略时其余行为完全
不变。

公共入口：

* ``relay_watch.run(input, checkpoint=None, output=None,
  tolerate_failures=False, continuity_output=None)`` -> list[dict]
  与命令行同参的模块 API；
* ``python -m relay_watch --input IN --checkpoint CP --output OUT
  [--tolerate-failures [{true,false}]] [--continuity-output PATH]``；
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
