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

可选的序列连续性盘点（``continuity_output`` / ``--continuity-output``）在
整批成功、报告与检查点安全发布后原子写出：UTF-8 JSONL，每链一行、按首次
出现排序，字段为 chain_id、event_count、min_sequence、max_sequence、
missing_ranges（相邻已出现 sequence 间空缺的升序闭区间）、missing_count。
盘点覆盖整个当前输入而非游标之后，续传、追加与重复执行结果一致；省略该
参数时行为与旧版完全一致。

可选的延迟越界清单（``latency_thresholds`` 与 ``latency_breach_output`` /
``--latency-thresholds`` 与 ``--latency-breach-output``，必须成对给出）在
报告、检查点、连续性盘点均安全发布后最后原子写出。阈值文件为 UTF-8 JSON
对象，仅含 proof_latency_ms、relay_latency_ms、destination_latency_ms 三个
非负整数毫秒字段，不合规抛 InvalidInputError；清单为 UTF-8 JSONL，按本次
运行新产出报告行的行序逐行检查，三个延迟字段仅严格大于同名阈值才越界，
breached_stages 按 proof_latency_ms、relay_latency_ms、
destination_latency_ms 顺序列出，行字段为 event_id、chain_id、sequence、
proof_status、breached_stages、attribution、finalized_at。隔离模式的失败
报告行同样参与（proof_status=failed）；严格模式证明失败仍抛
ProofVerificationError，不写清单。无越界或无新事件写空文件；省略这对参数
时行为与旧版完全一致。

可选的链级延迟画像（``latency_profile_output`` /
``--latency-profile-output``）在报告、检查点、已启用的连续性盘点均安全
发布后、延迟越界清单之前原子写出：UTF-8 JSONL，按 chain_id 首次出现顺序
每链一行，覆盖当前输入全部结构合法事件而非游标后的新行，空输入写空文件。
行字段为 chain_id、event_count、proof_latency_ms、relay_latency_ms、
destination_latency_ms（三个延迟对象仅含 min、p50、p95、max，p50/p95 用
最近秩，秩为 max(1,ceil(0.50*n))、max(1,ceil(0.95*n))，单事件四项相同）
与 attribution_counts（仅含 source、relay、destination，按现有归因计数，
未出现写 0）。隔离模式 proof_status=failed 的事件与 verified 一起统计；
严格模式证明失败仍抛 ProofVerificationError，报告、检查点、连续性盘点、
延迟越界清单和画像都不写；领域错误不生成画像，省略该参数时既有结果不变。

公共入口：

* ``relay_watch.run(input, checkpoint=None, output=None,
  tolerate_failures=False, continuity_output=None,
  latency_thresholds=None, latency_breach_output=None,
  latency_profile_output=None)`` -> list[dict]
  与命令行同参的模块 API；
* ``python -m relay_watch --input IN --checkpoint CP --output OUT
  [--continuity-output PATH] [--tolerate-failures [{true,false}]]
  [--latency-thresholds PATH --latency-breach-output PATH]
  [--latency-profile-output PATH]``；
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
