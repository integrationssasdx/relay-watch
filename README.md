# Relay Watch

跨链中继可靠性监控：轻客户端证明校验、延迟归因与断点续传。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

已实现：UTF-8 JSONL 离线读取、自描述轻客户端证明校验、三段延迟与归因、
按检查点断点续传（v3 含续传输入前缀完整性保护）、原子 JSONL 报告；单个
输入支持多个 chain_id；可选的逐事件失败隔离；可选的序列连续性缺口盘点；
可选的延迟越界清单。

## 延迟越界清单

成对传入 `--latency-thresholds PATH --latency-breach-output PATH`（模块
API 为 `run(..., latency_thresholds=PATH, latency_breach_output=PATH)`）
后，在报告、检查点、连续性盘点（若有）都安全发布之后，最后原子写出一份
UTF-8 JSONL 越界清单；两个参数缺一不可（CLI 以 `InvalidArgument` 固定
JSON、退出码 2 报错；API 抛 `InvalidInputError`）。

- 阈值文件为 UTF-8 JSON 对象，**仅含** `proof_latency_ms`、
  `relay_latency_ms`、`destination_latency_ms` 三个字段，值为非负整数
  毫秒；不是 JSON 对象、缺字段、出现未知字段、值为布尔/浮点/字符串/
  null/负数等都抛 `InvalidInputError`。
- 按本次运行新产出报告行的输入行序逐行检查：三个延迟字段仅在**严格大于**
  同名阈值时越界（等于不越界）。
- 每个越界事件一行，字段为 `event_id`、`chain_id`、`sequence`、
  `proof_status`、`breached_stages`、`attribution`、`finalized_at`；
  `breached_stages` 按 `proof_latency_ms`、`relay_latency_ms`、
  `destination_latency_ms` 的固定顺序列出该事件越界的阶段。
- 只查本次运行的新报告行：续传已发布的历史行不重查，无新事件或无越界时
  写空文件。
- 隔离模式（`--tolerate-failures`）下证明失败的报告行同样参与，
  `proof_status="failed"`；严格模式证明失败仍抛 `ProofVerificationError`，
  报告、检查点、清单都不写。
- 任何领域错误（输入/检查点/阈值不合规、证明失败等）都不写清单；清单不
  改报告与检查点字段。省略这对参数时不生成额外文件，旧报告、检查点、
  异常与退出码完全不变。阈值文件打不开、清单路径不可写等文件错误沿用
  CLI 的 OSError 子类 JSON 错误与非零退出。

## 序列连续性盘点

传入 `--continuity-output PATH`（模块 API 为
`run(..., continuity_output=PATH)`）后，整批成功、报告与检查点安全发布
之后，额外原子写出一份 UTF-8 JSONL 盘点：每条 `chain_id` 一行、按首次
出现排序，字段为 `chain_id`、`event_count`、`min_sequence`、
`max_sequence`、`missing_ranges`、`missing_count`。

- `event_count` 统计该链结构合法事件；`min_sequence`/`max_sequence` 取已
  出现值。
- `missing_ranges` 升序列出相邻已出现 `sequence` 之间的空缺，每项为闭区间
  `{"start": s, "end": e}`（两端皆缺失）；`missing_count` 为缺失总数。
- `sequence` 可从任意非负值开始，最小值之前不算缺口；单值或连续时
  ranges 为空、计数为 0；空输入输出空文件。
- 盘点覆盖整个当前输入而非游标之后，续传、追加与重复执行结果一致；
  `tolerate_failures` 下证明失败的事件仍占有其 `sequence`，严格模式失败
  仍抛 `ProofVerificationError` 且不写盘点。
- 盘点不参与游标，也不改报告字段；省略该参数时报告、检查点、异常与退出
  码与旧版完全一致。路径不可写沿用 CLI 的 OSError JSON 错误与非零退出。

## 严格模式与失败隔离

默认为严格处理：结构合法但证明失败的首个事件立即抛
`ProofVerificationError`（CLI 以非零码退出），不写报告、不推进检查点。

传入 `--tolerate-failures true`（裸用 `--tolerate-failures` 等价于 `true`；
模块 API 为 `run(..., tolerate_failures=True)`）进入逐事件失败隔离：

- 结构合法事件逐条独立处理，单条证明失败不再阻断后续校验、延迟归因和报告
  生成。
- 成功行 `proof_status="verified"`；失败行 `proof_status="failed"`，并带
  `error_type="ProofVerificationError"`、`error_message`（原异常文本）。
- 失败行仍输出 `event_id`、`chain_id`、`sequence`、`proof_latency_ms`、
  `relay_latency_ms`、`destination_latency_ms`、`attribution`、
  `finalized_at`，数值口径与成功行一致。
- 报告按输入行序，以 `(chain_id, sequence)` 去重；同链后续事件不受先前
  失败影响。
- 被选事件都有确定结果（成功或失败）后，检查点推进到各链本次已处理的最大
  `sequence`——成功与失败都算已处理。
- 已有报告续传去重追加，全新开始原子替换；隔离模式同样遵守这两个发布规则。
- 结构性输入错误、重复 `sequence`、时间字段重复或顺序错误仍抛
  `InvalidInputError`；检查点结构问题抛 `InvalidInputError`，游标问题抛
  `CheckpointError`。两种模式下这些错误都不写新报告、不推进检查点。
- `--tolerate-failures false` 为默认兼容值；取值仅接受 `true`/`false`。

## 多链输入

- 一个 JSONL 输入可承载多个 `chain_id`，各链事件可交错，报告严格按输入
  行序输出。
- 续传与报告去重身份为 `(chain_id, sequence)`：同一链内重复 `sequence`
  抛 `InvalidInputError`，不同链复用同一 `sequence` 合法且互不覆盖。
- 报告行在单链字段基础上增加 `chain_id`，其余字段与数值口径不变。

## 检查点

当前为 schema_version 3：

```json
{"schema_version":3,"last_sequence_by_chain":{"chain-a":3,"chain-b":7},"processed_lines":12,"input_prefix_sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}
```

- `processed_lines` 是已读取且结构有效的 JSONL **物理行数**（空行不计入，
  但行字节位于摘要覆盖范围内）。
- `input_prefix_sha256` 是输入首字节到第 `processed_lines` 行行末的**原始
  UTF-8 字节** SHA-256，写作 64 位小写十六进制；行末换行计入摘要，末行无
  换行不补。
- 一次有选中事件的运行先原子发布报告，再原子写检查点：严格模式下被选事件
  全部成功，或 `tolerate_failures=true` 下均有成功/失败结果后，各链游标推进
  到本次结果链的最大 sequence，其他链游标保留，并更新 `processed_lines` 与
  摘要。
- 续传时前 `processed_lines` 行必须与摘要**逐字节一致**，其后仅可追加完整
  JSONL 行（追加段同样经过结构校验）；摘要不一致、`processed_lines` 非正
  整数或超过输入行数、某链游标与前缀内最大 sequence 不一致（含前缀链游标
  缺失），抛 `CheckpointError`，CLI 以固定 JSON 错误格式非零退出，且不写
  报告或检查点——同一 `(chain_id, sequence)` 的历史事件即使被改写，也不会
  被游标静默跳过。
- v3 字段缺失、出现未知字段、类型错误（`processed_lines` 非整数、
  `input_prefix_sha256` 不是恰好 64 位小写十六进制字符串等）抛
  `InvalidInputError`。
- 旧版 `{"last_sequence": N}` 与 `schema_version` 2 检查点仍按原规则读取
  （旧版仅限单链输入归属，多链抛 `CheckpointError`；两者均不做前缀校验），
  只在确有新事件完成（严格模式成功；隔离模式成功或失败）后才升级为 v3——
  升级时才首次计算摘要，绝不伪造；无新事件保持空操作，检查点文件原样
  保留。
- 游标非非负整数、链标识非非空字符串，或某链游标超过该链输入最大
  `sequence`，仍按 `CheckpointError` 处理；结构无法解析、缺字段、出现
  `null`、数组或未知字段，抛 `InvalidInputError`。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
