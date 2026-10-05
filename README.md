# Relay Watch

跨链中继可靠性监控：轻客户端证明校验、延迟归因与断点续传。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

已实现：UTF-8 JSONL 离线读取、自描述轻客户端证明校验、三段延迟与归因、
按检查点断点续传（v3 含续传输入前缀完整性保护）、原子 JSONL 报告；单个
输入支持多个 chain_id；可选的逐事件失败隔离；可选的序列连续性缺口盘点；
可选的延迟越界清单；可选的链级延迟画像；可选的链级 SLO 汇总；可选的链级
时间窗口趋势画像；可选的轻客户端证明校验审计画像。

## 轻客户端证明校验审计画像

传入 `--proof-audit-output PATH`（模块 API 为
`run(..., proof_audit_output=PATH)`）后，在报告、检查点、连续性盘点、
链级延迟画像、延迟越界清单（若有）、链级 SLO 汇总（若有）与链级时间窗口
趋势画像（若有）都安全发布之后，**最后**原子替换一份 UTF-8 JSONL 审计
画像。画像按**输入行序**为当前完整输入的**全部结构合法事件**各写一行，
而非游标后的新行，因此续传、追加与重复执行结果一致，空输入原子写空文件。

- 每行字段为 `event_id`、`chain_id`、`sequence`、`proof_status`、
  `light_client_version`、`provided_signature_count`、
  `unique_signature_count`、`quorum`、`checks`、`failed_checks`、
  `finalized_at`。
- `proof_status` 仅取 `verified` 或 `failed`：三项检查全部为 true 才是
  `verified`。
- `provided_signature_count` 为原始 `proof.signatures` 列表长度（不做
  任何处理）；`unique_signature_count` 为 quorum 判定所用的原始签名
  字符串去重集合大小（重复签名只计一次）。
- `checks` 恰好含三个布尔键，依次为 `quorum_sufficient`、
  `validator_set_hash_matches`、`trusted_root_matches_header`，各自
  复用现有证明规则独立判定（一项失败不短路其余项）：去重签名达到 quorum；
  声明的验证者集合哈希等于按版本、链与签名者重算的承诺；可信根属于该
  版本下认证区块头哈希的候选承诺之一。
- `failed_checks` 仅按上述固定顺序列出值为 false 的键；`verified` 行为
  `[]`。
- 审计画像是只读推导：不参与游标与汇总，不改报告、检查点、输入前缀
  摘要或任何既有输出。
- 隔离模式（`--tolerate-failures true`）下成功与失败事件都入画像：
  报告失败行仍含 `error_type`/`error_message`，审计行 `proof_status`
  为 `failed`；严格模式证明失败（含游标覆盖的历史失败事件，例如先前以
  隔离模式处理、本次改为严格模式续传）仍在任何发布之前抛
  `ProofVerificationError`，不写画像。
- 结构错误、同链重复 `sequence`、时间顺序错误与检查点不合规仍抛
  `InvalidInputError` 或 `CheckpointError`，CLI 错误 JSON 与退出码
  不变且不写画像。画像路径不可写等文件错误沿用 CLI 的 OSError 子类
  固定 JSON 错误与非零退出（此前已发布的产物不受影响）。
- 省略该参数时 CLI、`run`、报告、检查点、异常与退出码与旧版完全一致。

## 链级时间窗口趋势画像

成对传入 `--trend-window-ms N --trend-output PATH`（模块 API 为
`run(..., trend_window_ms=N, trend_output=PATH)`）后，在报告、检查点、
连续性盘点、链级延迟画像、延迟越界清单（若有）与链级 SLO 汇总（若有）都
安全发布之后，**最后**原子替换一份 UTF-8 JSONL 趋势画像；两个参数缺一不
可（CLI 以 `InvalidArgument` 固定 JSON、退出码 2 报错；API 抛
`InvalidInputError`）。画像按 `chain_id` 在输入中的首次出现顺序、链内按
窗口起点升序，每个非空窗口一行；覆盖**当前输入全部结构合法事件**而非游标
后的新行，因此续传、追加与重复执行结果一致，空输入原子写空文件。

- 窗口宽度 `N` 仅接受大于等于 1 的整数毫秒；缺参、未知参数、语法错误
  （非整数、浮点、布尔、符号、空白等）或宽度错误（`0`、负数）CLI 一律
  输出固定 `InvalidArgument` JSON 并以退出码 2 退出，API 抛
  `InvalidInputError`。
- `window_start_ms` 取不大于 `finalized_at` 的最大 `N` 的整数倍
  （`finalized_at // N * N`），按 `chain_id` 与该起点合并；没有事件落入
  的空窗口不输出。
- 每行字段为 `chain_id`、`window_start_ms`、`event_count`、
  `proof_failure_count`、`attribution_counts`、`latency_p95_ms`。
- `event_count` 为该窗口事件数，`proof_failure_count` 为其中证明失败数；
  `attribution_counts` 仅含 `source`、`relay`、`destination` 三个键，
  归因沿用单事件口径，未出现写 0。
- `latency_p95_ms` 仅含三个整数键 `proof_latency_ms`、`relay_latency_ms`、
  `destination_latency_ms`，各取该窗口事件对应延迟的最近秩 p95
  `max(1,ceil(0.95*n))`（`n` 为窗口事件数）。
- 隔离模式（`--tolerate-failures true`）下成功与失败事件都计入
  `event_count`，失败事件另计 `proof_failure_count`，三段延迟与归因同口
  径；严格模式证明失败仍抛 `ProofVerificationError`，报告、检查点、连续性
  盘点、画像、越界清单、SLO 汇总和趋势画像都不写。
- 同链 `sequence` 重复、时间字段非法、输入或检查点不合规仍抛
  `InvalidInputError` 或 `CheckpointError`，沿用现有异常退出码且不写趋势
  文件。趋势不参与游标，也不改任何既有输出；省略这对参数时报告、检查点、
  异常与退出码与旧版完全一致。趋势路径不可写等文件错误沿用 CLI 的
  OSError 子类固定 JSON 错误与非零退出（此前已发布的产物不受影响）。

## 链级 SLO 汇总

成对传入 `--chain-slo-thresholds PATH --chain-health-output PATH`（模块
API 为 `run(..., chain_slo_thresholds=PATH, chain_health_output=PATH)`）
后，在报告、检查点、连续性盘点、链级延迟画像、延迟越界清单（若有）都
安全发布之后，最后原子替换一份 UTF-8 JSONL 汇总；两个参数缺一不可（CLI
以 `InvalidArgument` 固定 JSON、退出码 2 报错；API 抛
`InvalidInputError`）。汇总按 `chain_id` 在输入中的首次出现顺序每链一行，
覆盖**当前输入全部结构合法事件**而非游标后的新行，因此续传、追加与重复
执行结果一致，空输入写空文件。

- 阈值文件为 UTF-8 JSON 对象，**仅含** `proof_failure_rate_permille`、
  `missing_sequence_rate_permille`、`proof_latency_ms_p95`、
  `relay_latency_ms_p95`、`destination_latency_ms_p95` 五个字段；两个
  比率为 0 到 1000 的整数千分率，三个 p95 为非负整数毫秒。不是 JSON
  对象、缺字段、出现未知字段、值为布尔/浮点/字符串/null/越界值等都抛
  `InvalidInputError`。
- 每行字段为 `chain_id`、`event_count`、`proof_failure_rate_permille`、
  `missing_sequence_rate_permille`、`latency_p95_ms`、`violations`。
- `proof_failure_rate_permille = ceil(失败数 / 事件数 * 1000)`；
  `missing_sequence_rate_permille = ceil(missing_count /
  (event_count + missing_count) * 1000)`，`missing_count` 与序列连续性
  盘点同口径（相邻已出现 sequence 之间的空缺总数）。
- `latency_p95_ms` 仅含三个整数键 `proof_latency_ms`、
  `relay_latency_ms`、`destination_latency_ms`（即三个 p95 阈值名去掉
  `_p95` 后缀），值取该链全部事件对应延迟的最近秩 p95
  `max(1,ceil(0.95*n))`，与链级延迟画像的 p95 完全一致。
- `violations` 按两个比率、三个 p95 的固定顺序，仅列出指标值**严格大于**
  同名阈值的指标名；全部达标为 `[]`。
- 隔离模式（`--tolerate-failures`）下 `proof_status=failed` 的事件计入
  失败数（分母为全部事件），并与 verified 行一起计入三个 p95；严格模式
  证明失败仍抛 `ProofVerificationError`，报告、检查点、连续性盘点、画像、
  越界清单和汇总都不写。
- 同链 `sequence` 重复、时间字段非法、输入或检查点不合规仍抛
  `InvalidInputError` 或 `CheckpointError`，领域错误不生成汇总。汇总不
  参与游标，也不改任何既有输出；省略这对参数时报告、检查点、异常与退出
  码与旧版完全一致。阈值文件打不开、汇总路径不可写等文件错误沿用 CLI 的
  OSError 子类固定 JSON 错误与非零退出。

## 链级延迟画像

传入 `--latency-profile-output PATH`（模块 API 为
`run(..., latency_profile_output=PATH)`）后，在整批成功、报告与检查点
安全发布、已启用的连续性盘点安全发布之后、延迟越界清单（若有）之前，
原子替换一份 UTF-8 JSONL 画像：按 `chain_id` 在输入中的首次出现顺序，
每链一行；画像覆盖**当前输入全部结构合法事件**而非游标后的新行，因此
续传、追加与重复执行结果一致，空输入写空文件。

- 每行字段为 `chain_id`、`event_count`、`proof_latency_ms`、
  `relay_latency_ms`、`destination_latency_ms`、`attribution_counts`。
- 三个延迟对象**仅含** `min`、`p50`、`p95`、`max`，值取该链事件对应
  字段的整数毫秒升序数据；`p50`、`p95` 用最近秩，秩分别为
  `max(1,ceil(0.50*n))`、`max(1,ceil(0.95*n))`（`event_count` 为 n），
  单事件四项相同。
- `attribution_counts` 仅含 `source`、`relay`、`destination`，按现有
  归因计数，未出现的归因写 0。
- 隔离模式（`--tolerate-failures`）下 `proof_status=failed` 的事件同样
  有确定延迟与归因，与 `verified` 行一起统计；严格模式证明失败仍抛
  `ProofVerificationError`，报告、检查点、连续性盘点、延迟越界清单和
  画像都不写。
- 画像不参与游标，也不改报告、检查点与越界清单字段；同链 `sequence`
  重复、时间字段非法、输入或检查点不合规仍抛 `InvalidInputError` 或
  `CheckpointError`，领域错误不生成画像。省略该参数时报告、检查点、
  异常与退出码与旧版完全一致。画像路径不可写、输入读取失败等文件错误
  沿用 CLI 的 OSError 子类固定 JSON 错误与非零退出。

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
