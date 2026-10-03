# Relay Watch

跨链中继可靠性监控：轻客户端证明校验、延迟归因与断点续传。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

已实现：UTF-8 JSONL 离线读取、自描述轻客户端证明校验、三段延迟与归因、
按检查点断点续传、原子 JSONL 报告；单个输入支持多个 chain_id；支持逐事件
失败隔离。

## 多链输入

- 一个 JSONL 输入可承载多个 `chain_id`，各链事件可交错，报告严格按输入
  行序输出。
- 续传与报告去重身份为 `(chain_id, sequence)`：同一链内重复 `sequence`
  抛 `InvalidInputError`，不同链复用同一 `sequence` 合法且互不覆盖。
- 报告行在单链字段基础上增加 `chain_id`，其余字段与数值口径不变。

## 失败隔离

- 默认严格处理：首个 `ProofVerificationError` 立即失败，不写报告、不推进
  检查点（历史行为不变）。
- CLI 传 `--tolerate-failures`、模块 API 传 `tolerate_failures=True` 进入
  隔离模式：结构合法的事件逐条独立处理。
  - 成功行 `proof_status="verified"`；失败行 `proof_status="failed"`，并带
    `error_type="ProofVerificationError"` 与 `error_message`（原有异常文
    本）。
  - 失败行仍输出 `event_id`、`chain_id`、`sequence`、`proof_latency_ms`、
    `relay_latency_ms`、`destination_latency_ms`、`attribution`、
    `finalized_at`，数值口径与成功行一致。
  - 报告按输入行序，以 `chain_id`+`sequence` 去重；同链后续事件不受先前
    失败影响。
  - 被选事件均有确定结果（成功或失败）后，检查点推进到各链已处理的最大
    `sequence`，成功与失败都算已处理。
- 结构性输入错误、重复 `sequence`、时间字段重复或顺序错误仍抛
  `InvalidInputError`；检查点结构问题抛 `InvalidInputError`、游标问题抛
  `CheckpointError`。两种模式下这些错误都不写新报告、不推进检查点。

## 检查点

当前为 schema_version 2：

```json
{"schema_version":2,"last_sequence_by_chain":{"chain-a":3,"chain-b":7}}
```

- 各链只推进本次已处理的最大 `sequence`（严格模式下已处理即验证成功；隔离
  模式下成功与失败都算已处理）；缺失链从第一条开始。
- 旧版 `{"last_sequence": N}` 仍可读：单链输入将其解释为该链游标，成功后
  升级为 v2；多链输入因归属不明抛 `CheckpointError`。
- 游标非非负整数、链标识非非空字符串，或某链游标超过该链输入最大
  `sequence`，抛 `CheckpointError`；结构无法解析、缺字段、出现 `null`、
  数组或未知字段，抛 `InvalidInputError`。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
