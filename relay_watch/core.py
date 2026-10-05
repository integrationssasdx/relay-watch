"""离线中继可靠性监控的核心实现。

数据模型完全自包含（仅标准库），所有校验都由事件自带字段推导，无网络或
链上查询。

事件（JSONL 每行一个 JSON 对象）::

    event_id, chain_id, sequence, observed_at, proof_submitted_at,
    proof_verified_at, finalized_at, proof

``proof`` 含 ``light_client_version``、``trusted_root``、``header_hash``、
``validator_set_hash``、``signatures`` 和 ``quorum``。

仅当去重后的签名集合达到 ``quorum``、声明的验证者集合哈希与签名者一致、
可信根在给定轻客户端版本下认证了区块头哈希时，proof 才为 ``verified``。

一个输入可承载多个 ``chain_id``：sequence 仅在同一链内唯一（同链重复抛
InvalidInputError），不同链可复用同一 sequence；各链事件可交错，报告严格按
输入行序生成。续传与去重身份为 ``(chain_id, sequence)``。

默认严格处理：首个证明失败事件立即抛 ProofVerificationError。传入
``tolerate_failures=True`` 进入隔离模式后，结构合法事件逐条独立处理，证明
失败转为 ``proof_status="failed"`` 报告行（携带 error_type/error_message），
不阻断后续事件；成功与失败都算已处理并推进检查点。结构性输入/检查点错误在
两种模式下都直接抛出。

检查点当前为 schema_version 3：除按链游标外，还记录 ``processed_lines``
（已读取且结构有效的 JSONL 物理行数）与 ``input_prefix_sha256``（首字节到
第 processed_lines 行行末的原始 UTF-8 字节 SHA-256，64 位小写十六进制，
末行无换行不补）。续传时前 processed_lines 行必须与摘要逐字节一致，其后
仅可追加完整 JSONL 行；摘要不一致、processed_lines 非法或某链游标与前缀
内最大 sequence 不一致都抛 CheckpointError，防止历史事件被改写后仍被游标
跳过。旧版 last_sequence 与 schema_version 2 检查点仍按原规则读取，仅在
确有新事件成功（隔离模式下成功或失败）后才升级 v3，升级前不伪造摘要；无
新事件保持空操作，检查点文件原样保留。

可选的序列连续性盘点（``continuity_output``）在整批成功、报告与检查点
安全发布后原子写出：每链一行，统计该链结构合法事件数、已出现 sequence
的最小/最大值，以及相邻 sequence 间空缺的升序闭区间与缺失总数。盘点覆盖
整个当前输入而非游标之后，不参与游标，也不改报告字段；省略时行为与旧版
完全一致。

可选的延迟越界清单（``latency_thresholds`` 与 ``latency_breach_output``
成对给出）在报告、检查点、连续性盘点均安全发布后最后原子写出：阈值文件为
UTF-8 JSON 对象，仅含 proof_latency_ms、relay_latency_ms、
destination_latency_ms 三个非负整数毫秒字段，不合规抛 InvalidInputError；
按报告行序逐行查本次运行新产出的报告行，三个延迟字段仅在严格大于同名阈值
时列入 breached_stages（顺序固定为 proof_latency_ms、relay_latency_ms、
destination_latency_ms）。隔离模式下的失败报告行同样参与（proof_status 为
failed）；严格模式的证明失败仍在发布前抛 ProofVerificationError，不写清单。
无越界或无新事件时写空文件；任何领域错误都不写清单。省略这对参数时行为与
旧版完全一致。

可选的链级延迟画像（``latency_profile_output``）在报告、检查点、已启用的
连续性盘点均安全发布后、延迟越界清单之前原子写出：UTF-8 JSONL，按 chain_id
在输入中首次出现顺序每链一行，覆盖当前输入全部结构合法事件而非游标后的新
行；空输入写空文件。每行含 chain_id、event_count、三个延迟统计对象
（proof_latency_ms、relay_latency_ms、destination_latency_ms，各仅含 min、
p50、p95、max，p50/p95 取最近秩 max(1,ceil(0.50*n))、
max(1,ceil(0.95*n))）与 attribution_counts（仅含 source、relay、destination，未出现写 0）。隔离模式下 proof_status=failed 的事件同样有确定
延迟与归因，与 verified 一起统计；严格模式证明失败仍在发布前抛
ProofVerificationError，不写画像。任何领域错误都不写画像；省略该参数时行为
与旧版完全一致。

可选的链级 SLO 汇总（``chain_slo_thresholds`` 与 ``chain_health_output``
成对给出）在报告、检查点、连续性盘点、延迟画像、延迟越界清单全部安全发布
后最后原子写出：阈值文件为 UTF-8 JSON 对象，仅含
proof_failure_rate_permille、missing_sequence_rate_permille、
proof_latency_ms_p95、relay_latency_ms_p95、
destination_latency_ms_p95 五个字段；前两项为 0 到 1000 的整数千分率上限，
后三项为非负整数毫秒，字段或值不合规抛 InvalidInputError。汇总覆盖当前
输入全部结构合法事件（与游标无关），按 chain_id 首现顺序每链一行 UTF-8
JSONL：proof_failure_rate_permille 为隔离模式 proof_status=failed 事件数
除以事件数乘 1000 向上取整（严格模式的证明失败仍在发布前抛
ProofVerificationError，不写汇总，故该比率恒为 0），
missing_sequence_rate_permille 为连续性盘点口径的 missing_count 除以
(event_count+missing_count) 乘 1000 向上取整；latency_p95_ms 的三个整数
键取阈值名去掉 ``_p95`` 后缀（proof_latency_ms、relay_latency_ms、
destination_latency_ms），值取链级延迟画像的 p95 最近秩，含失败行；
violations 按两比率、三 p95 的固定顺序仅列严格大于阈值的项，达标为 []。
空输入写空文件；任何领域错误都不写汇总。省略这对参数时行为与旧版完全
一致。
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Union

PathLike = Union[str, "os.PathLike[str]"]

# 检查点结构版本；v3 在 v2 按链游标之外增加 processed_lines 与
# input_prefix_sha256，做续传输入前缀的逐字节完整性保护。
SCHEMA_VERSION = 3

# v3 摘要必须是恰好 64 位小写十六进制（SHA-256 hexdigest）。
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

EVENT_FIELDS = (
    "event_id",
    "chain_id",
    "sequence",
    "observed_at",
    "proof_submitted_at",
    "proof_verified_at",
    "finalized_at",
    "proof",
)

TIME_FIELDS = (
    "observed_at",
    "proof_submitted_at",
    "proof_verified_at",
    "finalized_at",
)

PROOF_FIELDS = (
    "light_client_version",
    "trusted_root",
    "header_hash",
    "validator_set_hash",
    "signatures",
    "quorum",
)

# 三个延迟阶段名，顺序即平局时的判定依据。
_SOURCE = "source"
_RELAY = "relay"
_DESTINATION = "destination"

# 延迟阈值字段名，亦即越界清单 breached_stages 中使用的阶段名；顺序即清单
# 中各越界阶段的固定列出顺序，也是延迟画像中三个统计对象的固定键序。
LATENCY_THRESHOLD_FIELDS = (
    "proof_latency_ms",
    "relay_latency_ms",
    "destination_latency_ms",
)

# 延迟画像 attribution_counts 的固定键序（归因阶段名）。
ATTRIBUTION_FIELDS = (_SOURCE, _RELAY, _DESTINATION)

# 链级 SLO 阈值字段名与固定顺序：先两个千分率上限，再三段 p95 毫秒上限；
# 顺序即 health 行 violations 中各违规项的固定列出顺序。
CHAIN_SLO_RATE_FIELDS = (
    "proof_failure_rate_permille",
    "missing_sequence_rate_permille",
)
CHAIN_SLO_LATENCY_P95_FIELDS = (
    "proof_latency_ms_p95",
    "relay_latency_ms_p95",
    "destination_latency_ms_p95",
)
CHAIN_SLO_THRESHOLD_FIELDS = (
    CHAIN_SLO_RATE_FIELDS + CHAIN_SLO_LATENCY_P95_FIELDS
)


class RelayWatchError(Exception):
    """relay_watch 所有异常的基类。"""


class InvalidInputError(RelayWatchError):
    """JSONL 输入（或检查点）无法解析或前后不一致。"""


class ProofVerificationError(RelayWatchError):
    """结构完整的事件未通过轻客户端证明规则。"""


class CheckpointError(RelayWatchError):
    """检查点 last_sequence 对当前输入不可用。"""


# --------------------------------------------------------------------------- #
# 小型结构工具
# --------------------------------------------------------------------------- #
def _is_int(value: Any) -> bool:
    """真正的整数（JSON 无小数部分的数字）；bool 虽是 int 子类也不接受。"""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex_string(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    body = value[2:] if value[:2].lower() == "0x" else value
    if not body or len(body) % 2:
        return False
    try:
        int(body, 16)
    except ValueError:
        return False
    return True


def _normalize_hash(value: str) -> str:
    """去除可选 0x 前缀并小写；非十六进制报输入错误。"""
    if not _is_hex_string(value):
        raise InvalidInputError("hash field must be a 0x-prefixed hex string")
    return value[2:].lower() if value[:2].lower() == "0x" else value.lower()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_hash(value: Any) -> str:
    """规范编码（排序键、无空白）后取 sha256，大小写不影响承诺。"""
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _sha256_hex(payload)


# --------------------------------------------------------------------------- #
# 解析 / 结构校验
# --------------------------------------------------------------------------- #
def _parse_json_line(line: str, lineno: int) -> dict:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"line {lineno}: malformed JSON: {exc.msg}"
        ) from exc
    if not isinstance(obj, dict):
        raise InvalidInputError(f"line {lineno}: event must be a JSON object")
    return obj


def _validate_proof(proof: Any, event_id: Any) -> dict:
    if not isinstance(proof, dict):
        raise InvalidInputError(f"event {event_id!r}: proof must be an object")

    missing = [name for name in PROOF_FIELDS if name not in proof]
    if missing:
        raise InvalidInputError(
            f"event {event_id!r}: proof missing field(s): {', '.join(missing)}"
        )
    for name in PROOF_FIELDS:
        if proof[name] is None:
            raise InvalidInputError(
                f"event {event_id!r}: proof field {name} must not be null"
            )

    version = proof["light_client_version"]
    if not isinstance(version, str) or not version:
        raise InvalidInputError(
            f"event {event_id!r}: light_client_version must be a non-empty "
            "string"
        )

    for name in ("trusted_root", "header_hash", "validator_set_hash"):
        if not _is_hex_string(proof[name]):
            raise InvalidInputError(
                f"event {event_id!r}: proof.{name} must be a hex string"
            )

    signatures = proof["signatures"]
    if not isinstance(signatures, list):
        raise InvalidInputError(
            f"event {event_id!r}: proof.signatures must be a list"
        )
    for sig in signatures:
        if not _is_hex_string(sig):
            raise InvalidInputError(
                f"event {event_id!r}: every signature must be a hex string"
            )

    quorum = proof["quorum"]
    if not _is_int(quorum):
        raise InvalidInputError(
            f"event {event_id!r}: proof.quorum must be an integer"
        )
    if quorum < 1:
        raise InvalidInputError(
            f"event {event_id!r}: proof.quorum must be a positive integer"
        )

    return proof


def _validate_event(raw: dict, lineno: int) -> dict:
    event_id = raw.get("event_id", f"line {lineno}")

    missing = [name for name in EVENT_FIELDS if name not in raw]
    if missing:
        raise InvalidInputError(
            f"event {event_id!r}: missing field(s): {', '.join(missing)}"
        )

    if not isinstance(raw["event_id"], str) or not raw["event_id"]:
        raise InvalidInputError(
            f"line {lineno}: event_id must be a non-empty string"
        )
    if not isinstance(raw["chain_id"], str) or not raw["chain_id"]:
        raise InvalidInputError(
            f"event {raw['event_id']!r}: chain_id must be a non-empty string"
        )
    if not _is_int(raw["sequence"]):
        raise InvalidInputError(
            f"event {raw['event_id']!r}: sequence must be an integer"
        )

    for name in TIME_FIELDS:
        if not _is_int(raw[name]):
            raise InvalidInputError(
                f"event {raw['event_id']!r}: {name} must be an integer "
                "number of milliseconds"
            )

    proof = _validate_proof(raw["proof"], raw["event_id"])

    event = {name: raw[name] for name in EVENT_FIELDS}
    event["proof"] = proof
    return event


def _check_time_order(events: Iterable[dict]) -> None:
    """每个事件的链上时钟须满足 submit <= verify <= finalize。

    观察发生在链下，可能早于或晚于提交，故不强制它落入链上顺序；
    延迟直接报告有符号差值，归因时忽略负值。
    """
    for event in events:
        eid = event["event_id"]
        submit = event["proof_submitted_at"]
        verify = event["proof_verified_at"]
        finalize = event["finalized_at"]
        if submit > verify:
            raise InvalidInputError(
                f"event {eid!r}: proof_submitted_at is after proof_verified_at"
            )
        if verify > finalize:
            raise InvalidInputError(
                f"event {eid!r}: proof_verified_at is after finalized_at"
            )


def _read_physical_lines(source: PathLike) -> tuple[bytes, list[tuple[int, str, int]]]:
    """读取 UTF-8 JSONL 原始字节并按物理行切分。

    返回 ``(data, lines)``：``data`` 为整个文件的原始字节；``lines`` 每项为
    ``(物理行号, 解码文本, 行末字节偏移)``，偏移含行末 ``\\n``（末行无换行
    则止于文件尾），可直接用于切出「首字节到第 N 行行末」的前缀。仅空白行
    跳过（不计入物理行，沿用读取器旧行为），但它们的字节仍位于前缀覆盖范围
    内；CRLF 的 ``\\r`` 原样保留在行字节中。
    """
    try:
        with open(source, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise InvalidInputError(
            f"cannot read input {str(source)!r}: {exc}"
        ) from exc

    lines: list[tuple[int, str, int]] = []
    start = 0
    lineno = 0
    total = len(data)
    for pos, byte in enumerate(data):
        if byte != 0x0A:
            continue
        lineno += 1
        chunk = data[start : pos + 1]
        start = pos + 1
        try:
            text = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidInputError(
                f"line {lineno}: invalid UTF-8 byte sequence: {exc.reason}"
            ) from exc
        if text.strip():
            lines.append((lineno, text, pos + 1))
    if start < total:
        lineno += 1
        chunk = data[start:]
        try:
            text = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidInputError(
                f"line {lineno}: invalid UTF-8 byte sequence: {exc.reason}"
            ) from exc
        if text.strip():
            lines.append((lineno, text, total))
    return data, lines


def _load_input(
    source: PathLike,
) -> tuple[list[dict], bytes, list[tuple[int, str, int]]]:
    """读取并结构性校验输入，返回事件、原始字节与物理行记录（一一对应）。"""
    data, lines = _read_physical_lines(source)

    events: list[dict] = []
    seen_sequences: dict[str, set[int]] = {}
    seen_timestamps: dict[str, set[int]] = {
        name: set() for name in TIME_FIELDS
    }
    for lineno, text, _end in lines:
        raw = _parse_json_line(text.strip(), lineno)
        event = _validate_event(raw, lineno)

        chain_seen = seen_sequences.setdefault(event["chain_id"], set())
        if event["sequence"] in chain_seen:
            raise InvalidInputError(
                f"event {event['event_id']!r}: duplicate sequence "
                f"{event['sequence']} on chain {event['chain_id']!r}"
            )
        chain_seen.add(event["sequence"])

        # 每个时间字段在该列内跨事件唯一；不同列允许相同。
        for name in TIME_FIELDS:
            stamp = event[name]
            if stamp in seen_timestamps[name]:
                raise InvalidInputError(
                    f"event {event['event_id']!r}: {name} value "
                    f"{stamp} is not unique"
                )
            seen_timestamps[name].add(stamp)

        events.append(event)

    _check_time_order(events)
    return events, data, lines


def load_events(source: PathLike) -> list[dict]:
    """解析并结构性校验 UTF-8 JSONL 事件文件。

    一个输入可承载多个 ``chain_id``：sequence 仅在同一链内唯一，不同链复用
    同一 sequence 合法。事件按文件中的输入行序返回（各链事件可交错）。
    """
    events, _data, _lines = _load_input(source)
    return events


# --------------------------------------------------------------------------- #
# 轻客户端证明
# --------------------------------------------------------------------------- #
#
# 输入自描述，所有承诺只由事件携带字段重算，不做链上查询。十六进制比较忽略
# 大小写，并允许有无 0x 前缀。
#
# * 验证者集合离线表示为从 signatures 恢复出的去重签名者；
#   validator_set_hash 必须等于「排序后签名者列表」规范编码的 SHA-256，
#   且承诺绑定 chain_id 与 light_client_version，防止跨链/跨版本重放。
# * 可信根在给定版本下认证区块头：它必须等于规范对象
#   {"header_hash": ..., "light_client_version": ...} 的 SHA-256，
#   或直接等于区块头承诺本身（把根直接钉在该区块头上的形态）。
def _signers(signatures: list[str]) -> list[str]:
    return sorted({_normalize_hash(sig) for sig in signatures})


def _validator_set_hash(
    version: str, chain_id: str, signatures: list[str]
) -> str:
    document = {
        "chain_id": chain_id,
        "light_client_version": version,
        "signers": _signers(signatures),
    }
    return _canonical_hash(document)


def _trusted_roots(version: str, header_hash: str) -> set[str]:
    header = _normalize_hash(header_hash)
    versioned = _canonical_hash(
        {"header_hash": header, "light_client_version": version}
    )
    return {header, versioned}


def verify_proof(event: dict) -> None:
    """应用轻客户端规则；规则不符抛 ProofVerificationError。"""
    proof = event["proof"]
    eid = event["event_id"]
    version = proof["light_client_version"]
    signatures: list[str] = proof["signatures"]
    quorum = proof["quorum"]

    # 一个验证者至多贡献一个签名；重复签名不得把计数抬过 quorum。
    distinct_signatures = set(signatures)
    if len(distinct_signatures) < quorum:
        raise ProofVerificationError(
            f"event {eid!r}: {len(distinct_signatures)} distinct signatures "
            f"do not reach quorum {quorum}"
        )

    declared = _normalize_hash(proof["validator_set_hash"])
    computed = _validator_set_hash(version, event["chain_id"], signatures)
    if declared != computed:
        raise ProofVerificationError(
            f"event {eid!r}: validator_set_hash does not match the signing set"
        )

    trusted_root = _normalize_hash(proof["trusted_root"])
    if trusted_root not in _trusted_roots(version, proof["header_hash"]):
        raise ProofVerificationError(
            f"event {eid!r}: trusted_root does not verify header_hash for "
            f"light_client_version {version}"
        )


# --------------------------------------------------------------------------- #
# 延迟与归因
# --------------------------------------------------------------------------- #
def _attribution(source_ms: int, relay_ms: int, destination_ms: int) -> str:
    """最大非负阶段；任何并列（含全等）归 relay。"""
    candidates = [
        (_SOURCE, source_ms),
        (_RELAY, relay_ms),
        (_DESTINATION, destination_ms),
    ]
    non_negative = [(name, value) for name, value in candidates if value >= 0]
    best_value = max(value for _, value in non_negative)
    winners = [name for name, value in non_negative if value == best_value]
    if len(winners) == 1:
        return winners[0]
    return _RELAY


def _latency_fields(event: dict) -> dict:
    """三段延迟与归因；成功行与隔离模式的失败行口径完全一致。"""
    proof_latency = event["proof_verified_at"] - event["proof_submitted_at"]
    relay_latency = event["proof_verified_at"] - event["observed_at"]
    destination_latency = event["finalized_at"] - event["proof_verified_at"]
    return {
        "proof_latency_ms": proof_latency,
        "relay_latency_ms": relay_latency,
        "destination_latency_ms": destination_latency,
        "attribution": _attribution(
            proof_latency, relay_latency, destination_latency
        ),
    }


def build_report(event: dict) -> dict:
    return {
        "event_id": event["event_id"],
        "chain_id": event["chain_id"],
        "sequence": event["sequence"],
        "proof_status": "verified",
        **_latency_fields(event),
        "finalized_at": event["finalized_at"],
    }


def build_failed_report(event: dict, exc: ProofVerificationError) -> dict:
    """隔离模式下证明失败的事件行。

    数值字段（三段延迟、归因、finalized_at）与成功行同一口径；证明结果以
    ``proof_status="failed"`` 加 ``error_type``/``error_message`` 表达，其中
    错误文本即原 ``ProofVerificationError`` 的异常文本。
    """
    return {
        "event_id": event["event_id"],
        "chain_id": event["chain_id"],
        "sequence": event["sequence"],
        "proof_status": "failed",
        "error_type": type(exc).__name__,
        "error_message": str(exc),
        **_latency_fields(event),
        "finalized_at": event["finalized_at"],
    }


# --------------------------------------------------------------------------- #
# 检查点
# --------------------------------------------------------------------------- #
#
# v3 检查点为::
#
#     {"schema_version": 3,
#      "last_sequence_by_chain": {"chain-a": 3, "chain-b": 7},
#      "processed_lines": 12,
#      "input_prefix_sha256": "<64 位小写十六进制>"}
#
# processed_lines 是已读取且结构有效的 JSONL 物理行数；input_prefix_sha256
# 是首字节到第 processed_lines 行行末（含行末换行；末行无换行则到文件尾，
# 不补换行）的原始 UTF-8 字节 SHA-256。
#
# 结构问题（无法解析、缺键、null、数组、未知字段、schema_version 取值非法、
# last_sequence_by_chain 不是对象、processed_lines 不是整数、摘要不是 64 位
# 小写十六进制字符串）一律 InvalidInputError；结构成立但取值非法（空链标识、
# 负游标、摘要与前缀不一致、processed_lines 非正或超过物理行数、某链游标与
# 前缀内最大 sequence 不一致、游标超过该链输入最大 sequence）为
# CheckpointError。
#
# v2 {"schema_version": 2, "last_sequence_by_chain": {...}} 与旧版
# {"last_sequence": N} 仍按原规则读取（无摘要，不做前缀校验），仅当本次确
# 有新事件完成（严格模式全部成功；隔离模式全部有成功或失败结果）后才升级为
# v3；无新事件时空操作，原检查点文件原样保留。
@dataclass
class _Checkpoint:
    """解析后的检查点。

    * legacy 为 True：旧版 last_sequence（值在 legacy_value，chains 为空）；
    * version 2：v2 按链游标，chains 为游标映射，processed_lines/digest 为空；
    * version 3：另有 processed_lines 与 input_prefix_sha256。
    """

    chains: dict[str, int]
    legacy: bool = False
    legacy_value: Optional[int] = None
    version: int = SCHEMA_VERSION
    processed_lines: Optional[int] = None
    digest: Optional[str] = None


def _checkpoint_invalid(message: str) -> InvalidInputError:
    return InvalidInputError(f"checkpoint: {message}")


def _parse_chain_mapping(mapping: Any) -> dict[str, int]:
    """结构 + 取值校验 last_sequence_by_chain（v2/v3 共用口径）。

    链标识为空字符串、游标为负数/浮点/字符串/布尔/对象等抛 CheckpointError；
    null/数组等“结构性”非法值抛 InvalidInputError。
    """
    # null 或数组（而非对象）属结构非法。
    if not isinstance(mapping, dict):
        raise _checkpoint_invalid("last_sequence_by_chain must be an object")

    chains: dict[str, int] = {}
    for chain, value in mapping.items():
        if not isinstance(chain, str) or not chain:
            # JSON 对象键恒为字符串，但空字符串链标识不合法。
            raise CheckpointError(
                "checkpoint chain identifier must be a non-empty string"
            )
        # null/数组在检查点中一律属结构非法（InvalidInputError）。
        if value is None or isinstance(value, list):
            kind = "null" if value is None else "an array"
            raise _checkpoint_invalid(
                f"cursor for chain {chain!r} must not be {kind}"
            )
        if not _is_int(value) or value < 0:
            # 负数、浮点、字符串、布尔、对象等“不是非负整数”的取值属语义
            # 非法（CheckpointError）。
            raise CheckpointError(
                f"checkpoint cursor for chain {chain!r} must be a non-negative "
                "integer"
            )
        chains[chain] = value
    return chains


def _parse_versioned_checkpoint(data: dict) -> _Checkpoint:
    """解析 schema_version 2/3 检查点；结构问题一律 InvalidInputError。"""
    version = data["schema_version"]
    # null、数组或任何非整数（含错误版本号）都属结构非法。
    if not _is_int(version):
        raise _checkpoint_invalid("schema_version must be an integer")
    if version not in (2, SCHEMA_VERSION):
        raise _checkpoint_invalid(
            f"unsupported schema_version {version}; expected {SCHEMA_VERSION}"
        )

    if "last_sequence_by_chain" not in data:
        raise _checkpoint_invalid("missing last_sequence_by_chain")

    allowed = {"schema_version", "last_sequence_by_chain"}
    if version == SCHEMA_VERSION:
        allowed |= {"processed_lines", "input_prefix_sha256"}
    unknown = set(data) - allowed
    if unknown:
        raise _checkpoint_invalid(
            f"unknown field(s): {', '.join(sorted(unknown))}"
        )

    chains = _parse_chain_mapping(data["last_sequence_by_chain"])

    if version == 2:
        return _Checkpoint(chains=chains, legacy=False, version=2)

    # ---- v3 专有字段：结构性校验在此完成，语义校验留给获知输入后进行。 ----
    if "processed_lines" not in data:
        raise _checkpoint_invalid("missing processed_lines")
    if "input_prefix_sha256" not in data:
        raise _checkpoint_invalid("missing input_prefix_sha256")

    processed_lines = data["processed_lines"]
    # null、数组、布尔、浮点、字符串都属结构非法。
    if not _is_int(processed_lines):
        raise _checkpoint_invalid("processed_lines must be an integer")

    digest = data["input_prefix_sha256"]
    # null、数组等非字符串，或不是恰好 64 位小写十六进制，都属结构非法。
    if not isinstance(digest, str) or _SHA256_HEX_RE.match(digest) is None:
        raise _checkpoint_invalid(
            "input_prefix_sha256 must be a 64-character lowercase hex string"
        )

    return _Checkpoint(
        chains=chains,
        legacy=False,
        version=3,
        processed_lines=processed_lines,
        digest=digest,
    )


def load_checkpoint(path: PathLike) -> Optional[_Checkpoint]:
    """读取检查点；文件不存在返回 None（首次处理）。

    返回 v3（含 processed_lines/digest）、v2（仅按链游标）或包装旧版
    last_sequence 的遗留检查点。
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InvalidInputError(
            f"cannot read checkpoint {str(path)!r}: {exc}"
        ) from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _checkpoint_invalid(f"is not valid JSON: {exc.msg}") from exc

    if not isinstance(data, dict):
        raise _checkpoint_invalid("must be a JSON object")

    # 旧版检查点：只允许 last_sequence 一个字段。
    if "schema_version" not in data:
        unknown = set(data) - {"last_sequence"}
        if unknown or "last_sequence" not in data:
            raise _checkpoint_invalid(
                "must contain schema_version and last_sequence_by_chain"
            )
        last_sequence = data["last_sequence"]
        if not _is_int(last_sequence):
            # 布尔、浮点、字符串、null 都算“非整数”。
            raise CheckpointError("checkpoint last_sequence must be an integer")
        if last_sequence < 0:
            raise CheckpointError("checkpoint last_sequence must not be negative")
        return _Checkpoint(
            chains={}, legacy=True, legacy_value=last_sequence, version=1
        )

    return _parse_versioned_checkpoint(data)


def _max_sequence_by_chain(events: list[dict]) -> dict[str, int]:
    max_by_chain: dict[str, int] = {}
    for event in events:
        chain = event["chain_id"]
        sequence = event["sequence"]
        if chain not in max_by_chain or sequence > max_by_chain[chain]:
            max_by_chain[chain] = sequence
    return max_by_chain


def _verify_v3_prefix(
    checkpoint: _Checkpoint,
    events: list[dict],
    data: bytes,
    lines: list[tuple[int, str, int]],
) -> None:
    """v3 续传完整性校验：processed_lines、摘要、游标三者必须互相吻合。

    任何不一致都意味着历史事件可能在两次运行之间被改写，抛 CheckpointError
    且绝不发布报告或推进检查点。
    """
    processed_lines = checkpoint.processed_lines
    assert processed_lines is not None and checkpoint.digest is not None

    total_lines = len(lines)
    if processed_lines < 1 or processed_lines > total_lines:
        raise CheckpointError(
            f"checkpoint processed_lines {processed_lines} is not a positive "
            f"integer within the input line count {total_lines}"
        )

    prefix_end = lines[processed_lines - 1][2]
    prefix = data[:prefix_end]
    actual_digest = _sha256_hex(prefix)
    if actual_digest != checkpoint.digest:
        raise CheckpointError(
            "input prefix digest mismatch: previously processed JSONL lines "
            "have changed since the checkpoint was written"
        )

    # 第 processed_lines 行之后只允许追加完整 JSONL 行；结构校验已在加载阶段
    # 对全部物理行完成（包括追加段），走到这里说明尾部每行都是完整合法行。
    # 若文件在最后一个换行后还残留非空白字节，加载阶段已按一行处理，故此处
    # 无需额外判断。

    # 各链游标必须等于前缀内该链已处理事件的最大 sequence：游标偏小会重放
    # （报告去重可兜底但游标语义已被破坏），偏大意味着游标越过了前缀实际
    # 覆盖的事件；前缀出现的链在游标映射中缺失同样属于不一致（自己写出的
    # v3 恒含全部前缀链）。检查点记录但前缀中没有任何事件的链不参与此比对
    # （其游标可能指向另一份输入中的链，v2 起即允许保留），改由全输入上界
    # 检查约束。
    prefix_events = events[:processed_lines]
    prefix_max = _max_sequence_by_chain(prefix_events)
    for chain, expected in prefix_max.items():
        if chain not in checkpoint.chains:
            raise CheckpointError(
                f"checkpoint carries no cursor for chain {chain!r} present in "
                "the verified input prefix"
            )
        if checkpoint.chains[chain] != expected:
            raise CheckpointError(
                f"checkpoint cursor {checkpoint.chains[chain]} for chain "
                f"{chain!r} does not match sequence {expected} reached within "
                "the verified input prefix"
            )

    # 前缀未出现、但追加段或全输入中出现的链沿用 v2 上界规则：游标超过该
    # 链全输入最大 sequence 时无法解释，抛 CheckpointError。
    max_by_chain = _max_sequence_by_chain(events)
    for chain, cursor in checkpoint.chains.items():
        if chain in max_by_chain and cursor > max_by_chain[chain]:
            raise CheckpointError(
                f"checkpoint cursor {cursor} for chain {chain!r} exceeds input "
                f"maximum sequence {max_by_chain[chain]}"
            )


def _resolve_checkpoint(
    checkpoint: Optional[_Checkpoint],
    events: list[dict],
    data: Optional[bytes] = None,
    lines: Optional[list[tuple[int, str, int]]] = None,
) -> dict[str, int]:
    """把解析结果落实为按链游标，并做跨输入一致性检查。

    * 无检查点（首次处理）：空映射，各链均从第一条开始。
    * v3：先做前缀完整性与游标一致性校验，再返回游标映射。
    * v2：直接采用；某链游标超过该链输入最大 sequence 抛 CheckpointError。
    * 旧版：仅当输入恰含一个 chain_id 时可归属；多链输入抛 CheckpointError。
      缺失链从第一条开始（游标取 -1 语义由调用方以“不在映射中”表达）。
    """
    if checkpoint is None:
        return {}

    if checkpoint.version == 3:
        assert data is not None and lines is not None
        _verify_v3_prefix(checkpoint, events, data, lines)
        return dict(checkpoint.chains)

    chains = checkpoint.chains

    if checkpoint.legacy:
        chain_ids = {event["chain_id"] for event in events}
        if len(chain_ids) > 1:
            raise CheckpointError(
                "legacy last_sequence checkpoint cannot resume a multi-chain "
                "input: chain ownership is ambiguous"
            )
        if len(chain_ids) == 1:
            # 旧值已在加载时校验为非负整数；归属到唯一链。
            chains = {next(iter(chain_ids)): checkpoint.legacy_value}
        # 空输入（零链）无可归属，也无事件可处理：留作成功空操作。

    max_by_chain = _max_sequence_by_chain(events)
    for chain, cursor in chains.items():
        if chain in max_by_chain and cursor > max_by_chain[chain]:
            raise CheckpointError(
                f"checkpoint cursor {cursor} for chain {chain!r} exceeds input "
                f"maximum sequence {max_by_chain[chain]}"
            )
    return chains


# --------------------------------------------------------------------------- #
# 原子输出
# --------------------------------------------------------------------------- #
def _atomic_write(path: PathLike, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".relay-watch-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _render_reports(reports: list[dict]) -> str:
    return "".join(
        json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n"
        for report in reports
    )


# --------------------------------------------------------------------------- #
# 序列连续性盘点
# --------------------------------------------------------------------------- #
def _build_continuity(events: list[dict]) -> list[dict]:
    """按链汇总 sequence 连续性，覆盖整个当前输入（与游标无关）。

    每链一行，按该链在输入中的首次出现排序；sequence 可从任意非负值开始，
    最小值之前不算缺口。missing_ranges 升序列出相邻已出现 sequence 之间的
    空缺，每项为闭区间 {"start": s, "end": e}（两端皆缺失值）；单值或连续
    时 ranges 为空、计数为 0。缺失范围只由已出现的整数 sequence 推导。
    """
    sequences_by_chain: dict[str, list[int]] = {}
    for event in events:
        sequences_by_chain.setdefault(event["chain_id"], []).append(
            event["sequence"]
        )

    rows: list[dict] = []
    for chain, sequences in sequences_by_chain.items():
        ordered = sorted(sequences)
        missing_ranges: list[dict] = []
        missing_count = 0
        for low, high in zip(ordered, ordered[1:]):
            if high > low + 1:
                missing_ranges.append({"start": low + 1, "end": high - 1})
                missing_count += high - low - 1
        rows.append(
            {
                "chain_id": chain,
                "event_count": len(sequences),
                "min_sequence": ordered[0],
                "max_sequence": ordered[-1],
                "missing_ranges": missing_ranges,
                "missing_count": missing_count,
            }
        )
    return rows


def _read_report_rows(path: PathLike) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise InvalidInputError(
            f"cannot read report {str(path)!r}: {exc}"
        ) from exc

    rows: list[dict] = []
    for lineno, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InvalidInputError(
                f"existing report {str(path)!r} line {lineno}: malformed JSON"
            ) from exc
        if not isinstance(row, dict):
            raise InvalidInputError(
                f"existing report {str(path)!r} line {lineno}: not a JSON "
                "object"
            )
        rows.append(row)
    return rows


def _report_identity(row: dict) -> tuple[Any, Any]:
    """报告行的去重身份：(chain_id, sequence)。"""
    return (row.get("chain_id"), row.get("sequence"))


def _publish_resumed(path: PathLike, reports: list[dict]) -> None:
    """向累积报告追加新行，且绝不重复输出。

    按 (chain_id, sequence) 去重使发布幂等：即便上一次已写报告却在推进检查
    点前崩溃，重跑会选中同样的事件，但不会二次写出。不同链复用同一 sequence
    不会相互覆盖。
    """
    existing = _read_report_rows(path)
    known = {_report_identity(row) for row in existing}
    fresh = [row for row in reports if _report_identity(row) not in known]
    if not fresh and existing:
        return
    _atomic_write(path, _render_reports(existing + fresh))


# --------------------------------------------------------------------------- #
# 延迟越界清单
# --------------------------------------------------------------------------- #
def load_latency_thresholds(path: PathLike) -> dict[str, int]:
    """读取并校验延迟阈值 JSON 对象。

    文件必须是 UTF-8 JSON 对象，且恰好只含 proof_latency_ms、
    relay_latency_ms、destination_latency_ms 三个字段，每个值为非负整数
    毫秒（布尔、浮点、字符串、null、负数等一律拒绝）。无法解析或不合规都抛
    InvalidInputError；文件无法打开等错误原样作为 OSError 子类传播，文件
    存在但含非法 UTF-8 字节按不合规输入抛 InvalidInputError，由调用方沿用
    统一的文件错误处理。
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except UnicodeDecodeError as exc:
        raise InvalidInputError(
            f"latency thresholds {str(path)!r}: invalid UTF-8 byte sequence: "
            f"{exc.reason}"
        ) from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"latency thresholds {str(path)!r}: invalid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise InvalidInputError(
            f"latency thresholds {str(path)!r}: must be a JSON object"
        )

    missing = [name for name in LATENCY_THRESHOLD_FIELDS if name not in data]
    if missing:
        raise InvalidInputError(
            f"latency thresholds {str(path)!r}: missing field(s): "
            f"{', '.join(missing)}"
        )
    unknown = set(data) - set(LATENCY_THRESHOLD_FIELDS)
    if unknown:
        raise InvalidInputError(
            f"latency thresholds {str(path)!r}: unknown field(s): "
            f"{', '.join(sorted(unknown))}"
        )

    thresholds: dict[str, int] = {}
    for name in LATENCY_THRESHOLD_FIELDS:
        value = data[name]
        if not _is_int(value) or value < 0:
            raise InvalidInputError(
                f"latency thresholds {str(path)!r}: {name} must be a "
                "non-negative integer number of milliseconds"
            )
        thresholds[name] = value
    return thresholds


def load_chain_slo_thresholds(path: PathLike) -> dict[str, int]:
    """读取并校验链级 SLO 阈值 JSON 对象。

    文件必须是 UTF-8 JSON 对象，且恰好只含
    proof_failure_rate_permille、missing_sequence_rate_permille、
    proof_latency_ms_p95、relay_latency_ms_p95、
    destination_latency_ms_p95 五个字段：前两个为 0 到 1000（含端点）的
    整数千分率上限，后三个为非负整数毫秒（布尔、浮点、字符串、null、越界
    整数等一律拒绝）。无法解析或不合规都抛 InvalidInputError；文件无法
    打开等错误原样作为 OSError 子类传播，文件存在但含非法 UTF-8 字节按
    不合规输入抛 InvalidInputError。
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except UnicodeDecodeError as exc:
        raise InvalidInputError(
            f"chain SLO thresholds {str(path)!r}: invalid UTF-8 byte "
            f"sequence: {exc.reason}"
        ) from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"chain SLO thresholds {str(path)!r}: invalid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise InvalidInputError(
            f"chain SLO thresholds {str(path)!r}: must be a JSON object"
        )

    missing = [name for name in CHAIN_SLO_THRESHOLD_FIELDS if name not in data]
    if missing:
        raise InvalidInputError(
            f"chain SLO thresholds {str(path)!r}: missing field(s): "
            f"{', '.join(missing)}"
        )
    unknown = set(data) - set(CHAIN_SLO_THRESHOLD_FIELDS)
    if unknown:
        raise InvalidInputError(
            f"chain SLO thresholds {str(path)!r}: unknown field(s): "
            f"{', '.join(sorted(unknown))}"
        )

    thresholds: dict[str, int] = {}
    for name in CHAIN_SLO_RATE_FIELDS:
        value = data[name]
        if not _is_int(value) or not 0 <= value <= 1000:
            raise InvalidInputError(
                f"chain SLO thresholds {str(path)!r}: {name} must be an "
                "integer between 0 and 1000 inclusive"
            )
        thresholds[name] = value
    for name in CHAIN_SLO_LATENCY_P95_FIELDS:
        value = data[name]
        if not _is_int(value) or value < 0:
            raise InvalidInputError(
                f"chain SLO thresholds {str(path)!r}: {name} must be a "
                "non-negative integer number of milliseconds"
            )
        thresholds[name] = value
    return thresholds


def _build_latency_breaches(
    reports: list[dict], thresholds: dict[str, int]
) -> list[dict]:
    """按报告行序逐行挑出严格越界阶段，生成越界清单行。

    仅本次运行新产出的报告行参与（续传已发布的历史行不再重查，故无新事件时
    结果为空）；三个延迟字段只有「严格大于」同名阈值才算越界，等于不越界。
    breached_stages 按 proof_latency_ms、relay_latency_ms、
    destination_latency_ms 的固定顺序列出；失败报告行同样参与，
    proof_status 原样带出。
    """
    breaches: list[dict] = []
    for report in reports:
        breached = [
            name
            for name in LATENCY_THRESHOLD_FIELDS
            if report[name] > thresholds[name]
        ]
        if not breached:
            continue
        breaches.append(
            {
                "event_id": report["event_id"],
                "chain_id": report["chain_id"],
                "sequence": report["sequence"],
                "proof_status": report["proof_status"],
                "breached_stages": breached,
                "attribution": report["attribution"],
                "finalized_at": report["finalized_at"],
            }
        )
    return breaches


# --------------------------------------------------------------------------- #
# 链级延迟画像
# --------------------------------------------------------------------------- #
def _nearest_rank(sorted_values: list[int], quantile: float) -> int:
    """最近秩分位：升序数据按 ceil(quantile*n) 取 1 基秩（至少为 1）。"""
    rank = max(1, math.ceil(quantile * len(sorted_values)))
    return sorted_values[rank - 1]


def _latency_stats(values: list[int]) -> dict:
    """单个延迟阶段的 min/p50/p95/max；数据已升序，n >= 1。"""
    return {
        "min": values[0],
        "p50": _nearest_rank(values, 0.50),
        "p95": _nearest_rank(values, 0.95),
        "max": values[-1],
    }


def _build_latency_profile(events: list[dict]) -> list[dict]:
    """按链汇总三段延迟分布与归因计数，覆盖整个当前输入（与游标无关）。

    每链一行，按该链在输入中的首次出现排序；每个结构合法事件贡献三个整数
    毫秒延迟（成功行与隔离模式失败行口径完全一致）及其归因。三个统计对象仅
    含 min、p50、p95、max，p50/p95 用最近秩（秩为 max(1,ceil(0.50*n)) 与
    max(1,ceil(0.95*n))）；单事件四项相同。attribution_counts 仅含 source、
    relay、destination，未出现的归因写 0。
    """
    per_chain: dict[str, dict[str, list[int]]] = {}
    attribution_counts: dict[str, dict[str, int]] = {}
    for event in events:
        chain = event["chain_id"]
        latency = _latency_fields(event)
        if chain not in per_chain:
            per_chain[chain] = {name: [] for name in LATENCY_THRESHOLD_FIELDS}
            attribution_counts[chain] = {name: 0 for name in ATTRIBUTION_FIELDS}
        for name in LATENCY_THRESHOLD_FIELDS:
            per_chain[chain][name].append(latency[name])
        attribution_counts[chain][latency["attribution"]] += 1

    rows: list[dict] = []
    for chain, stages in per_chain.items():
        rows.append(
            {
                "chain_id": chain,
                "event_count": len(stages[LATENCY_THRESHOLD_FIELDS[0]]),
                "proof_latency_ms": _latency_stats(sorted(stages["proof_latency_ms"])),
                "relay_latency_ms": _latency_stats(sorted(stages["relay_latency_ms"])),
                "destination_latency_ms": _latency_stats(
                    sorted(stages["destination_latency_ms"])
                ),
                "attribution_counts": dict(attribution_counts[chain]),
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# 链级 SLO 汇总
# --------------------------------------------------------------------------- #
def _ceil_permille(numerator: int, denominator: int) -> int:
    """ceil(1000 * numerator / denominator)；分母恒为正的整数精确实现。"""
    return (1000 * numerator + denominator - 1) // denominator


def _build_chain_slo(
    events: list[dict],
    failed_identities: set[tuple[str, int]],
    thresholds: dict[str, int],
) -> list[dict]:
    """按链汇总两比率与三段 p95 并对照阈值列违规，覆盖整个当前输入。

    每链一行，按该链在输入中的首次出现排序。失败计数为
    ``failed_identities``（(chain_id, sequence) 集合）命中的事件数——严格
    模式证明失败在任何发布前抛出，故严格模式下该集合恒空、失败率恒为 0；
    缺失计数沿用连续性盘点口径（相邻已出现 sequence 间空缺总数）。两个比率
    为 ceil(1000 * 失败数 / 事件数) 与
    ceil(1000 * missing_count / (event_count + missing_count))。三个 p95 取
    链级延迟画像同一口径的最近秩，失败行同样参与。violations 按两个比率、
    三个 p95 的固定顺序仅列「严格大于」阈值的项（键为阈值名去掉 ``_p95``
    后缀的形式），全部达标时为 []。
    """
    missing_by_chain = {
        row["chain_id"]: row["missing_count"]
        for row in _build_continuity(events)
    }

    per_chain: dict[str, dict[str, list[int]]] = {}
    event_counts: dict[str, int] = {}
    failure_counts: dict[str, int] = {}
    for event in events:
        chain = event["chain_id"]
        latency = _latency_fields(event)
        if chain not in per_chain:
            per_chain[chain] = {name: [] for name in LATENCY_THRESHOLD_FIELDS}
            event_counts[chain] = 0
            failure_counts[chain] = 0
        event_counts[chain] += 1
        for name in LATENCY_THRESHOLD_FIELDS:
            per_chain[chain][name].append(latency[name])
        if (chain, event["sequence"]) in failed_identities:
            failure_counts[chain] += 1

    rows: list[dict] = []
    for chain, stages in per_chain.items():
        event_count = event_counts[chain]
        failure_count = failure_counts[chain]
        missing_count = missing_by_chain[chain]
        failure_rate = _ceil_permille(failure_count, event_count)
        missing_denominator = event_count + missing_count
        missing_rate = _ceil_permille(missing_count, missing_denominator)
        latency_p95 = {
            name: _nearest_rank(sorted(stages[name]), 0.95)
            for name in LATENCY_THRESHOLD_FIELDS
        }

        # (输出键, 实际值, 阈值键)；先两比率再三 p95，顺序即 violations
        # 中各违规项的固定列出顺序。
        metrics = (
            (
                "proof_failure_rate_permille",
                failure_rate,
                "proof_failure_rate_permille",
            ),
            (
                "missing_sequence_rate_permille",
                missing_rate,
                "missing_sequence_rate_permille",
            ),
            (
                "proof_latency_ms",
                latency_p95["proof_latency_ms"],
                "proof_latency_ms_p95",
            ),
            (
                "relay_latency_ms",
                latency_p95["relay_latency_ms"],
                "relay_latency_ms_p95",
            ),
            (
                "destination_latency_ms",
                latency_p95["destination_latency_ms"],
                "destination_latency_ms_p95",
            ),
        )
        violations = [
            name
            for name, value, threshold_name in metrics
            if value > thresholds[threshold_name]
        ]
        rows.append(
            {
                "chain_id": chain,
                "event_count": event_count,
                "proof_failure_rate_permille": failure_rate,
                "missing_sequence_rate_permille": missing_rate,
                # latency_p95 仅含 proof/relay/destination_latency_ms 三个
                # 整数键（阈值名去 _p95 后缀），顺序与画像对象一致。
                "latency_p95_ms": latency_p95,
                "violations": violations,
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# 公共管线
# --------------------------------------------------------------------------- #
def _render_checkpoint(
    cursors: dict[str, int], processed_lines: int, digest: str
) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "last_sequence_by_chain": dict(sorted(cursors.items())),
        "processed_lines": processed_lines,
        "input_prefix_sha256": digest,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n"


def watch(
    input_path: PathLike,
    checkpoint: Optional[PathLike] = None,
    output_path: Optional[PathLike] = None,
    tolerate_failures: bool = False,
    continuity_output: Optional[PathLike] = None,
    latency_thresholds: Optional[PathLike] = None,
    latency_breach_output: Optional[PathLike] = None,
    latency_profile_output: Optional[PathLike] = None,
    chain_slo_thresholds: Optional[PathLike] = None,
    chain_health_output: Optional[PathLike] = None,
) -> list[dict]:
    """运行监控并返回逐事件报告行（按输入行序）。

    一个输入可承载多个 chain_id；选择与续传身份为 (chain_id, sequence)。
    给定 output_path 时原子写 JSONL 报告；仅当所有被选中事件都有确定结果
    后，才原子推进 checkpoint（若给出），且各链只推进到本次已处理的最大
    sequence。

    v3 检查点同时提交 processed_lines（末条被选事件所在的物理行号）与首字节
    到该行行末原始字节的 input_prefix_sha256。续传时先逐字节校验此前处理的
    前缀及其游标一致性，任一不成立都抛 CheckpointError 且不写报告、不推进
    检查点；旧版 last_sequence 与 v2 检查点仍可读，但只在确有新事件完成后才
    升级 v3（升级时才首次计算摘要，绝不伪造），无新事件时空操作、原文件保留。

    严格模式（``tolerate_failures=False``，默认，兼容旧行为）下，结构合法但
    证明失败的首个事件立即抛 :class:`ProofVerificationError`，不写报告、不推进
    检查点。隔离模式（``tolerate_failures=True``）下，每个结构合法事件独立
    处理：成功者为 ``proof_status="verified"`` 行，失败者为
    ``proof_status="failed"`` 行（携带 error_type/error_message）；成功与失败
    都算“已处理”，同样推进检查点，同链后续事件不受先前失败影响。结构性输入
    错误与检查点错误在两种模式下都直接抛出，不写报告、不推进检查点。

    给定 ``continuity_output`` 时，在报告与检查点都安全发布后，额外原子写出
    一份序列连续性盘点（UTF-8 JSONL，每链一行、按首次出现排序，字段为
    chain_id、event_count、min_sequence、max_sequence、missing_ranges、
    missing_count；详见 :func:`_build_continuity`）。盘点覆盖整个当前输入而
    非游标之后，因此续传、追加与重复执行结果一致；隔离模式下证明失败的事件
    仍占有其 sequence。省略该参数时行为与旧版完全一致；任何领域错误抛出时
    都不写盘点文件。

    同时（且必须成对）给出 ``latency_thresholds`` 与
    ``latency_breach_output`` 时，在报告、检查点、连续性盘点都安全发布后，
    最后再原子写出一份延迟越界清单（UTF-8 JSONL；详见
    :func:`_build_latency_breaches`）。阈值文件为仅含 proof_latency_ms、
    relay_latency_ms、destination_latency_ms 三个非负整数毫秒字段的 JSON
    对象，不合规抛 InvalidInputError；两参数缺一对（API）同样抛
    InvalidInputError。清单只查本次运行新产出的报告行（严格行序），三个延迟
    字段仅严格大于同名阈值才越界，隔离模式的失败行同样参与
    （proof_status="failed"），严格模式证明失败仍在任何发布前抛
    ProofVerificationError。无越界或无新事件写空文件；领域错误时不写清单，
    阈值文件本身的读取错误原样作为 OSError 子类传播。省略这对参数时行为与
    旧版完全一致。

    给定 ``latency_profile_output`` 时，在报告、检查点、连续性盘点（若有）
    都安全发布后、延迟越界清单（若有）之前，原子写出一份链级延迟画像
    （UTF-8 JSONL，每链一行、按首次出现排序；详见
    :func:`_build_latency_profile`）。画像覆盖当前输入全部结构合法事件而非
    游标后的新行，故续传、追加与重复执行结果一致，空输入写空文件；隔离模式
    下 proof_status="failed" 的事件同样有确定延迟与归因，与 verified 一起
    统计。严格模式证明失败仍在任何发布前抛 ProofVerificationError，不写
    画像；任何领域错误都不写画像。省略该参数时行为与旧版完全一致。

    同时（且必须成对）给出 ``chain_slo_thresholds`` 与
    ``chain_health_output`` 时，在报告、检查点、连续性盘点、延迟画像、延迟
    越界清单全部安全发布后，最后再原子写出一份链级 SLO 汇总（UTF-8 JSONL，
    按 chain_id 首现顺序每链一行；详见 :func:`_build_chain_slo`）。阈值
    文件仅含 proof_failure_rate_permille、missing_sequence_rate_permille
    （0 到 1000 的整数）与 proof_latency_ms_p95、relay_latency_ms_p95、
    destination_latency_ms_p95（非负整数毫秒），字段或值不合规抛
    InvalidInputError；两参数缺一对（API）同样抛 InvalidInputError。汇总
    覆盖当前输入全部结构合法事件（与游标无关）：隔离模式下逐条重验全部事件
    的证明以统计链级失败数（续传重跑结果一致），严格模式首个证明失败仍在
    任何发布前抛 ProofVerificationError，不写汇总；两比率为失败数/事件数
    与 missing_count/(event_count+missing_count) 乘 1000 向上取整，三个
    p95 取链级延迟画像的 p95 最近秩（失败行同口径参与），violations 按两
    比率、三 p95 的顺序仅列严格大于阈值的项，达标为 []。空输入写空文件；
    领域错误时不写汇总，阈值文件本身的读取错误原样作为 OSError 子类传播。
    省略这对参数时行为与旧版完全一致。
    """
    if (latency_thresholds is None) != (latency_breach_output is None):
        raise InvalidInputError(
            "latency_thresholds and latency_breach_output must be given "
            "together"
        )
    if (chain_slo_thresholds is None) != (chain_health_output is None):
        raise InvalidInputError(
            "chain_slo_thresholds and chain_health_output must be given "
            "together"
        )

    # 阈值是额外输入：在任何发布之前先加载并校验，使不合规阈值与结构非法
    # 输入同口径处理——不写报告、不推进检查点、不写任何附加清单。文件本身
    # 打不开等错误原样作为 OSError 子类传播。
    thresholds: Optional[dict[str, int]] = None
    if latency_thresholds is not None:
        thresholds = load_latency_thresholds(latency_thresholds)

    # SLO 阈值同属额外输入，同样在任何发布之前加载校验；文件本身打不开等
    # 错误原样作为 OSError 子类传播。
    slo_thresholds: Optional[dict[str, int]] = None
    if chain_slo_thresholds is not None:
        slo_thresholds = load_chain_slo_thresholds(chain_slo_thresholds)

    events, data, lines = _load_input(input_path)

    parsed_checkpoint: Optional[_Checkpoint] = None
    resuming = False
    if checkpoint is not None:
        # 仅当检查点文件确实存在时才续传；文件缺失视为全新开始，需要完整
        # （重新）发布输入，而不是并入可能已陈旧的报告。
        resuming = os.path.exists(checkpoint)
        parsed_checkpoint = load_checkpoint(checkpoint)

    # 各链游标；v3 会在此完成前缀摘要与游标一致性校验；映射中缺失的链（含
    # 检查点未记录的新链）从第一条开始。
    cursors = _resolve_checkpoint(parsed_checkpoint, events, data, lines)
    selected = [
        event
        for event in events
        if event["sequence"] > cursors.get(event["chain_id"], -1)
    ]

    reports: list[dict] = []
    for event in selected:
        try:
            verify_proof(event)
        except ProofVerificationError as exc:
            if not tolerate_failures:
                raise
            reports.append(build_failed_report(event, exc))
        else:
            reports.append(build_report(event))

    # 链级 SLO 汇总覆盖整个当前输入（含游标前的历史事件），失败率需要全部
    # 事件的证明结果而非仅本次新行：隔离模式下逐条重验，收集
    # (chain_id, sequence) 失败身份（纯函数重放，续传与重复执行结果一致）；
    # 严格模式下任一事件（含游标覆盖的历史事件）证明失败都在任何发布前抛
    # ProofVerificationError，不写汇总。仅在启用该对参数时执行，省略时行为
    # 完全不变。
    failed_identities: set[tuple[str, int]] = set()
    if chain_health_output is not None:
        for event in events:
            try:
                verify_proof(event)
            except ProofVerificationError:
                if not tolerate_failures:
                    raise
                failed_identities.add(
                    (event["chain_id"], event["sequence"])
                )

    # 先发布输出、再推进检查点：二者之间崩溃只会让下次重选行，绝不静默丢
    # 事件；续传时累积发布按 (chain_id, sequence) 去重，因此即便重选也不会
    # 写两次。全新开始总是写一份完整报告，覆盖输出路径上的陈旧文件。
    if output_path is not None:
        if resuming:
            _publish_resumed(output_path, reports)
        else:
            _atomic_write(output_path, _render_reports(reports))

    if checkpoint is not None and selected:
        new_cursors = dict(cursors)
        for event in selected:
            chain = event["chain_id"]
            sequence = event["sequence"]
            if sequence > new_cursors.get(chain, -1):
                new_cursors[chain] = sequence
        # 结构校验是整文件先行的：每个事件要么是本次有结果的被选事件，要么
        # 由保留游标覆盖（同链重复已被结构校验拒绝，未选行必然属于游标已达
        # 的历史）。故提交范围覆盖全部已读取且结构有效的物理行，摘要截到最
        # 后一条 JSONL 行行末（文件尾部空行不计入、其字节不纳入承诺）。这
        # 同时保证新 v3 自身满足“前缀内各链最大 sequence == 游标”不变式：
        # v2 升级时位于被选事件之后的历史行（如交错文件中其他链的高水位行）
        # 也被纳入承诺，而不是产出一份下次续传不可读的检查点。
        processed_lines = len(lines)
        prefix_end = lines[-1][2]
        digest = _sha256_hex(data[:prefix_end])
        # 旧版 last_sequence / v2 检查点在此随首次新事件完成一并升级为 v3
        # （隔离模式下成功或失败行都算已处理，同样触发升级）。
        _atomic_write(
            checkpoint, _render_checkpoint(new_cursors, processed_lines, digest)
        )

    # 连续性盘点最后发布：此时报告与检查点都已安全落盘，整批已成功；盘点由
    # 全部已读取事件推导，与游标无关，故空批（无新事件）也照常写出同一内容。
    if continuity_output is not None:
        _atomic_write(
            continuity_output, _render_reports(_build_continuity(events))
        )

    # 链级延迟画像在连续性盘点之后、延迟越界清单之前发布：由全部结构合法
    # 事件推导（成功行与隔离模式失败行同口径），与游标无关，故空批（无新
    # 事件）也照常写出同一内容，空输入写空文件。走到这里时整批已定稿，故
    # 严格模式的证明失败不可能到达此处。
    if latency_profile_output is not None:
        _atomic_write(
            latency_profile_output,
            _render_reports(_build_latency_profile(events)),
        )

    # 延迟越界清单在报告、检查点、连续性盘点、延迟画像之后最后发布：只查本
    # 次运行新产出的报告行（reports 即按行序的新行），无越界或无新事件时渲
    # 染为空串，原子替换为空文件。走到这里时整批已定稿，故严格模式的证明失
    # 败不可能到达此处。
    if latency_breach_output is not None:
        assert thresholds is not None
        _atomic_write(
            latency_breach_output,
            _render_reports(_build_latency_breaches(reports, thresholds)),
        )

    # 链级 SLO 汇总在所有其他产物之后最后发布：由全部结构合法事件推导
    # （含游标前历史行；失败身份见上），与游标无关，故空批（无新事件）也
    # 照常写出同一内容，空输入写空文件。走到这里时整批已定稿，严格模式的
    # 证明失败已在发布前抛出，不可能到达此处。
    if chain_health_output is not None:
        assert slo_thresholds is not None
        _atomic_write(
            chain_health_output,
            _render_reports(
                _build_chain_slo(events, failed_identities, slo_thresholds)
            ),
        )

    return reports


def run(
    input: PathLike,
    checkpoint: Optional[PathLike] = None,
    output: Optional[PathLike] = None,
    tolerate_failures: bool = False,
    continuity_output: Optional[PathLike] = None,
    latency_thresholds: Optional[PathLike] = None,
    latency_breach_output: Optional[PathLike] = None,
    latency_profile_output: Optional[PathLike] = None,
    chain_slo_thresholds: Optional[PathLike] = None,
    chain_health_output: Optional[PathLike] = None,
) -> list[dict]:
    """模块 API，与 ``relay-watch --input --checkpoint --output`` 同参。

    ``tolerate_failures`` 为真时进入逐事件失败隔离模式（见 :func:`watch`）；
    ``continuity_output`` 给定时在整批成功后额外原子写出序列连续性盘点；
    ``latency_thresholds`` 与 ``latency_breach_output`` 成对给定时最后原子
    写出延迟越界清单（阈值文件与越界判定口径见 :func:`watch`）；
    ``latency_profile_output`` 给定时在连续性盘点之后、延迟越界清单之前
    原子写出链级延迟画像（每链一行的 min/p50/p95/max 与归因计数，口径见
    :func:`watch` 与 :func:`_build_latency_profile`）；
    ``chain_slo_thresholds`` 与 ``chain_health_output`` 成对给定时最后原子
    写出链级 SLO 汇总（每链一行的两比率、三段 p95 与 violations，阈值文件
    与判定口径见 :func:`watch` 与 :func:`_build_chain_slo`）。
    """
    return watch(
        input,
        checkpoint,
        output,
        tolerate_failures,
        continuity_output,
        latency_thresholds,
        latency_breach_output,
        latency_profile_output,
        chain_slo_thresholds,
        chain_health_output,
    )
