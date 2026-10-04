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

可选的序列连续性盘点（``continuity_output``）：整批成功（报告与检查点均
安全发布）后原子写出一份 UTF-8 JSONL，每条 chain_id 一行并按该链在输入中
首次出现的顺序排列，字段为 chain_id、event_count、min_sequence、
max_sequence、missing_ranges、missing_count。盘点覆盖整份当前输入中结构
合法的事件，与续传游标无关：sequence 可从任意非负值开始，最小值之前不算
缺口，missing_ranges 升序列出相邻已出现 sequence 之间的闭区间空缺。隔离
模式下证明失败的事件同样占有其 sequence。空输入原子替换为空文件。

检查点当前为 schema_version 3：除按链游标外，还记录 ``processed_lines``
（已读取且结构有效的 JSONL 物理行数）与 ``input_prefix_sha256``（首字节到
第 processed_lines 行行末的原始 UTF-8 字节 SHA-256，64 位小写十六进制，
末行无换行不补）。续传时前 processed_lines 行必须与摘要逐字节一致，其后
仅可追加完整 JSONL 行；摘要不一致、processed_lines 非法或某链游标与前缀
内最大 sequence 不一致都抛 CheckpointError，防止历史事件被改写后仍被游标
跳过。旧版 last_sequence 与 schema_version 2 检查点仍按原规则读取，仅在
确有新事件成功（隔离模式下成功或失败）后才升级 v3，升级前不伪造摘要；无
新事件保持空操作，检查点文件原样保留。
"""

from __future__ import annotations

import hashlib
import json
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
# 序列连续性盘点
# --------------------------------------------------------------------------- #
def _continuity_rows(events: list[dict]) -> list[dict]:
    """按链盘点整个输入（与续传游标无关）的 sequence 连续性。

    链按其事件在输入中首次出现的顺序排列；event_count 统计该链结构合法
    事件数，min/max_sequence 取已出现值。missing_ranges 升序列出相邻已出现
    sequence 之间的闭区间空缺（含 start 与 end）：sequence 可从任意非负值
    开始，最小值之前不算缺口；单值或连续时为空，missing_count 为缺失总数。
    """
    order: list[str] = []
    sequences_by_chain: dict[str, list[int]] = {}
    for event in events:
        chain = event["chain_id"]
        if chain not in sequences_by_chain:
            sequences_by_chain[chain] = []
            order.append(chain)
        sequences_by_chain[chain].append(event["sequence"])

    rows: list[dict] = []
    for chain in order:
        sequences = sorted(sequences_by_chain[chain])
        missing_ranges: list[dict] = []
        missing_count = 0
        for low, high in zip(sequences, sequences[1:]):
            gap = high - low - 1
            if gap > 0:
                missing_ranges.append({"start": low + 1, "end": high - 1})
                missing_count += gap
        rows.append(
            {
                "chain_id": chain,
                "event_count": len(sequences),
                "min_sequence": sequences[0],
                "max_sequence": sequences[-1],
                "missing_ranges": missing_ranges,
                "missing_count": missing_count,
            }
        )
    return rows


def _render_continuity(rows: list[dict]) -> str:
    return "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        for row in rows
    )


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

    给定 ``continuity_output`` 时，仅在报告与检查点都安全发布后，原子替换
    该路径上的序列连续性盘点 JSONL（见模块说明）；盘点基于整份当前输入而非
    游标之后，故续传、追加与重复执行结果一致。该文件不参与游标，写出失败
    （如路径不可写）抛 OSError，此前已发布的报告与检查点保持有效。
    """
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

    if continuity_output is not None:
        # 盘点在既有报告与检查点安全发布之后写出，整批成功才会走到这里：
        # 严格模式证明失败已抛出，结构/检查点错误同样不会抵达此处。盘点覆盖
        # 整份当前输入（而非仅被选事件），与游标无关，续传、追加或重复执行
        # 结果一致；原子替换，绝不留下半成品。
        _atomic_write(
            continuity_output, _render_continuity(_continuity_rows(events))
        )

    return reports


def run(
    input: PathLike,
    checkpoint: Optional[PathLike] = None,
    output: Optional[PathLike] = None,
    tolerate_failures: bool = False,
    continuity_output: Optional[PathLike] = None,
) -> list[dict]:
    """模块 API，与 ``relay-watch --input --checkpoint --output`` 同参。

    ``tolerate_failures`` 为真时进入逐事件失败隔离模式（见 :func:`watch`）。
    给出 ``continuity_output`` 时整批成功后原子写出序列连续性盘点 JSONL
    （CLI 对应可选参数 ``--continuity-output``）；省略时其余行为不变。
    """
    return watch(
        input,
        checkpoint,
        output,
        tolerate_failures,
        continuity_output,
    )
