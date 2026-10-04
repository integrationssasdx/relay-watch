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

检查点当前为 schema_version 3：除按链游标外记录 ``processed_lines``（已读取
且结构有效的 JSONL 物理行数）与 ``input_prefix_sha256``（首字节到第
processed_lines 行行末原始 UTF-8 字节的 SHA-256）。续传时此前缀必须逐字节
复算一致，防止同一 (chain_id, sequence) 的历史事件在两次运行之间被改写后
仍被游标跳过；前缀只允许追加完整 JSONL 行。
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

# 检查点结构版本；v3 在 v2 按链游标之上增加已处理物理行数与输入前缀摘要。
SCHEMA_VERSION = 3

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


def _read_input_bytes(source: PathLike) -> bytes:
    """读取原始 UTF-8 字节；解码失败或无法读取均属输入错误。"""
    try:
        with open(source, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise InvalidInputError(
            f"cannot read input {str(source)!r}: {exc}"
        ) from exc


@dataclass
class _Input:
    """解析后的输入：原始字节与逐事件的物理行字节区间。

    ``spans`` 与 ``events`` 一一对应，给出每个事件所在物理行（含行末换行；
    末行无换行则截至 EOF）在 ``data`` 中的半开区间。空白行被跳过、既不生成
    事件也不计入 ``spans``。
    """

    data: bytes
    events: list[dict]
    spans: list[tuple[int, int]]


def load_input(source: PathLike) -> _Input:
    """解析并结构性校验 UTF-8 JSONL 事件文件，保留原始字节与物理行区间。

    一个输入可承载多个 ``chain_id``：sequence 仅在同一链内唯一，不同链复用
    同一 sequence 合法。事件按文件中的输入行序返回（各链事件可交错）。

    物理行按 ``\\n`` 切分（兼容 ``\\r\\n``）；空白行跳过且不计入物理行数。
    每个结构有效行恰好承载一个事件，故事件数即“已读取且结构有效的 JSONL
    物理行数”。
    """
    data = _read_input_bytes(source)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidInputError(
            f"input {str(source)!r} is not valid UTF-8: {exc}"
        ) from exc

    # \n 是 ASCII 字节，UTF-8 多字节序列不会包含 0x0A，故文本与字节两种切分
    # 的段数严格对齐，可并行处理而保持字节区间精确。
    text_parts = text.split("\n")
    byte_parts = data.split(b"\n")

    events: list[dict] = []
    spans: list[tuple[int, int]] = []
    seen_sequences: dict[str, set[int]] = {}
    seen_timestamps: dict[str, set[int]] = {
        name: set() for name in TIME_FIELDS
    }

    offset = 0
    for physical_lineno, (line_text, line_bytes) in enumerate(
        zip(text_parts, byte_parts), start=1
    ):
        line_len = len(line_bytes) + (1 if physical_lineno < len(text_parts) else 0)
        end = offset + line_len

        stripped = line_text.strip()
        if stripped:
            raw = _parse_json_line(stripped, physical_lineno)
            event = _validate_event(raw, physical_lineno)

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
            spans.append((offset, end))

        offset = end

    _check_time_order(events)
    return _Input(data=data, events=events, spans=spans)


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
# processed_lines 是已读取且结构有效的 JSONL 物理行数（=已处理事件数，空白
# 行不计）；input_prefix_sha256 是输入首字节到第 processed_lines 行行末原始
# UTF-8 字节的 SHA-256，末行无换行不补。
#
# 结构问题（无法解析、缺键、null、数组、未知字段、schema_version 取值非法、
# last_sequence_by_chain 不是对象、processed_lines 非正整数、摘要不是 64 位
# 小写十六进制）一律 InvalidInputError；结构成立但与当前输入不一致（游标非
# 非负整数或超过该链输入最大 sequence、processed_lines 超行数、前缀摘要不
# 匹配、某链最大 sequence 与游标不一致）为 CheckpointError。
#
# 旧版 {"last_sequence": N} 与 v2 检查点仍可读，但不伪造摘要：按当前规则
# 完成游标选择，只在确有新事件成功（隔离模式下成功或失败都算）后升级为 v3，
# 无新事件保持原样、空操作成功。
_HEX64_LOWER = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class _Checkpoint:
    """解析后的检查点。

    * legacy（``{"last_sequence": N}``）：legacy=True、legacy_value 记录旧值；
    * v2：version=2，游标位于 chains；
    * v3：version=3，另有 processed_lines 与 input_prefix_sha256。
    """

    chains: dict[str, int]
    version: int = SCHEMA_VERSION
    legacy: bool = False
    legacy_value: Optional[int] = None
    processed_lines: Optional[int] = None
    input_prefix_sha256: Optional[str] = None


def _checkpoint_invalid(message: str) -> InvalidInputError:
    return InvalidInputError(f"checkpoint: {message}")


def _parse_chain_mapping(mapping: Any) -> dict[str, int]:
    """校验 ``last_sequence_by_chain`` 的结构与游标取值。

    映射本身不是对象（null/数组等）属结构非法（InvalidInputError）；链标识
    为空字符串、游标为 null/数组或不是非负整数的区分沿用 v2 规则：null/数组
    属结构非法，其余非非负整数取值属语义非法（CheckpointError）。
    """
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
    """结构校验 v2/v3 检查点。"""
    version = data["schema_version"]
    # null、数组或任何非整数（含错误版本号）都属结构非法。
    if not _is_int(version):
        raise _checkpoint_invalid("schema_version must be an integer")
    if version not in (2, 3):
        raise _checkpoint_invalid(
            f"unsupported schema_version {version}; expected 2 or 3"
        )

    allowed = {"schema_version", "last_sequence_by_chain"}
    if version == 3:
        allowed |= {"processed_lines", "input_prefix_sha256"}
    unknown = set(data) - allowed
    if unknown:
        raise _checkpoint_invalid(
            f"unknown field(s): {', '.join(sorted(unknown))}"
        )
    if "last_sequence_by_chain" not in data:
        raise _checkpoint_invalid("missing last_sequence_by_chain")

    chains = _parse_chain_mapping(data["last_sequence_by_chain"])

    if version == 2:
        return _Checkpoint(chains=chains, version=2)

    if "processed_lines" not in data:
        raise _checkpoint_invalid("missing processed_lines")
    if "input_prefix_sha256" not in data:
        raise _checkpoint_invalid("missing input_prefix_sha256")

    processed_lines = data["processed_lines"]
    # null/数组或非正整数（含 0、负数、浮点、字符串、布尔）属结构非法。
    if (
        processed_lines is None
        or isinstance(processed_lines, list)
        or not _is_int(processed_lines)
        or processed_lines <= 0
    ):
        raise _checkpoint_invalid(
            "processed_lines must be a positive integer"
        )

    digest = data["input_prefix_sha256"]
    # 类型错误与格式（非 64 位小写十六进制；大写也不接受）都属结构非法。
    if not isinstance(digest, str) or not _HEX64_LOWER.match(digest):
        raise _checkpoint_invalid(
            "input_prefix_sha256 must be a 64-character lowercase hex string"
        )

    return _Checkpoint(
        chains=chains,
        version=3,
        processed_lines=processed_lines,
        input_prefix_sha256=digest,
    )


def load_checkpoint(path: PathLike) -> Optional[_Checkpoint]:
    """读取检查点；文件不存在返回 None（首次处理）。

    支持旧版 last_sequence、v2 与 v3 三种形态。
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
            chains={},
            version=1,
            legacy=True,
            legacy_value=last_sequence,
        )

    return _parse_versioned_checkpoint(data)


def _prefix_digest(input_data: _Input, processed_lines: int) -> tuple[str, int]:
    """返回前 ``processed_lines`` 个事件物理行（含行末字节）的摘要与区间末。

    行按输入行序取自 :attr:`_Input.spans`；末行无换行时 span 已不含换行，
    故不额外补字节。
    """
    end = input_data.spans[processed_lines - 1][1]
    return _sha256_hex(input_data.data[:end]), end


def _resolve_checkpoint(
    checkpoint: Optional[_Checkpoint], input_data: _Input
) -> dict[str, int]:
    """把解析结果落实为按链游标，并做跨输入一致性检查。

    * 无检查点（首次处理）：空映射，各链均从第一条开始。
    * v2：直接采用；某链游标超过该链输入最大 sequence 抛 CheckpointError。
      v2 不携带输入摘要，不做前缀校验（升级 v3 后才开始保护）。
    * v3：processed_lines 不得超过有效物理行数，记录的前缀摘要必须与当前
      输入逐字节一致；其后只允许追加完整 JSONL 行；且各链游标必须等于前
      processed_lines 行内该链的最大 sequence（游标与输入不一致即拒绝）。
    * 旧版：仅当输入恰含一个 chain_id 时可归属；多链输入抛 CheckpointError。
      缺失链从第一条开始（游标取 -1 语义由调用方以“不在映射中”表达）。
    """
    events = input_data.events
    if checkpoint is None:
        return {}

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

    max_by_chain: dict[str, int] = {}
    for event in events:
        chain = event["chain_id"]
        sequence = event["sequence"]
        if chain not in max_by_chain or sequence > max_by_chain[chain]:
            max_by_chain[chain] = sequence

    for chain, cursor in chains.items():
        if chain in max_by_chain and cursor > max_by_chain[chain]:
            raise CheckpointError(
                f"checkpoint cursor {cursor} for chain {chain!r} exceeds input "
                f"maximum sequence {max_by_chain[chain]}"
            )

    if checkpoint.version == 3:
        total_lines = len(events)
        processed_lines = checkpoint.processed_lines
        assert processed_lines is not None  # 结构校验已保证
        if processed_lines > total_lines:
            raise CheckpointError(
                f"checkpoint processed_lines {processed_lines} exceeds the "
                f"{total_lines} valid JSONL line(s) in the input"
            )

        digest, end = _prefix_digest(input_data, processed_lines)
        if digest != checkpoint.input_prefix_sha256:
            raise CheckpointError(
                "input prefix digest mismatch: the first "
                f"{processed_lines} processed line(s) changed since the "
                "checkpoint was written"
            )

        # 前缀之后只允许追加完整 JSONL 行：end 处若非 EOF，必位于行边界
        # （下一物理行起点），即前一字节必须是换行。正常情况下摘要逐字节
        # 匹配已隐含此不变量（旧末行无换行时任何续写都会改动该行终止符而
        # 先导致摘要不一致），这里保留一道防御性复核。
        if end < len(input_data.data) and input_data.data[end - 1] != 0x0A:
            raise CheckpointError(
                "input can only be extended by appending complete JSONL lines "
                "after the processed prefix"
            )

        # 前缀内出现的每条链都必须在游标映射中，且游标等于其前缀最大
        # sequence；映射可额外保留前缀（本输入）未出现链的游标不动，以
        # 支持多个输入轮流处理不同链。游标落后、超前或链缺失都视为不一致。
        prefix_max: dict[str, int] = {}
        for event in events[:processed_lines]:
            chain = event["chain_id"]
            sequence = event["sequence"]
            if chain not in prefix_max or sequence > prefix_max[chain]:
                prefix_max[chain] = sequence
        for chain, max_sequence in prefix_max.items():
            if chains.get(chain) != max_sequence:
                raise CheckpointError(
                    f"checkpoint cursor for chain {chain!r} does not match the "
                    f"maximum sequence {max_sequence} within the processed prefix"
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
# 公共管线
# --------------------------------------------------------------------------- #
def _render_checkpoint(
    cursors: dict[str, int], processed_lines: int, prefix_digest: str
) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "last_sequence_by_chain": dict(sorted(cursors.items())),
        "processed_lines": processed_lines,
        "input_prefix_sha256": prefix_digest,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n"


def watch(
    input_path: PathLike,
    checkpoint: Optional[PathLike] = None,
    output_path: Optional[PathLike] = None,
    tolerate_failures: bool = False,
) -> list[dict]:
    """运行监控并返回逐事件报告行（按输入行序）。

    一个输入可承载多个 chain_id；选择与续传身份为 (chain_id, sequence)。
    给定 output_path 时原子写 JSONL 报告；仅当所有被选中事件都有确定结果
    后，才原子推进 checkpoint（若给出），且各链只推进到本次已处理的最大
    sequence。

    检查点推进时同步把 ``processed_lines`` 推进到本次最后一个被选事件所在
    物理行，并记录该前缀（首字节至该行行末的原始 UTF-8 字节）的 SHA-256；
    下次续传先复算此前缀逐字节比对，历史行一旦被改写即抛 CheckpointError，
    不会被游标静默跳过。旧版 last_sequence 与 v2 检查点不带摘要，按既有游标
    规则读取，仅在确有被选事件产生结果（严格模式下全部验证成功；隔离模式下
    成功或失败行都算）后才随本次推进升级为 v3；无被选事件时原样保留、空
    操作成功。

    严格模式（``tolerate_failures=False``，默认，兼容旧行为）下，结构合法但
    证明失败的首个事件立即抛 :class:`ProofVerificationError`，不写报告、不推进
    检查点。隔离模式（``tolerate_failures=True``）下，每个结构合法事件独立
    处理：成功者为 ``proof_status="verified"`` 行，失败者为
    ``proof_status="failed"`` 行（携带 error_type/error_message）；成功与失败
    都算“已处理”，同样推进检查点，同链后续事件不受先前失败影响。结构性输入
    错误与检查点错误在两种模式下都直接抛出，不写报告、不推进检查点。
    """
    input_data = load_input(input_path)
    events = input_data.events

    parsed_checkpoint: Optional[_Checkpoint] = None
    resuming = False
    if checkpoint is not None:
        # 仅当检查点文件确实存在时才续传；文件缺失视为全新开始，需要完整
        # （重新）发布输入，而不是并入可能已陈旧的报告。
        resuming = os.path.exists(checkpoint)
        parsed_checkpoint = load_checkpoint(checkpoint)

    # 各链游标；映射中缺失的链（含检查点未记录的新链）从第一条开始。
    cursors = _resolve_checkpoint(parsed_checkpoint, input_data)

    # 记录每个被选事件在 events 中的下标：v3 的 processed_lines 推进到本次
    # 最后一个被选事件所在的物理行。
    selected: list[dict] = []
    selected_indices: list[int] = []
    for index, event in enumerate(events):
        if event["sequence"] > cursors.get(event["chain_id"], -1):
            selected.append(event)
            selected_indices.append(index)

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
        # processed_lines 落在最后一个被选事件行；旧版/v2 检查点在此一并升级
        # 为 v3（隔离模式下成功或失败行都算已处理，同样触发升级），摘要只
        # 覆盖真实读过的前缀，绝不伪造。
        new_processed_lines = selected_indices[-1] + 1
        prefix_digest, _ = _prefix_digest(input_data, new_processed_lines)
        _atomic_write(
            checkpoint,
            _render_checkpoint(new_cursors, new_processed_lines, prefix_digest),
        )

    return reports


def run(
    input: PathLike,
    checkpoint: Optional[PathLike] = None,
    output: Optional[PathLike] = None,
    tolerate_failures: bool = False,
) -> list[dict]:
    """模块 API，与 ``relay-watch --input --checkpoint --output`` 同参。

    ``tolerate_failures`` 为真时进入逐事件失败隔离模式（见 :func:`watch`）。
    """
    return watch(input, checkpoint, output, tolerate_failures)
