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

处理模式由 watch/run 的 tolerate_failures 决定：默认 False 为严格模式，
首个 ProofVerificationError 立即失败、不写报告、不推进检查点；True 为隔离
模式，单条证明失败转成 proof_status="failed" 的报告行（error_type 与
error_message 记录原异常），不阻断后续事件，成功与失败都算已处理并推进
检查点。结构性输入/检查点错误在两种模式下都照常抛出。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Union

PathLike = Union[str, "os.PathLike[str]"]

# 检查点结构版本；v2 以 chain_id 为键分别记录各链游标。
SCHEMA_VERSION = 2

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


def load_events(source: PathLike) -> list[dict]:
    """解析并结构性校验 UTF-8 JSONL 事件文件。

    一个输入可承载多个 ``chain_id``：sequence 仅在同一链内唯一，不同链复用
    同一 sequence 合法。事件按文件中的输入行序返回（各链事件可交错）。
    """
    events: list[dict] = []
    seen_sequences: dict[str, set[int]] = {}
    seen_timestamps: dict[str, set[int]] = {
        name: set() for name in TIME_FIELDS
    }
    try:
        with open(source, "r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                raw = _parse_json_line(text, lineno)
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
    except OSError as exc:
        raise InvalidInputError(
            f"cannot read input {str(source)!r}: {exc}"
        ) from exc

    _check_time_order(events)
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


def _latencies(event: dict) -> tuple[int, int, int]:
    proof_latency = event["proof_verified_at"] - event["proof_submitted_at"]
    relay_latency = event["proof_verified_at"] - event["observed_at"]
    destination_latency = event["finalized_at"] - event["proof_verified_at"]
    return proof_latency, relay_latency, destination_latency


def build_report(
    event: dict, error: Optional[ProofVerificationError] = None
) -> dict:
    """构造单行报告。

    严格模式下 ``error`` 恒为 None，行为与历史一致：proof 通过的事件输出
    ``proof_status="verified"``。隔离模式用被捕获的 ProofVerificationError
    调用时输出 ``proof_status="failed"``，并携带 error_type 与原有异常文本；
    延迟、归因与 finalized_at 的数值口径与成功行完全相同（结构合法事件的
    这些量不依赖证明结果）。
    """
    proof_latency, relay_latency, destination_latency = _latencies(event)

    report = {
        "event_id": event["event_id"],
        "chain_id": event["chain_id"],
        "sequence": event["sequence"],
        "proof_status": "verified" if error is None else "failed",
        "proof_latency_ms": proof_latency,
        "relay_latency_ms": relay_latency,
        "destination_latency_ms": destination_latency,
        "attribution": _attribution(
            proof_latency, relay_latency, destination_latency
        ),
        "finalized_at": event["finalized_at"],
    }
    if error is not None:
        report["error_type"] = type(error).__name__
        report["error_message"] = str(error)
    return report


# --------------------------------------------------------------------------- #
# 检查点
# --------------------------------------------------------------------------- #
#
# v2 检查点为::
#
#     {"schema_version": 2,
#      "last_sequence_by_chain": {"chain-a": 3, "chain-b": 7}}
#
# 结构问题（无法解析、缺键、null、数组、未知字段、schema_version 取值非法、
# last_sequence_by_chain 不是对象）一律 InvalidInputError；结构成立但游标取值
# 非法（游标非非负整数、链标识非非空字符串、游标超过该链输入最大 sequence）
# 为 CheckpointError。
#
# 旧版 {"last_sequence": N} 检查点仍可读：单 chain_id 输入把它解释为该链游标，
# 成功后升级为 v2；多 chain_id 输入无法确定归属，抛 CheckpointError。
@dataclass
class _Checkpoint:
    """解析后的检查点。

    legacy 为 True 表示读到旧版 last_sequence（其值记录在 legacy_value，
    chains 为空）；为 False 表示已是 v2，游标位于 chains。
    """

    chains: dict[str, int]
    legacy: bool = False
    legacy_value: Optional[int] = None


def _checkpoint_invalid(message: str) -> InvalidInputError:
    return InvalidInputError(f"checkpoint: {message}")


def _parse_v2_checkpoint(data: Any) -> dict[str, int]:
    """结构校验 v2 检查点。

    结构性问题抛 InvalidInputError：非对象、未知/缺失字段、schema_version
    不是整数 2、last_sequence_by_chain 不是对象，或任何位置出现 null/数组。
    语义问题抛 CheckpointError：链标识为空字符串、游标既非 null/数组又不是
    非负整数（负数、浮点、字符串、布尔等）。游标是否超过输入最大值由
    :func:`_resolve_checkpoint` 在获知输入后判定。
    """
    if not isinstance(data, dict):
        raise _checkpoint_invalid("must be a JSON object")

    allowed = {"schema_version", "last_sequence_by_chain"}
    unknown = set(data) - allowed
    if unknown:
        raise _checkpoint_invalid(
            f"unknown field(s): {', '.join(sorted(unknown))}"
        )
    if "schema_version" not in data:
        raise _checkpoint_invalid("missing schema_version")
    if "last_sequence_by_chain" not in data:
        raise _checkpoint_invalid("missing last_sequence_by_chain")

    version = data["schema_version"]
    # null、数组或任何非整数（含错误版本号）都属结构非法。
    if not _is_int(version):
        raise _checkpoint_invalid("schema_version must be an integer")
    if version != SCHEMA_VERSION:
        raise _checkpoint_invalid(
            f"unsupported schema_version {version}; expected {SCHEMA_VERSION}"
        )

    mapping = data["last_sequence_by_chain"]
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


def load_checkpoint(path: PathLike) -> Optional[_Checkpoint]:
    """读取检查点；文件不存在返回 None（首次处理）。

    返回 v2 游标映射，或包装旧版 last_sequence 的遗留检查点。
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
        return _Checkpoint(chains={}, legacy=True, legacy_value=last_sequence)

    chains = _parse_v2_checkpoint(data)
    return _Checkpoint(chains=chains, legacy=False)


def _resolve_checkpoint(
    checkpoint: Optional[_Checkpoint], events: list[dict]
) -> dict[str, int]:
    """把解析结果落实为按链游标，并做跨输入一致性检查。

    * 无检查点（首次处理）：空映射，各链均从第一条开始。
    * v2：直接采用；某链游标超过该链输入最大 sequence 抛 CheckpointError。
    * 旧版：仅当输入恰含一个 chain_id 时可归属；多链输入抛 CheckpointError。
      缺失链从第一条开始（游标取 -1 语义由调用方以“不在映射中”表达）。
    """
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
def _render_checkpoint(cursors: dict[str, int]) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "last_sequence_by_chain": dict(sorted(cursors.items())),
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
    给定 output_path 时原子写 JSONL 报告；各链只推进到本次已处理的最大
    sequence。

    严格模式（tolerate_failures=False，默认，兼容旧行为）：首个证明失败立即
    抛 ProofVerificationError，不写报告、不推进检查点。

    隔离模式（tolerate_failures=True）：结构合法事件逐条独立处理，单条证明
    失败转成 proof_status="failed" 的报告行（携带 error_type 与原有异常
    文本），不阻断后续事件的校验、延迟归因与报告生成；成功与失败都算已处理，
    检查点照常推进。结构性输入错误、检查点错误在两种模式下都照常抛出，不写
    新报告、不推进检查点。
    """
    events = load_events(input_path)

    parsed_checkpoint: Optional[_Checkpoint] = None
    resuming = False
    if checkpoint is not None:
        # 仅当检查点文件确实存在时才续传；文件缺失视为全新开始，需要完整
        # （重新）发布输入，而不是并入可能已陈旧的报告。
        resuming = os.path.exists(checkpoint)
        parsed_checkpoint = load_checkpoint(checkpoint)

    # 各链游标；映射中缺失的链（含检查点未记录的新链）从第一条开始。
    cursors = _resolve_checkpoint(parsed_checkpoint, events)
    selected = [
        event
        for event in events
        if event["sequence"] > cursors.get(event["chain_id"], -1)
    ]

    reports: list[dict] = []
    if tolerate_failures:
        # 隔离模式：逐事件独立验证，证明失败只影响该行。
        for event in selected:
            try:
                verify_proof(event)
            except ProofVerificationError as exc:
                reports.append(build_report(event, exc))
            else:
                reports.append(build_report(event))
    else:
        # 严格模式（默认）：首个证明失败立即抛出，不写报告、不推进检查点。
        for event in selected:
            verify_proof(event)
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
        # 旧版 last_sequence 检查点在此随单链成功处理一并升级为 v2。
        _atomic_write(checkpoint, _render_checkpoint(new_cursors))

    return reports


def run(
    input: PathLike,
    checkpoint: Optional[PathLike] = None,
    output: Optional[PathLike] = None,
    tolerate_failures: bool = False,
) -> list[dict]:
    """模块 API，与 ``relay-watch --input --checkpoint --output`` 同参。

    tolerate_failures=True 进入逐事件失败隔离模式（详见 :func:`watch`）。
    """
    return watch(input, checkpoint, output, tolerate_failures)
