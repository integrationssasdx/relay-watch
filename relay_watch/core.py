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
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from typing import Any, Iterable, Optional, Union

PathLike = Union[str, "os.PathLike[str]"]

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

    一个输入可承载多条链：身份与所有唯一性约束都在各自 ``chain_id`` 内部
    判定，因此不同链复用同一 sequence 合法，各链事件也可以交错出现。
    """
    events: list[dict] = []
    seen_sequences: set[tuple[str, int]] = set()
    seen_timestamps: dict[tuple[str, str], set[int]] = {}
    try:
        with open(source, "r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                raw = _parse_json_line(text, lineno)
                event = _validate_event(raw, lineno)

                identity = (event["chain_id"], event["sequence"])
                if identity in seen_sequences:
                    raise InvalidInputError(
                        f"event {event['event_id']!r}: duplicate sequence "
                        f"{event['sequence']} on chain {event['chain_id']!r}"
                    )
                seen_sequences.add(identity)

                # 每个时间字段在「同一链、同一列」内跨事件唯一；不同链或不同
                # 列允许相同。
                for name in TIME_FIELDS:
                    stamp = event[name]
                    key = (event["chain_id"], name)
                    column = seen_timestamps.setdefault(key, set())
                    if stamp in column:
                        raise InvalidInputError(
                            f"event {event['event_id']!r}: {name} value "
                            f"{stamp} is not unique on chain "
                            f"{event['chain_id']!r}"
                        )
                    column.add(stamp)

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


def build_report(event: dict, multi_chain: bool = False) -> dict:
    proof_latency = event["proof_verified_at"] - event["proof_submitted_at"]
    relay_latency = event["proof_verified_at"] - event["observed_at"]
    destination_latency = event["finalized_at"] - event["proof_verified_at"]

    report = {
        "event_id": event["event_id"],
        "sequence": event["sequence"],
        "proof_status": "verified",
        "proof_latency_ms": proof_latency,
        "relay_latency_ms": relay_latency,
        "destination_latency_ms": destination_latency,
        "attribution": _attribution(
            proof_latency, relay_latency, destination_latency
        ),
        "finalized_at": event["finalized_at"],
    }
    # 单链入口保持原字段与口径不变；只有一个输入承载多条链时才用 chain_id
    # 区分报告行，避免不同链的同 sequence 相互覆盖。
    if multi_chain:
        report = {"chain_id": event["chain_id"], **report}
    return report


# --------------------------------------------------------------------------- #
# 检查点
# --------------------------------------------------------------------------- #
#
# 现行结构（schema_version 2）按链记录游标::
#
#     {"schema_version": 2,
#      "last_sequence_by_chain": {"chain-a": 3, "chain-b": 7}}
#
# 旧结构 {"last_sequence": N}（无 schema_version）仍可读，但只能归属到单链
# 输入；多链输入无法确定它属于哪条链，拒绝续传。
SCHEMA_VERSION = 2


def load_checkpoint(path: PathLike) -> Union[dict, int, None]:
    """读取检查点。

    文件不存在返回 ``None``。返回 v2 的 ``last_sequence_by_chain`` 字典，
    或旧格式的裸 ``last_sequence`` 整数（结构已校验，尚未对照输入）。
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
        raise InvalidInputError(
            f"checkpoint is not valid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise InvalidInputError("checkpoint must be a JSON object")

    # 旧格式：{"last_sequence": N}，无 schema_version。沿用旧版的宽容度：
    # 只要携带 last_sequence 即可读，额外字段忽略。
    if "schema_version" not in data:
        if "last_sequence" not in data:
            raise InvalidInputError(
                "checkpoint must be a JSON object containing "
                "schema_version and last_sequence_by_chain"
            )
        return _legacy_cursor(data["last_sequence"])

    return _v2_checkpoint(data)


def _legacy_cursor(value: Any) -> int:
    if not _is_int(value):
        # 布尔、浮点、字符串、null 都算“非整数”。
        raise CheckpointError("checkpoint last_sequence must be an integer")
    if value < 0:
        raise CheckpointError("checkpoint last_sequence must not be negative")
    return value


def _v2_checkpoint(data: dict) -> dict:
    if set(data) != {"schema_version", "last_sequence_by_chain"}:
        raise InvalidInputError(
            "checkpoint must contain only schema_version and "
            "last_sequence_by_chain"
        )

    version = data["schema_version"]
    if not _is_int(version) or version != SCHEMA_VERSION:
        raise InvalidInputError(
            f"unsupported checkpoint schema_version: {version!r}"
        )

    cursors = data["last_sequence_by_chain"]
    # 映射整体为 null / 数组属于结构错误；游标单个取值不合规则属于
    # CheckpointError（见下方逐项校验）。
    if not isinstance(cursors, dict):
        raise InvalidInputError(
            "checkpoint last_sequence_by_chain must be a JSON object"
        )

    normalized: dict[str, int] = {}
    for chain_id, cursor in cursors.items():
        if not isinstance(chain_id, str) or not chain_id:
            raise CheckpointError(
                "checkpoint chain identifiers must be non-empty strings"
            )
        if not _is_int(cursor):
            # null、布尔、浮点、字符串等游标均不是非负整数。
            raise CheckpointError(
                f"checkpoint cursor for chain {chain_id!r} must be a "
                "non-negative integer"
            )
        if cursor < 0:
            raise CheckpointError(
                f"checkpoint cursor for chain {chain_id!r} must not be negative"
            )
        normalized[chain_id] = cursor
    return normalized


def max_sequence_by_chain(events: list[dict]) -> dict[str, int]:
    maxima: dict[str, int] = {}
    for event in events:
        chain_id = event["chain_id"]
        sequence = event["sequence"]
        if chain_id not in maxima or sequence > maxima[chain_id]:
            maxima[chain_id] = sequence
    return maxima


def resolve_cursors(
    checkpoint_data: Any, chain_ids: set[str]
) -> tuple[dict[str, int], bool]:
    """把读入的检查点归属于本批输入的链。

    返回 ``(各链游标, 是否旧格式)``。只做归属，不做“游标超过输入最大
    sequence”校验——那需要事件本身，由 :func:`validate_cursors` 完成。
    检查点中出现但本批输入不含的链原样保留、不参与选择。
    """
    if checkpoint_data is None:
        return {}, False

    if isinstance(checkpoint_data, int):
        # 旧 last_sequence 检查点没有链归属：单链输入可归给该链，多链输入
        # 无法确定归属。
        if len(chain_ids) > 1:
            raise CheckpointError(
                "legacy last_sequence checkpoint cannot be attributed to a "
                "multi-chain input"
            )
        if len(chain_ids) == 1:
            return {next(iter(chain_ids)): checkpoint_data}, True
        return {}, True

    return dict(checkpoint_data), False


def validate_cursors(
    cursors: dict[str, int], maxima_by_chain: dict[str, int]
) -> None:
    """某链游标超过该链输入最大 sequence 即不可用。"""
    for chain_id, cursor in cursors.items():
        maximum = maxima_by_chain.get(chain_id)
        if maximum is not None and cursor > maximum:
            raise CheckpointError(
                f"checkpoint last_sequence {cursor} for chain {chain_id!r} "
                f"exceeds input maximum sequence {maximum}"
            )


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


def _publish_resumed(
    path: PathLike, reports: list[dict], single_chain: Optional[str] = None
) -> None:
    """向累积报告追加新行，且绝不重复输出。

    报告行由 (chain_id, sequence) 唯一识别：多链行显式携带 chain_id；单链
    入口的行没有该字段，归属到 ``single_chain``。按身份去重使发布幂等：
    即便上一次已写报告却在推进检查点前崩溃，重跑会选中同样的事件，但不会
    二次写出。
    """
    existing = _read_report_rows(path)

    def identity(row: dict) -> tuple[Optional[str], Any]:
        return (row.get("chain_id", single_chain), row.get("sequence"))

    known = {identity(row) for row in existing}
    fresh = [row for row in reports if identity(row) not in known]
    if not fresh:
        # 没有任何新身份：续传空操作，既不重复写也不凭空创建输出文件。
        return
    _atomic_write(path, _render_reports(existing + fresh))


# --------------------------------------------------------------------------- #
# 公共管线
# --------------------------------------------------------------------------- #
def watch(
    input_path: PathLike,
    checkpoint: Optional[PathLike] = None,
    output_path: Optional[PathLike] = None,
) -> list[dict]:
    """运行监控并返回逐事件报告行（按输入行顺序）。

    一个输入可承载多条链：选择、去重、检查点推进都以 (chain_id, sequence)
    为身份；单链输入的报告字段保持不变，多链输入的每行额外携带 chain_id。

    给定 output_path 时原子写 JSONL 报告；仅当所有被选中事件都验证成功后，
    才原子推进 checkpoint（若给出）。
    """
    events = load_events(input_path)
    maxima = max_sequence_by_chain(events)
    input_chains = set(maxima)
    multi_chain = len(input_chains) > 1

    resuming = False
    cursors: dict[str, int] = {}
    if checkpoint is not None:
        # 仅当检查点文件确实存在时才续传；文件缺失视为全新开始，需要完整
        # （重新）发布输入，而不是并入可能已陈旧的报告。
        resuming = os.path.exists(checkpoint)
        if resuming:
            checkpoint_data = load_checkpoint(checkpoint)
            cursors, _legacy = resolve_cursors(checkpoint_data, input_chains)
            validate_cursors(cursors, maxima)

    if resuming:
        # 检查点中缺失的链没有游标：其全部事件都视为尚未处理。
        selected = []
        for event in events:
            cursor = cursors.get(event["chain_id"])
            if cursor is None or event["sequence"] > cursor:
                selected.append(event)
    else:
        selected = list(events)

    reports: list[dict] = []
    for event in selected:
        verify_proof(event)
        reports.append(build_report(event, multi_chain=multi_chain))

    # 先发布输出、再推进检查点：二者之间崩溃只会让下次重选行，绝不静默丢
    # 事件；续传时累积发布按 (chain_id, sequence) 去重，因此即便重选也不会
    # 写两次。全新开始总是写一份完整报告，覆盖输出路径上的陈旧文件。
    if output_path is not None:
        if resuming:
            single_chain = None if multi_chain else next(iter(input_chains), None)
            _publish_resumed(output_path, reports, single_chain=single_chain)
        else:
            _atomic_write(output_path, _render_reports(reports))

    if checkpoint is not None and selected:
        # 在旧游标基础上只推进本次成功处理的链；本批未出现的链原样保留。
        new_cursors = dict(cursors)
        for chain_id, sequence in max_sequence_by_chain(selected).items():
            previous = new_cursors.get(chain_id)
            new_cursors[chain_id] = (
                sequence if previous is None else max(previous, sequence)
            )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "last_sequence_by_chain": new_cursors,
        }
        _atomic_write(
            checkpoint,
            json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
        )

    return reports


def run(
    input: PathLike,
    checkpoint: Optional[PathLike] = None,
    output: Optional[PathLike] = None,
) -> list[dict]:
    """模块 API，与 ``relay-watch --input --checkpoint --output`` 同参。"""
    return watch(input, checkpoint, output)
