"""relay-watch 命令行接口。

relay-watch --input IN --checkpoint CP --output OUT
    [--continuity-output PATH] [--tolerate-failures [{true,false}]]
    [--latency-thresholds PATH --latency-breach-output PATH]
    [--latency-profile-output PATH]
    [--chain-slo-thresholds PATH --chain-health-output PATH]
    [--trend-window-ms N --trend-output PATH]
    [--proof-audit-output PATH] [--attribution-audit-output PATH]

全程离线处理。任何领域错误都向标准错误写一个固定结构的 JSON 对象
``{"error": ..., "message": ...}``，以非零码退出，且绝不留下半成品报告。
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .core import (
    CheckpointError,
    InvalidInputError,
    ProofVerificationError,
    run,
)


class _JsonArgumentParser(argparse.ArgumentParser):
    """把用法错误也报告为固定 JSON 对象。"""

    def error(self, message: str) -> None:  # type: ignore[override]
        emit_error("InvalidArgument", message)
        raise SystemExit(2)


def emit_error(error: str, message: str) -> None:
    """把固定错误对象作为一行 JSON 写到标准错误。"""
    sys.stderr.write(
        json.dumps(
            {"error": error, "message": message}, ensure_ascii=False
        )
        + "\n"
    )


def _tolerate_failures_value(value: str) -> bool:
    """解析 --tolerate-failures 的布尔取值（仅接受小写 true/false）。"""
    if value == "true":
        return True
    if value == "false":
        return False
    # argparse 会在此消息前补 "argument --tolerate-failures: "。
    raise argparse.ArgumentTypeError("expected 'true' or 'false'")


def _positive_ms_value(value: str) -> int:
    """解析趋势窗口宽度：仅接受 >=1 的整数毫秒（拒绝浮点、符号、空白等）。"""
    if not value or not all("0" <= char <= "9" for char in value):
        # argparse 会在此消息前补 "argument --trend-window-ms: "。
        raise argparse.ArgumentTypeError(
            "must be an integer number of milliseconds"
        )
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError(
            "must be greater than or equal to 1"
        )
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        prog="relay-watch",
        description=(
            "离线跨链中继可靠性监控：校验轻客户端证明、对延迟归因并支持"
            "检查点续传。"
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        metavar="IN",
        help="UTF-8 JSONL 中继事件文件",
    )
    parser.add_argument(
        "--checkpoint",
        required=True,
        metavar="CP",
        help=(
            "按链记录续传游标的检查点 JSON 文件（schema_version 3："
            "last_sequence_by_chain、processed_lines、input_prefix_sha256）；"
            "schema_version 2 与旧版 last_sequence 仍可读。"
            "文件缺失表示从头处理"
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        metavar="OUT",
        help="JSONL 报告输出路径（原子写出）",
    )
    parser.add_argument(
        "--continuity-output",
        metavar="PATH",
        default=None,
        help=(
            "可选：序列连续性盘点输出路径（整批成功后原子替换的 UTF-8 "
            "JSONL，每链一行：chain_id、event_count、min_sequence、"
            "max_sequence、missing_ranges、missing_count）。盘点覆盖整个"
            "当前输入，与检查点游标无关；省略时不生成"
        ),
    )
    parser.add_argument(
        "--tolerate-failures",
        metavar="{true,false}",
        nargs="?",
        const=True,
        default=False,
        type=_tolerate_failures_value,
        help=(
            "逐事件失败隔离：true 时单条证明失败转为 proof_status=failed "
            "的报告行，不阻断后续事件与检查点推进；false（默认）为严格模式，"
            "首个证明失败立即报错退出。裸用该标志等价于 true。"
        ),
    )
    parser.add_argument(
        "--latency-thresholds",
        metavar="PATH",
        default=None,
        help=(
            "可选：延迟阈值 UTF-8 JSON 文件路径，对象仅含 proof_latency_ms、"
            "relay_latency_ms、destination_latency_ms 三个非负整数毫秒字段。"
            "必须与 --latency-breach-output 成对给出"
        ),
    )
    parser.add_argument(
        "--latency-breach-output",
        metavar="PATH",
        default=None,
        help=(
            "可选：延迟越界清单输出路径（整批成功后最后原子替换的 UTF-8 "
            "JSONL，字段为 event_id、chain_id、sequence、proof_status、"
            "breached_stages、attribution、finalized_at；三个延迟字段仅在"
            "严格大于 --latency-thresholds 同名阈值时列入）。必须与 "
            "--latency-thresholds 成对给出；无越界或无新事件时写空文件"
        ),
    )
    parser.add_argument(
        "--latency-profile-output",
        metavar="PATH",
        default=None,
        help=(
            "可选：链级延迟画像输出路径（整批成功、连续性盘点安全发布后、"
            "延迟越界清单之前原子替换的 UTF-8 JSONL）。按 chain_id 首次"
            "出现顺序每链一行，覆盖当前输入全部结构合法事件而非游标后的"
            "新行，空输入写空文件；字段为 chain_id、event_count、"
            "proof_latency_ms、relay_latency_ms、destination_latency_ms"
            "（三者各仅含 min、p50、p95、max，p50/p95 取最近秩）与"
            "attribution_counts（source、relay、destination，未出现写 0）。"
            "隔离模式 proof_status=failed 的事件与 verified 一起统计；"
            "省略时不生成"
        ),
    )
    parser.add_argument(
        "--chain-slo-thresholds",
        metavar="PATH",
        default=None,
        help=(
            "可选：链级 SLO 阈值 UTF-8 JSON 文件路径，对象仅含 "
            "proof_failure_rate_permille、missing_sequence_rate_permille"
            "（均为 0 到 1000 的整数）与 proof_latency_ms_p95、"
            "relay_latency_ms_p95、destination_latency_ms_p95（均为非负"
            "整数毫秒）。必须与 --chain-health-output 成对给出"
        ),
    )
    parser.add_argument(
        "--chain-health-output",
        metavar="PATH",
        default=None,
        help=(
            "可选：链级 SLO 汇总输出路径（报告、检查点、连续性盘点、延迟"
            "画像、延迟越界清单都安全发布后最后原子替换的 UTF-8 JSONL）。"
            "按 chain_id 首次出现顺序每链一行，覆盖当前输入全部结构合法"
            "事件而非游标后的新行，空输入写空文件；字段为 chain_id、"
            "event_count、proof_failure_rate_permille、"
            "missing_sequence_rate_permille、latency_p95_ms（三个整数键 "
            "proof_latency_ms、relay_latency_ms、destination_latency_ms，"
            "p95 取最近秩）与 violations（按两比率、三 p95 顺序仅列严格"
            "大于阈值项，达标为 []）。隔离模式 proof_status=failed 的事件"
            "计入失败率与 p95；省略时不生成"
        ),
    )
    parser.add_argument(
        "--trend-window-ms",
        metavar="N",
        default=None,
        type=_positive_ms_value,
        help=(
            "可选：链级时间窗口趋势画像的窗口宽度（大于等于 1 的整数"
            "毫秒）。window_start_ms 取不大于 finalized_at 的最大 N 的"
            "整数倍，按 chain_id 与该起点合并，空窗口不输出。必须与 "
            "--trend-output 成对给出"
        ),
    )
    parser.add_argument(
        "--trend-output",
        metavar="PATH",
        default=None,
        help=(
            "可选：链级时间窗口趋势画像输出路径（所有既有输出都安全发布"
            "后最后原子替换的 UTF-8 JSONL）。按 chain_id 首次出现顺序、"
            "链内窗口起点升序每窗口一行，覆盖当前输入全部结构合法事件"
            "而非游标后的新行，空输入写空文件；字段为 chain_id、"
            "window_start_ms、event_count、proof_failure_count、"
            "attribution_counts（仅含 source、relay、destination）与"
            "latency_p95_ms（三个 p95 各仅含 proof_latency_ms、"
            "relay_latency_ms、destination_latency_ms，取窗口事件最近秩"
            "max(1,ceil(0.95*n))）。隔离模式 proof_status=failed 的事件"
            "计入 event_count 并另计 proof_failure_count。必须与 "
            "--trend-window-ms 成对给出"
        ),
    )
    parser.add_argument(
        "--proof-audit-output",
        metavar="PATH",
        default=None,
        help=(
            "可选：轻客户端证明校验审计画像输出路径（所有既有输出都安全"
            "发布后最后原子替换的 UTF-8 JSONL）。按输入行序为当前完整"
            "输入的全部结构合法事件各写一行而非游标后的新行，续传、追加、"
            "重复执行结果一致，空输入写空文件；字段为 event_id、chain_id、"
            "sequence、proof_status、light_client_version、"
            "provided_signature_count、unique_signature_count、quorum、"
            "checks（三个布尔键依次为 quorum_sufficient、"
            "validator_set_hash_matches、trusted_root_matches_header，"
            "各自复用现有证明规则）、failed_checks（仅按序列出 false 项，"
            "verified 为 []）与 finalized_at。隔离模式成功与失败事件都入"
            "画像（proof_status=failed）；严格模式证明失败仍抛 "
            "ProofVerificationError 且不写画像；结构/检查点错误同样不写。"
            "画像只读推导，不参与游标、汇总，不改任何既有输出；省略时不"
            "生成"
        ),
    )
    parser.add_argument(
        "--attribution-audit-output",
        metavar="PATH",
        default=None,
        help=(
            "可选：归因审计画像输出路径（所有既有输出都安全发布后最后原子"
            "替换的 UTF-8 JSONL）。按输入行序为当前完整输入的全部结构合法"
            "事件各写一行而非游标后的新行，续传、追加、重复执行结果一致，"
            "空输入写空文件；字段为 event_id、chain_id、sequence、"
            "proof_status、latency_ms（仅含 proof_latency_ms、"
            "relay_latency_ms、destination_latency_ms）、attribution"
            "（最大非负延迟阶段，并列最高归 source）、"
            "attribution_candidates（按 source、relay、destination 列出"
            "全部并列最高）、attribution_gap_ms（第一与第二高非负延迟之"
            "差，并列为 0）、negative_stages（同序列出负延迟阶段，无为 "
            "[]）与 finalized_at。隔离模式成功与失败事件都入画像"
            "（proof_status=failed）；严格模式证明失败仍抛 "
            "ProofVerificationError 且不写画像；结构/检查点错误同样不写。"
            "画像只读推导，不参与游标、汇总，不改任何既有输出；省略时不"
            "生成"
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # 两个延迟越界参数必须成对：缺一即用法错误，按固定 JSON（InvalidArgument）
    # 以退出码 2 报告，与 argparse 自身的参数错误同口径。
    if (args.latency_thresholds is None) != (
        args.latency_breach_output is None
    ):
        parser.error(
            "--latency-thresholds and --latency-breach-output must be "
            "given together"
        )

    # 链级 SLO 两参数同样必须成对，错误口径与延迟越界参数一致。
    if (args.chain_slo_thresholds is None) != (
        args.chain_health_output is None
    ):
        parser.error(
            "--chain-slo-thresholds and --chain-health-output must be "
            "given together"
        )

    # 链级时间窗口趋势画像两参数同样必须成对；窗口宽度的语法与取值错误
    # 已由 argparse 的 type=_positive_ms_value 以同一固定 JSON 口径拒绝。
    if (args.trend_window_ms is None) != (args.trend_output is None):
        parser.error(
            "--trend-window-ms and --trend-output must be given together"
        )

    try:
        run(
            args.input,
            args.checkpoint,
            args.output,
            tolerate_failures=args.tolerate_failures,
            continuity_output=args.continuity_output,
            latency_thresholds=args.latency_thresholds,
            latency_breach_output=args.latency_breach_output,
            latency_profile_output=args.latency_profile_output,
            chain_slo_thresholds=args.chain_slo_thresholds,
            chain_health_output=args.chain_health_output,
            trend_window_ms=args.trend_window_ms,
            trend_output=args.trend_output,
            proof_audit_output=args.proof_audit_output,
            attribution_audit_output=args.attribution_audit_output,
        )
    except ProofVerificationError as exc:
        emit_error("ProofVerificationError", str(exc))
        return 1
    except CheckpointError as exc:
        emit_error("CheckpointError", str(exc))
        return 1
    except InvalidInputError as exc:
        emit_error("InvalidInputError", str(exc))
        return 1
    except OSError as exc:
        emit_error(type(exc).__name__, str(exc))
        return 1
    return 0
