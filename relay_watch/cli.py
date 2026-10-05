"""relay-watch 命令行接口。

relay-watch --input IN --checkpoint CP --output OUT
    [--continuity-output PATH] [--tolerate-failures [{true,false}]]
    [--latency-thresholds PATH --latency-breach-output PATH]
    [--latency-profile-output PATH]
    [--chain-slo-thresholds PATH --chain-health-output PATH]

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
            "（0 到 1000 的整数）与 proof_latency_ms_p95、"
            "relay_latency_ms_p95、destination_latency_ms_p95（非负整数"
            "毫秒）五个字段。必须与 --chain-health-output 成对给出"
        ),
    )
    parser.add_argument(
        "--chain-health-output",
        metavar="PATH",
        default=None,
        help=(
            "可选：链级 SLO 汇总输出路径（其他产物全部安全发布后最后原子"
            "替换的 UTF-8 JSONL）。按 chain_id 首现顺序每链一行，覆盖当前"
            "输入全部结构合法事件而非游标后的新行，空输入写空文件；字段为"
            "chain_id、event_count、proof_failure_rate_permille、"
            "missing_sequence_rate_permille、latency_p95_ms（仅含 "
            "proof_latency_ms、relay_latency_ms、destination_latency_ms "
            "三个整数键，取画像 p95 最近秩）与 violations（按两比率、三 "
            "p95 顺序仅列严格大于阈值的项，达标为 []）。隔离模式 "
            "proof_status=failed 行计入失败率与 p95；必须与 "
            "--chain-slo-thresholds 成对给出"
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

    # 两个链级 SLO 参数同样必须成对：缺一同口径报 InvalidArgument、退出 2。
    if (args.chain_slo_thresholds is None) != (
        args.chain_health_output is None
    ):
        parser.error(
            "--chain-slo-thresholds and --chain-health-output must be "
            "given together"
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
