"""relay-watch 命令行接口。

relay-watch --input IN --checkpoint CP --output OUT [--tolerate-failures]

全程离线处理。任何领域错误都向标准错误写一个固定结构的 JSON 对象
``{"error": ..., "message": ...}``，以非零码退出，且绝不留下半成品报告。
严格模式（默认）下首个证明失败即如此；--tolerate-failures 进入隔离模式，
证明失败不报错退出，而是写入 proof_status=failed 的报告行。
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
            "按链记录续传游标的检查点 JSON 文件（schema_version 2，"
            "last_sequence_by_chain）；旧版 last_sequence 仍可读。"
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
        "--tolerate-failures",
        dest="tolerate_failures",
        action="store_true",
        default=False,
        help=(
            "逐事件失败隔离：单条证明失败转成 proof_status=failed 的报告行，"
            "不阻断后续校验、归因与报告生成，检查点照常推进。"
            "默认关闭（严格模式）：首个证明失败即以非零码退出，不写报告、"
            "不推进检查点。"
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        run(
            args.input,
            args.checkpoint,
            args.output,
            tolerate_failures=args.tolerate_failures,
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
