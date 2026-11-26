"""SBOMScope 命令行入口（argparse，零依赖）。"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .engine import AuditEngine, audit_sbom, load_policy, load_sbom
from .exceptions import PolicyError, SBOMScopeError
from .models import AuditResult
from .parsers import parse
from .reporting import render as render_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbomscope",
        description="Zero-dependency offline SBOM parsing & compliance audit engine.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"sbomscope {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # audit
    p_audit = sub.add_parser("audit", help="审计 SBOM 并生成报告")
    p_audit.add_argument("path", help="SBOM JSON 文件路径，使用 - 表示标准输入")
    p_audit.add_argument("-f", "--format", default="text",
                         choices=["text", "json", "sarif", "github", "annotations"],
                         help="报告格式（默认 text）")
    p_audit.add_argument("-p", "--policy", help="策略文件路径（JSON）")
    p_audit.add_argument("--fmt", dest="sbom_format",
                         help="强制指定 SBOM 格式（spdx / cyclonedx），默认自动检测")
    p_audit.add_argument("-o", "--output", help="报告输出文件，默认标准输出")
    p_audit.add_argument("--fail-on", default="error", choices=["error", "warning", "none"],
                         help="退出码失败阈值（默认 error）")

    # normalize
    p_norm = sub.add_parser("normalize", help="将 SBOM 归一化成统一结构")
    p_norm.add_argument("path", help="SBOM JSON 文件路径，使用 - 表示标准输入")
    p_norm.add_argument("--fmt", dest="sbom_format", help="强制指定 SBOM 格式")
    p_norm.add_argument("-o", "--output", help="输出文件，默认标准输出")

    # rules
    p_rules = sub.add_parser("rules", help="列出所有内置审计规则")
    p_rules.add_argument("-f", "--format", default="text", choices=["text", "json"])

    # detect
    p_det = sub.add_parser("detect", help="自动检测 SBOM 格式")
    p_det.add_argument("path", help="SBOM JSON 文件路径，使用 - 表示标准输入")

    return parser


def _write(content: str, output: Optional[str]) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(content)
    else:
        sys.stdout.write(content)


def _exit_code(result: AuditResult, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    score = result.score
    if fail_on == "error":
        return 1 if score.errors else 0
    return 1 if (score.errors or score.warnings) else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    try:
        if args.command == "audit":
            engine = AuditEngine(load_policy(args.policy))
            sbom = load_sbom(args.path, fmt=args.sbom_format)
            result = engine.audit(sbom)
            _write(render_report(result, args.format), args.output)
            return _exit_code(result, args.fail_on)

        if args.command == "normalize":
            sbom = load_sbom(args.path, fmt=args.sbom_format)
            payload = sbom.to_dict()
            content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
            _write(content, args.output)
            return 0

        if args.command == "rules":
            from .rules import REGISTRY
            rules = sorted(
                [{"rule_id": c.rule_id, "title": c.title, "description": c.description}
                 for c in REGISTRY],
                key=lambda r: r["rule_id"],
            )
            if args.format == "json":
                _write(json.dumps(rules, ensure_ascii=False, indent=2) + "\n", None)
            else:
                for r in rules:
                    _write(f"{r['rule_id']}  {r['title']}\n    {r['description']}\n", None)
            return 0

        if args.command == "detect":
            sbom = load_sbom(args.path)
            _write(f"{sbom.document.format} {sbom.document.spec_version}\n", None)
            return 0

    except SBOMScopeError as exc:
        sys.stderr.write(f"sbomscope: error: {exc}\n")
        return 2
    except OSError as exc:
        sys.stderr.write(f"sbomscope: error: {exc}\n")
        return 2

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
