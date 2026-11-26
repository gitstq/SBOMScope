"""GitHub Actions 注解格式渲染器。"""

from __future__ import annotations

from ..models import AuditResult, Severity


def _escape(value: str) -> str:
    """转义注解控制字符。"""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render(result: AuditResult) -> str:
    """输出 ::error/:warning/:notice 工作流命令。"""
    level = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "notice"}
    lines = []
    for f in result.sorted_findings():
        msg = _escape(f"{f.rule_id} {f.title}: {f.message}")
        lines.append(f"::{level[f.severity]}::{msg}")
    if not lines:
        lines.append("::notice::SBOMScope: no findings")
    return "\n".join(lines) + "\n"
