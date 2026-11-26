"""人类可读文本报告渲染器（无颜色依赖，纯 ASCII 标记）。"""

from __future__ import annotations

from ..models import AuditResult, Severity

MARKS = {
    Severity.ERROR: "X",
    Severity.WARNING: "!",
    Severity.INFO: "i",
}
LABELS = {
    Severity.ERROR: "ERROR",
    Severity.WARNING: "WARN",
    Severity.INFO: "INFO",
}


def render(result: AuditResult) -> str:
    """生成确定性文本报告。"""
    doc = result.sbom.document
    score = result.score
    lines: list = []
    lines.append("=" * 68)
    lines.append("  SBOMScope Audit Report")
    lines.append("=" * 68)
    lines.append(f"  Format     : {doc.format} {doc.spec_version}")
    lines.append(f"  Name       : {doc.name or '<unnamed>'}")
    lines.append(f"  Components : {len(result.sbom.components)}")
    lines.append(f"  Rules run  : {len(result.rules_run)}")
    lines.append("-" * 68)
    lines.append(
        f"  Score      : {score.value}/100   "
        f"ERROR={score.errors} WARN={score.warnings} INFO={score.infos}"
    )
    lines.append(f"  Verdict    : {'PASS' if score.passed else 'FAIL'}")
    lines.append("=" * 68)

    findings = result.sorted_findings()
    if not findings:
        lines.append("")
        lines.append("  No findings. Clean SBOM.")
    else:
        lines.append("")
        lines.append("  FINDINGS")
        lines.append("-" * 68)
        for f in findings:
            head = f"[{LABELS[f.severity]:<5}] {f.rule_id}  {f.title}"
            lines.append("  " + head)
            lines.append(f"        {f.message}")
            if f.component:
                lines.append(f"        component: {f.component}")
            if f.field:
                lines.append(f"        field    : {f.field}")
            if f.remediation:
                lines.append(f"        fix      : {f.remediation}")
            lines.append("")

    lines.append("=" * 68)
    return "\n".join(lines)
