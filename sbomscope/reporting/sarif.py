"""SARIF 2.1.0 报告渲染器，便于 CI/CD 平台集成。"""

from __future__ import annotations

import json

from ..models import AuditResult, Severity

SARIF_LEVEL = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}

# 规则元数据（从 Finding 反推，保持稳定 ruleId）
RULE_META: dict = {}


def render(result: AuditResult) -> str:
    """生成符合 SARIF 2.1.0 的结果对象。"""
    rules = []
    seen = set()
    results = []
    for f in result.sorted_findings():
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.title},
                "helpUri": "https://github.com/gitstq/SBOMScope#rules",
            })
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "properties": {
                "component": f.component,
                "field": f.field,
                "remediation": f.remediation,
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SBOMScope",
                    "version": _version(),
                    "informationUri": "https://github.com/gitstq/SBOMScope",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2) + "\n"


def _version() -> str:
    from .. import __version__
    return __version__
