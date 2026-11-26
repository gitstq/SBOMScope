"""结构化 JSON 报告渲染器（确定性排序）。"""

from __future__ import annotations

import json

from ..models import AuditResult


def render(result: AuditResult) -> str:
    """输出可机器解析的审计结果。"""
    payload = result.to_dict()
    payload["tool"] = {"name": "SBOMScope", "version": _version()}
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _version() -> str:
    from .. import __version__
    return __version__
