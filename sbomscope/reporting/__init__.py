"""报告渲染器包。"""

from typing import Callable, Dict

from ..models import AuditResult
from . import annotations as _annotations
from . import json_report as _json_report
from . import sarif as _sarif
from . import text as _text

RENDERERS: Dict[str, Callable[[AuditResult], str]] = {
    "text": _text.render,
    "json": _json_report.render,
    "sarif": _sarif.render,
    "github": _annotations.render,
    "annotations": _annotations.render,
}


def render(result: AuditResult, fmt: str = "text") -> str:
    """按格式渲染审计报告。"""
    key = fmt.lower()
    if key not in RENDERERS:
        raise ValueError(f"未知报告格式：{fmt}。可选：{', '.join(sorted(RENDERERS))}")
    return RENDERERS[key](result)


__all__ = ["render", "RENDERERS", "_text", "_json_report", "_sarif", "_annotations"]
