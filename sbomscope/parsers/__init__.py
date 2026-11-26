"""格式解析器包。"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..detect import detect_format
from ..exceptions import UnsupportedFormatError
from ..models import SBOM
from .cyclonedx import parse_cyclonedx
from .spdx import parse_spdx


def parse(data: Dict[str, Any], fmt: Optional[str] = None) -> SBOM:
    """根据数据自动检测（或强制指定）格式并解析为统一 SBOM 模型。"""
    detected, spec = detect_format(data)
    use = (fmt or detected).lower()
    if use in {"spdx", "spdx2", "spdx-2", "spdx3"}:
        return parse_spdx(data)
    if use in {"cyclonedx", "cdx"}:
        return parse_cyclonedx(data)
    raise UnsupportedFormatError(
        f"无法识别的 SBOM 格式（detected={detected!r}）。"
        "仅支持 SPDX 2.x/3.0 与 CycloneDX 1.x JSON。"
    )


__all__ = ["parse", "parse_spdx", "parse_cyclonedx"]
