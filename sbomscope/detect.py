"""SBOM 格式自动检测。

仅依据文档结构与特征字段判断，不依赖文件名或扩展名。
"""

from __future__ import annotations

from typing import Any, Dict, Tuple


def detect_format(data: Any) -> Tuple[str, str]:
    """返回 (format, spec_version)。

    format 取值：spdx / cyclonedx / unknown
    无法识别时返回 unknown，由调用方决定是否抛错。
    """
    if not isinstance(data, dict):
        return "unknown", ""

    # SPDX 2.x JSON 典型字段
    if "spdxVersion" in data:
        return "spdx", str(data.get("spdxVersion", ""))
    if data.get("SPDXID") is not None and "packages" in data:
        return "spdx", str(data.get("spdxVersion", ""))

    # CycloneDX 1.x JSON 典型字段
    if "bomFormat" in data or "specVersion" in data:
        if str(data.get("bomFormat", "")).lower() == "cyclonedx" or "specVersion" in data:
            return "cyclonedx", str(data.get("specVersion", ""))

    # SPDX 3.0 使用 "@context" / "spdxVersion" 变体
    ctx = data.get("@context")
    if isinstance(ctx, (str, list, dict)) and ("packages" in data or "elements" in data):
        return "spdx", str(data.get("spdxVersion", "3.0"))

    return "unknown", ""
