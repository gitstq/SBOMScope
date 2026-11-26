"""CycloneDX 1.x JSON 解析器（纯标准库实现）。

参考 CycloneDX 1.5 规范：components[]、metadata、hashes、licenses、
purl、supplier、externalReferences、dependencies。
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..models import Component, Document, SBOM


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _licenses(comp: Dict[str, Any]) -> List[str]:
    """提取 licenses 字段，支持 expression 与 license.id/name。"""
    out: List[str] = []
    expr = comp.get("licenses")
    for item in _as_list(expr):
        if isinstance(item, str) and item:
            if item not in out:
                out.append(item)
        elif isinstance(item, dict):
            if item.get("expression"):
                val = str(item["expression"])
            elif item.get("license"):
                lic = item["license"]
                if isinstance(lic, dict):
                    val = str(lic.get("id") or lic.get("name") or "")
                else:
                    val = str(lic)
            else:
                val = ""
            if val and val not in out:
                out.append(val)
    return out


def _hashes(comp: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in _as_list(comp.get("hashes")):
        if isinstance(h, dict):
            alg = str(h.get("alg", ""))
            val = str(h.get("content", ""))
            if alg and val:
                out[alg] = val
    return out


def _supplier(comp: Dict[str, Any]) -> str:
    sup = comp.get("supplier") or comp.get("publisher") or comp.get("author") or ""
    if isinstance(sup, dict):
        return str(sup.get("name", ""))
    return str(sup)


def parse_cyclonedx(data: Dict[str, Any]) -> SBOM:
    """将 CycloneDX JSON 文档解析为统一 SBOM 模型。"""
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    doc = Document(
        format="cyclonedx",
        spec_version=str(data.get("specVersion", "")),
        name=str((metadata.get("component") or {}).get("name", ""))
        if isinstance(metadata.get("component"), dict) else "",
        version=str((metadata.get("component") or {}).get("version", ""))
        if isinstance(metadata.get("component"), dict) else "",
        serial_number=str(data.get("serialNumber", "")),
        created=str(metadata.get("timestamp", "")),
    )

    # 工具与制造商
    for tool in _as_list((metadata.get("tools") or {}).get("components")
                         if isinstance(metadata.get("tools"), dict) else metadata.get("tools")):
        if isinstance(tool, dict) and tool.get("name"):
            doc.tools.append(str(tool["name"]))
        elif isinstance(tool, str) and tool:
            doc.tools.append(tool)
    if isinstance(metadata.get("manufacture"), dict):
        doc.creators.append(str(metadata["manufacture"].get("name", "")))

    components: List[Component] = []
    for comp in _as_list(data.get("components")):
        if not isinstance(comp, dict):
            continue
        components.append(
            Component(
                name=str(comp.get("name", "")),
                version=str(comp.get("version", "")),
                purl=str(comp.get("purl", "")),
                supplier=_supplier(comp),
                licenses=_licenses(comp),
                copyright=str(comp.get("copyright", "")),
                hashes=_hashes(comp),
                bom_ref=str(comp.get("bom-ref", "")),
                source_format="cyclonedx",
                extra={
                    "group": str(comp.get("group", "")),
                    "type": str(comp.get("type", "")),
                    "scope": str(comp.get("scope", "")),
                },
            )
        )

    for dep in _as_list(data.get("dependencies")):
        if not isinstance(dep, dict):
            continue
        ref = str(dep.get("ref", ""))
        depends = [str(x) for x in _as_list(dep.get("dependsOn")) if x]
        if ref:
            doc.dependencies.setdefault(ref, []).extend(depends)

    return SBOM(document=doc, components=components, raw=data)
