"""SPDX 2.x / 3.0 JSON 解析器（纯标准库实现）。

参考 SPDX 2.3 规范：packages[].licenseConcluded / licenseDeclared /
externalRefs[PURL] / checksums / supplier / originator。
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..models import Component, Document, SBOM


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _licenses_from_package(pkg: Dict[str, Any]) -> List[str]:
    """收集许可证：优先 declared，其次 concluded，去重保序。"""
    out: List[str] = []
    for key in ("licenseDeclared", "licenseConcluded"):
        val = pkg.get(key)
        if isinstance(val, str) and val and val not in out:
            out.append(val)
    for lic in _as_list(pkg.get("licenseInfoFromFiles")):
        if isinstance(lic, str) and lic and lic not in out:
            out.append(lic)
    return out


def _supplier(pkg: Dict[str, Any]) -> str:
    """supplier 优先于 originator；去掉 'Organization:'/'Person:' 前缀。"""
    raw = pkg.get("supplier") or pkg.get("originator") or ""
    if not isinstance(raw, str):
        return ""
    for prefix in ("Organization: ", "Person: "):
        if raw.startswith(prefix):
            return raw[len(prefix):]
    return "NOASSERTION" if raw == "NOASSERTION" else raw


def _purl(pkg: Dict[str, Any]) -> str:
    for ref in _as_list(pkg.get("externalRefs")):
        if not isinstance(ref, dict):
            continue
        if str(ref.get("referenceType", "")).upper() == "PURL":
            return str(ref.get("referenceLocator", ""))
    return ""


def _hashes(pkg: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for chk in _as_list(pkg.get("checksums")):
        if not isinstance(chk, dict):
            continue
        alg = str(chk.get("algorithm", ""))
        val = str(chk.get("checksumValue", ""))
        if alg and val:
            out[alg] = val
    return out


def parse_spdx(data: Dict[str, Any]) -> SBOM:
    """将 SPDX JSON 文档解析为统一 SBOM 模型。"""
    doc = Document(
        format="spdx",
        spec_version=str(data.get("spdxVersion", "")),
        name=str(data.get("name", "")),
        version=str(data.get("dataLicense", "")),
        serial_number=str(data.get("SPDXID", "")),
        created=str(data.get("created", "")),
    )

    for creator in _as_list(data.get("creators")):
        if isinstance(creator, str) and creator:
            doc.creators.append(creator)

    tools = _as_list(data.get("tool"))
    for tool in tools:
        if isinstance(tool, str) and tool:
            doc.tools.append(tool)

    components: List[Component] = []
    for pkg in _as_list(data.get("packages")):
        if not isinstance(pkg, dict):
            continue
        components.append(
            Component(
                name=str(pkg.get("name", "")),
                version=str(pkg.get("versionInfo", "")),
                purl=_purl(pkg),
                supplier=_supplier(pkg),
                licenses=_licenses_from_package(pkg),
                copyright=str(pkg.get("copyrightText", "")),
                hashes=_hashes(pkg),
                bom_ref=str(pkg.get("SPDXID", "")),
                source_format="spdx",
                extra={
                    "downloadLocation": str(pkg.get("downloadLocation", "")),
                    "filesAnalyzed": pkg.get("filesAnalyzed"),
                },
            )
        )

    # SPDX 依赖关系：relationshipType 形如 DEPENDS_ON
    for rel in _as_list(data.get("relationships")):
        if not isinstance(rel, dict):
            continue
        try:
            a = str(rel.get("spdxElementId", ""))
            rel_type = str(rel.get("relationshipType", ""))
            related = rel.get("relatedSpdxElement", "")
            b = related[0] if isinstance(related, list) and related else str(related)
        except Exception:  # pragma: no cover - 防御性
            continue
        if a and rel_type.upper() == "DEPENDS_ON" and b:
            doc.dependencies.setdefault(a, []).append(b)

    return SBOM(document=doc, components=components, raw=data)
