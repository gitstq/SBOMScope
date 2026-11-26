"""统一数据模型。

无论输入是 SPDX 还是 CycloneDX，都会被归一化成这里的统一结构，
后续所有规则引擎与报告器只依赖这些模型，与具体格式解耦。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """问题严重级别。字符串枚举便于直接序列化到 JSON / SARIF。"""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def rank(self) -> int:
        """用于排序：ERROR 最高。"""
        return {"error": 0, "warning": 1, "info": 2}[self.value]


class Component:
    """归一化后的单个软件组件。"""

    __slots__ = (
        "name",
        "version",
        "purl",
        "supplier",
        "licenses",
        "copyright",
        "hashes",
        "bom_ref",
        "source_format",
        "extra",
    )

    def __init__(
        self,
        name: str = "",
        version: str = "",
        purl: str = "",
        supplier: str = "",
        licenses: Optional[List[str]] = None,
        copyright: str = "",
        hashes: Optional[Dict[str, str]] = None,
        bom_ref: str = "",
        source_format: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name or ""
        self.version = version or ""
        self.purl = purl or ""
        self.supplier = supplier or ""
        self.licenses: List[str] = list(licenses or [])
        self.copyright = copyright or ""
        self.hashes: Dict[str, str] = dict(hashes or {})
        self.bom_ref = bom_ref or ""
        self.source_format = source_format or ""
        self.extra: Dict[str, Any] = dict(extra or {})

    @property
    def identity(self) -> str:
        """稳定标识：优先 PURL，其次 name@version，最后 name。"""
        if self.purl:
            return self.purl
        if self.name and self.version:
            return f"{self.name}@{self.version}"
        return self.name or self.bom_ref or "<unknown>"

    def to_dict(self) -> Dict[str, Any]:
        """导出为可 JSON 序列化的字典（确定性字段顺序）。"""
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "supplier": self.supplier,
            "licenses": sorted(self.licenses),
            "copyright": self.copyright,
            "hashes": {k: self.hashes[k] for k in sorted(self.hashes)},
            "bom_ref": self.bom_ref,
            "source_format": self.source_format,
            "identity": self.identity,
        }


@dataclass
class Document:
    """归一化后的 SBOM 文档元数据。"""

    format: str = "unknown"          # spdx / cyclonedx
    spec_version: str = ""           # 例如 2.3 / 1.5
    name: str = ""
    version: str = ""
    serial_number: str = ""
    created: str = ""
    creators: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "spec_version": self.spec_version,
            "name": self.name,
            "version": self.version,
            "serial_number": self.serial_number,
            "created": self.created,
            "creators": sorted(self.creators),
            "tools": sorted(self.tools),
        }


@dataclass
class SBOM:
    """一份完整的归一化 SBOM。"""

    document: Document
    components: List[Component] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document": self.document.to_dict(),
            "components": [c.to_dict() for c in self.components],
        }


@dataclass(frozen=True)
class Finding:
    """规则引擎产出的一条审计发现。"""

    rule_id: str
    severity: Severity
    title: str
    message: str
    component: str = ""
    field: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "component": self.component,
            "field": self.field,
            "remediation": self.remediation,
        }

    def sort_key(self) -> tuple:
        """确定性排序键：级别 -> 规则 -> 组件 -> 消息。"""
        return (
            self.severity.rank,
            self.rule_id,
            self.component,
            self.field,
            self.message,
        )


class Score:
    """基于发现项的确定性评分（不依赖外部库）。"""

    WEIGHTS = {Severity.ERROR: 12, Severity.WARNING: 4, Severity.INFO: 1}
    PASS_THRESHOLD = 80

    def __init__(self, findings: List[Finding]) -> None:
        self.findings = findings
        self.errors = sum(1 for f in findings if f.severity == Severity.ERROR)
        self.warnings = sum(1 for f in findings if f.severity == Severity.WARNING)
        self.infos = sum(1 for f in findings if f.severity == Severity.INFO)
        penalty = sum(self.WEIGHTS[f.severity] for f in findings)
        self.value = max(0, 100 - penalty)
        self.passed = self.errors == 0 and self.value >= self.PASS_THRESHOLD

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.value,
            "passed": self.passed,
            "counts": {
                "error": self.errors,
                "warning": self.warnings,
                "info": self.infos,
                "total": len(self.findings),
            },
        }


@dataclass
class AuditResult:
    """一次完整审计的结果。"""

    sbom: SBOM
    findings: List[Finding]
    score: Score
    rules_run: List[str] = field(default_factory=list)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document": self.sbom.document.to_dict(),
            "summary": self.score.to_dict(),
            "rules_run": sorted(self.rules_run),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
