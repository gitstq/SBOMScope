"""SBOMScope — 零依赖、离线优先的 SBOM 解析与合规审计引擎。

支持 SPDX 2.x/3.0 与 CycloneDX 1.x，提供统一模型、确定性规则引擎
以及 text / JSON / SARIF / GitHub 注解等多种报告格式。

Public API:
    >>> from sbomscope import audit_sbom, AuditEngine, load_sbom
    >>> result = audit_sbom(sbom_dict)
    >>> result.score.passed
"""

from __future__ import annotations

from .engine import AuditEngine, audit_sbom, load_policy, load_sbom
from .models import AuditResult, Component, Document, Finding, SBOM, Score, Severity
from .parsers import parse as parse_sbom
from .reporting import render as render_report

__version__ = "1.0.0"
__author__ = "gitstq"
__license__ = "MIT"

__all__ = [
    "__version__",
    "AuditEngine",
    "audit_sbom",
    "load_policy",
    "load_sbom",
    "parse_sbom",
    "render_report",
    "AuditResult",
    "Component",
    "Document",
    "Finding",
    "SBOM",
    "Score",
    "Severity",
]
