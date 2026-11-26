"""文档完整性类规则：规范版本、时间戳、组件数量、悬空依赖。"""

from __future__ import annotations

from typing import List

from ..models import Severity
from .base import Rule, RuleContext, register


@register
class EmptyDocumentRule(Rule):
    rule_id = "SBOM-DOC-001"
    title = "SBOM 不含任何组件"
    description = "空 SBOM 没有审计价值。"

    def check(self, ctx: RuleContext) -> List:
        if not ctx.sbom.components:
            return [self.finding(
                Severity.ERROR, "文档中未发现任何组件。", field="components",
                remediation="确认解析正确，或剔除空 SBOM 文件。",
            )]
        return []


@register
class MissingSpecVersionRule(Rule):
    rule_id = "SBOM-DOC-002"
    title = "缺少规范版本"
    description = "规范版本缺失会影响工具兼容性与追溯。"

    def check(self, ctx: RuleContext) -> List:
        if not ctx.sbom.document.spec_version:
            return [self.finding(
                Severity.WARNING, "文档未声明 specVersion / spdxVersion。",
                field="spec_version",
                remediation="在文档根部声明规范版本。",
            )]
        return []


@register
class MissingTimestampRule(Rule):
    rule_id = "SBOM-DOC-003"
    title = "缺少生成时间"
    description = "时间戳用于判定 SBOM 时效性。"

    def check(self, ctx: RuleContext) -> List:
        if not ctx.sbom.document.created:
            return [self.finding(
                Severity.INFO, "文档未声明生成时间。", field="created",
                remediation="补充 created / metadata.timestamp。",
            )]
        return []


@register
class MissingSupplierRule(Rule):
    rule_id = "SBOM-DOC-004"
    title = "组件缺少供应商"
    description = "供应商信息有助于供应链溯源。"

    def check(self, ctx: RuleContext) -> List:
        return [
            self.finding(Severity.INFO,
                         f"组件 {c.name} 未声明供应商。",
                         component=c.identity, field="supplier",
                         remediation="补充 supplier / publisher 信息。")
            for c in ctx.sbom.components
            if c.name.strip() and (not c.supplier.strip() or c.supplier.strip().upper() == "NOASSERTION")
        ]


@register
class DanglingDependencyRule(Rule):
    rule_id = "SBOM-DOC-005"
    title = "存在悬空依赖关系"
    description = "依赖引用了不存在的组件。"

    def check(self, ctx: RuleContext) -> List:
        known = {c.bom_ref for c in ctx.sbom.components if c.bom_ref}
        findings = []
        for src, targets in sorted(ctx.sbom.document.dependencies.items()):
            if src and src not in known:
                findings.append(self.finding(
                    Severity.WARNING, f"依赖源引用了未知组件：{src}。",
                    component=src, field="dependencies",
                    remediation="检查 bom-ref / SPDXID 是否一致。",
                ))
            for t in sorted(set(targets)):
                if t and t not in known:
                    findings.append(self.finding(
                        Severity.WARNING,
                        f"依赖目标引用了未知组件：{t}。",
                        component=src, field="dependencies",
                        remediation="检查依赖目标是否存在于 components。",
                    ))
        return findings
