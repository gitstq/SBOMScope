"""许可证类规则：缺失、NOASSERTION、非法标识符、copyleft 策略。"""

from __future__ import annotations

from typing import List

from .. import spdx_licenses as lic
from ..models import Severity
from .base import Rule, RuleContext, register


def _base_tokens(expression: str) -> List[str]:
    """将 SPDX 表达式拆为基础标识符（去掉 AND/OR/WITH/括号）。"""
    parts = expression.replace("(", " ").replace(")", " ").split()
    return [p for p in parts if p.upper() not in {"AND", "OR", "WITH"}]


@register
class MissingLicenseRule(Rule):
    rule_id = "SBOM-LIC-001"
    title = "组件缺少许可证声明"
    description = "每个组件都应声明许可证以明确合规义务。"

    def check(self, ctx: RuleContext) -> List:
        return [
            self.finding(Severity.ERROR,
                         f"组件 {c.name} 未声明任何许可证。",
                         component=c.identity, field="licenses",
                         remediation="补充 licenseDeclared / licenses 字段。")
            for c in ctx.sbom.components if not c.licenses
        ]


@register
class NoAssertionLicenseRule(Rule):
    rule_id = "SBOM-LIC-002"
    title = "许可证为 NOASSERTION / NONE"
    description = "笼统的 NOASSERTION 无法支持合规判定。"

    def check(self, ctx: RuleContext) -> List:
        findings = []
        for c in ctx.sbom.components:
            placeholders = [l for l in c.licenses if l.strip().upper() in {"NOASSERTION", "NONE"}]
            if placeholders and len(placeholders) == len(c.licenses):
                findings.append(self.finding(
                    Severity.WARNING,
                    f"组件 {c.name} 许可证为 {placeholders[0]}。",
                    component=c.identity, field="licenses",
                    remediation="人工核实并填写确切的 SPDX 许可证标识符。",
                ))
        return findings


@register
class InvalidLicenseRule(Rule):
    rule_id = "SBOM-LIC-003"
    title = "许可证标识符非标准"
    description = "使用非 SPDX 标识符将阻碍自动化合规。"

    def check(self, ctx: RuleContext) -> List:
        findings = []
        for c in ctx.sbom.components:
            for expression in c.licenses:
                if expression.strip().upper() in {"NOASSERTION", "NONE"}:
                    continue
                for token in _base_tokens(expression):
                    if not lic.is_known(token):
                        findings.append(self.finding(
                            Severity.WARNING,
                            f"组件 {c.name} 使用了非标准标识符：{token}。",
                            component=c.identity, field="licenses",
                            remediation="替换为标准 SPDX 标识符，或使用 LicenseRef- 前缀。",
                        ))
        return findings


@register
class DeprecatedLicenseRule(Rule):
    rule_id = "SBOM-LIC-004"
    title = "使用废弃的许可证标识符"
    description = "废弃标识符应使用 -only / -or-later 变体。"

    def check(self, ctx: RuleContext) -> List:
        findings = []
        for c in ctx.sbom.components:
            for expression in c.licenses:
                for token in _base_tokens(expression):
                    if token.upper() in {d.upper() for d in lic.DEPRECATED_IDENTIFIERS}:
                        findings.append(self.finding(
                            Severity.INFO,
                            f"组件 {c.name} 使用废弃标识符：{token}。",
                            component=c.identity, field="licenses",
                            remediation="迁移到 -only 或 -or-later 明确变体。",
                        ))
        return findings


@register
class CopyleftPolicyRule(Rule):
    rule_id = "SBOM-LIC-005"
    title = "命中 Copyleft 许可证策略"
    description = "强/弱 copyleft 组件需按策略审查。"

    def check(self, ctx: RuleContext) -> List:
        deny = {s.upper() for s in ctx.policy_list("deny_licenses")}
        findings = []
        for c in ctx.sbom.components:
            for expression in c.licenses:
                for token in _base_tokens(expression):
                    key = token.upper()
                    if key in deny:
                        findings.append(self.finding(
                            Severity.ERROR,
                            f"组件 {c.name} 命中策略黑名单许可证：{token}。",
                            component=c.identity, field="licenses",
                            remediation="评估替换组件或申请合规豁免。",
                        ))
                    elif key in {x.upper() for x in lic.STRONG_COPYLEFT}:
                        findings.append(self.finding(
                            Severity.WARNING,
                            f"组件 {c.name} 使用强 copyleft 许可证：{token}。",
                            component=c.identity, field="licenses",
                            remediation="确认分发合规义务（源码开放、传染性）。",
                        ))
        return findings


@register
class AllowlistPolicyRule(Rule):
    rule_id = "SBOM-LIC-006"
    title = "许可证不在允许清单"
    description = "当配置 allow_licenses 时，仅允许的标识符可通过。"

    def check(self, ctx: RuleContext) -> List:
        allow = {s.upper() for s in ctx.policy_list("allow_licenses")}
        if not allow:
            return []
        findings = []
        for c in ctx.sbom.components:
            for expression in c.licenses:
                for token in _base_tokens(expression):
                    if token.upper() not in allow:
                        findings.append(self.finding(
                            Severity.WARNING,
                            f"组件 {c.name} 的许可证 {token} 不在允许清单。",
                            component=c.identity, field="licenses",
                            remediation="确认许可证合规性或更新 allow_licenses 策略。",
                        ))
        return findings
