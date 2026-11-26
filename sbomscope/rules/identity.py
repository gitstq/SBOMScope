"""组件身份类规则：名称、版本、PURL、重复组件。"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import List

from ..models import Component, Severity
from .base import Rule, RuleContext, register

# PURL 已知类型（参考 purl-spec）
PURL_TYPES = {
    "npm", "maven", "pypi", "golang", "cargo", "gem", "nuget", "deb", "rpm",
    "apk", "composer", "generic", "github", "gitlab", "bitbucket", "oci",
    "docker", "swift", "cocoapods", "crates", "hex", "pub", "conan", "hackage",
}
PURL_RE = re.compile(r"^pkg:([a-z0-9.+-]+)/([^@?#]+)(?:@([^?#]+))?(?:\?[^#]*)?(?:#.*)?$")


@register
class MissingNameRule(Rule):
    rule_id = "SBOM-ID-001"
    title = "组件缺少名称"
    description = "每个组件必须声明 name。"

    def check(self, ctx: RuleContext) -> List:
        return [
            self.finding(Severity.ERROR, "组件缺少名称，无法唯一标识。",
                         component=c.identity, field="name",
                         remediation="为组件补充 name 字段。")
            for c in ctx.sbom.components if not c.name.strip()
        ]


@register
class MissingVersionRule(Rule):
    rule_id = "SBOM-ID-002"
    title = "组件缺少版本号"
    description = "组件应声明明确版本以支持可复现构建。"

    def check(self, ctx: RuleContext) -> List:
        findings = []
        for c in ctx.sbom.components:
            if c.name.strip() and not c.version.strip():
                findings.append(self.finding(
                    Severity.WARNING,
                    f"组件 {c.name} 缺少版本号。",
                    component=c.identity, field="version",
                    remediation="补充 version 字段，建议使用语义化版本。",
                ))
        return findings


@register
class MissingPurlRule(Rule):
    rule_id = "SBOM-ID-003"
    title = "组件缺少 PURL"
    description = "缺少 Package URL 将削弱跨工具互操作性。"

    def check(self, ctx: RuleContext) -> List:
        return [
            self.finding(Severity.WARNING,
                         f"组件 {c.name} 缺少 PURL 标识。",
                         component=c.identity, field="purl",
                         remediation="添加 package-url 外部引用（SPDX）或 purl 字段（CycloneDX）。")
            for c in ctx.sbom.components if c.name.strip() and not c.purl.strip()
        ]


@register
class MalformedPurlRule(Rule):
    rule_id = "SBOM-ID-004"
    title = "PURL 格式不合法"
    description = "PURL 应符合 pkg:type/name@version 语法。"

    def check(self, ctx: RuleContext) -> List:
        findings = []
        for c in ctx.sbom.components:
            if not c.purl.strip():
                continue
            m = PURL_RE.match(c.purl.strip())
            if not m:
                findings.append(self.finding(
                    Severity.ERROR, f"PURL 无法解析：{c.purl}",
                    component=c.identity, field="purl",
                    remediation="修正为 pkg:<type>/<name>@<version> 形式。",
                ))
            elif m.group(1).lower() not in PURL_TYPES:
                findings.append(self.finding(
                    Severity.WARNING, f"PURL 使用了未知类型：{m.group(1)}",
                    component=c.identity, field="purl",
                    remediation="使用标准 PURL 类型，或补充自定义类型到白名单。",
                ))
        return findings


@register
class DuplicateComponentRule(Rule):
    rule_id = "SBOM-ID-005"
    title = "检测到重复组件"
    description = "同一 identity 出现多次会扭曲依赖分析。"

    def check(self, ctx: RuleContext) -> List:
        seen: dict = defaultdict(int)
        for c in ctx.sbom.components:
            seen[c.identity] += 1
        return [
            self.finding(Severity.WARNING,
                         f"组件 {identity} 出现 {count} 次。",
                         component=identity, field="identity",
                         remediation="合并重复条目或消除版本冲突。")
            for identity, count in sorted(seen.items()) if count > 1
        ]
