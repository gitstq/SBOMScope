"""完整性类规则：哈希缺失、弱算法、哈希值格式。"""

from __future__ import annotations

import re
from typing import List

from ..models import Severity
from .base import Rule, RuleContext, register

# 各哈希算法期望的十六进制长度
HASH_LENGTHS = {
    "MD5": 32,
    "SHA1": 40,
    "SHA-1": 40,
    "SHA256": 64,
    "SHA-256": 64,
    "SHA384": 96,
    "SHA-384": 96,
    "SHA512": 128,
    "SHA-512": 128,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
    "BLAKE3-256": 64,
}
WEAK_ALGOS = {"MD5", "SHA1", "SHA-1"}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@register
class MissingHashRule(Rule):
    rule_id = "SBOM-INT-001"
    title = "组件缺少哈希"
    description = "缺少哈希无法验证组件完整性。"

    def check(self, ctx: RuleContext) -> List:
        return [
            self.finding(Severity.WARNING,
                         f"组件 {c.name} 未提供任何哈希值。",
                         component=c.identity, field="hashes",
                         remediation="至少提供 SHA-256 哈希以校验完整性。")
            for c in ctx.sbom.components if not c.hashes
        ]


@register
class WeakHashRule(Rule):
    rule_id = "SBOM-INT-002"
    title = "使用弱哈希算法"
    description = "MD5 / SHA-1 已不适合作为完整性凭据。"

    def check(self, ctx: RuleContext) -> List:
        findings = []
        for c in ctx.sbom.components:
            weak = sorted(a for a in c.hashes if a.upper() in WEAK_ALGOS)
            if weak:
                findings.append(self.finding(
                    Severity.WARNING,
                    f"组件 {c.name} 使用弱哈希算法：{', '.join(weak)}。",
                    component=c.identity, field="hashes",
                    remediation="改用 SHA-256 或更强的哈希算法。",
                ))
        return findings


@register
class MalformedHashRule(Rule):
    rule_id = "SBOM-INT-003"
    title = "哈希值格式非法"
    description = "哈希值必须为十六进制且长度匹配算法。"

    def check(self, ctx: RuleContext) -> List:
        findings = []
        for c in ctx.sbom.components:
            for alg, value in sorted(c.hashes.items()):
                reasons = []
                if not HEX_RE.match(value):
                    reasons.append("包含非十六进制字符")
                expected = HASH_LENGTHS.get(alg.upper())
                if expected and len(value) != expected:
                    reasons.append(f"长度 {len(value)} != 期望 {expected}")
                if reasons:
                    findings.append(self.finding(
                        Severity.ERROR,
                        f"组件 {c.name} 的 {alg} 哈希非法：{'、'.join(reasons)}。",
                        component=c.identity, field=f"hashes.{alg}",
                        remediation="重新计算并填写正确的哈希值。",
                    ))
        return findings
