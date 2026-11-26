"""审计引擎：加载策略 -> 解析 -> 执行规则 -> 汇总结果。"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .exceptions import ParseError, PolicyError
from .models import AuditResult, Finding, SBOM, Score, Severity
from .parsers import parse
from .rules import RuleContext, all_rules

DEFAULT_POLICY: Dict[str, Any] = {
    "allow_licenses": [],
    "deny_licenses": [],
}


def load_policy(path: Optional[str] = None) -> Dict[str, Any]:
    """加载策略文件；未提供或文件不存在时使用默认策略。"""
    if not path:
        return dict(DEFAULT_POLICY)
    if not os.path.isfile(path):
        raise PolicyError(f"策略文件不存在：{path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"策略文件解析失败：{exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("策略文件顶层必须是 JSON 对象。")
    policy = dict(DEFAULT_POLICY)
    policy.update(data)
    return policy


def load_sbom(path: str, fmt: Optional[str] = None) -> SBOM:
    """从文件或标准输入（-）加载 SBOM JSON。"""
    try:
        if path == "-":
            import sys
            data = json.load(sys.stdin)
        else:
            if not os.path.isfile(path):
                raise ParseError(f"文件不存在：{path}")
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ParseError(f"JSON 解析失败：{exc}", path) from exc
    except OSError as exc:
        raise ParseError(str(exc), path) from exc
    return parse(data, fmt=fmt)


class AuditEngine:
    """确定性审计引擎。相同输入 + 相同策略 => 完全相同输出。"""

    def __init__(self, policy: Optional[Dict[str, Any]] = None) -> None:
        self.policy = policy if policy is not None else dict(DEFAULT_POLICY)
        self.rules = all_rules()

    def audit(self, sbom: SBOM) -> AuditResult:
        ctx = RuleContext(sbom, self.policy)
        findings: List[Finding] = []
        rules_run: List[str] = []
        for rule in self.rules:
            rules_run.append(rule.rule_id)
            try:
                findings.extend(rule.check(ctx))
            except Exception as exc:  # 单规则失败不阻断其他规则
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    severity=Severity.ERROR,
                    title="规则执行异常",
                    message=f"规则 {rule.rule_id} 执行失败：{exc}",
                    remediation="请报告此问题，附上 SBOM 样本。",
                ))
        return AuditResult(
            sbom=sbom,
            findings=findings,
            score=Score(findings),
            rules_run=rules_run,
        )

    def audit_file(self, path: str, fmt: Optional[str] = None) -> AuditResult:
        return self.audit(load_sbom(path, fmt=fmt))


def audit_sbom(data: Dict[str, Any], policy_path: Optional[str] = None) -> AuditResult:
    """便捷 API：直接对字典进行审计。"""
    engine = AuditEngine(load_policy(policy_path))
    return engine.audit(parse(data))
