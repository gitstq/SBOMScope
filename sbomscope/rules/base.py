"""规则引擎基础设施：抽象规则、上下文与注册表。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from ..models import Finding, SBOM


class RuleContext:
    """规则执行上下文，携带 SBOM 与用户策略配置。"""

    def __init__(self, sbom: SBOM, policy: Dict[str, Any]) -> None:
        self.sbom = sbom
        self.policy = policy

    def policy_list(self, key: str) -> List[str]:
        """读取策略中的字符串列表，缺失返回空列表。"""
        value = self.policy.get(key, [])
        if not isinstance(value, list):
            return []
        return [str(v) for v in value]


class Rule(ABC):
    """单条审计规则的抽象基类。"""

    rule_id: str = "SBOM-000"
    title: str = "未命名规则"
    description: str = ""

    @abstractmethod
    def check(self, ctx: RuleContext) -> List[Finding]:
        """执行检查并返回发现项列表。"""
        raise NotImplementedError

    def finding(self, severity: Any, message: str, **kwargs: Any) -> Finding:
        """便捷构造 Findings。"""
        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            title=self.title,
            message=message,
            **kwargs,
        )


# 注册表：规则类按定义顺序执行，保证结果确定性
REGISTRY: List[type] = []


def register(cls: type) -> type:
    """装饰器：注册规则类。"""
    REGISTRY.append(cls)
    return cls


def all_rules() -> List[Rule]:
    """实例化全部已注册规则。"""
    return [cls() for cls in REGISTRY]
