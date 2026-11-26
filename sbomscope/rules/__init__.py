"""审计规则包：导入即完成注册。"""

from __future__ import annotations

from . import completeness, identity, integrity, license_policy  # noqa: F401
from .base import REGISTRY, Rule, RuleContext, all_rules, register

__all__ = ["Rule", "RuleContext", "REGISTRY", "all_rules", "register"]
