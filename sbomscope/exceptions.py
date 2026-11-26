"""SBOMScope 自定义异常集合。

所有异常均不依赖第三方库，便于离线环境精确定位失败原因。
"""

from __future__ import annotations


class SBOMScopeError(Exception):
    """SBOMScope 所有异常的基类。"""


class ParseError(SBOMScopeError):
    """SBOM 文档解析失败（格式无法识别、JSON 损坏等）。"""

    def __init__(self, message: str, path: str = "") -> None:
        self.path = path
        super().__init__(message if not path else f"{path}: {message}")


class UnsupportedFormatError(ParseError):
    """SBOM 格式或规范版本不受支持。"""


class PolicyError(SBOMScopeError):
    """策略文件缺失、语法错误或字段非法。"""


class ReportError(SBOMScopeError):
    """报告渲染失败。"""
