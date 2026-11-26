"""SPDX 许可证标识符参考集（子集，离线内置）。

仅内置常见标识符与废弃标识符，用于"可疑/非法许可证"检测，
不提供联网校验，保证完全离线与确定性。数据参考 SPDX License List 3.x。
"""

from __future__ import annotations

# 常见规范 SPDX 许可证标识符（大写精确匹配）
KNOWN_IDENTIFIERS = frozenset(
    {
        "0BSD",
        "AFL-3.0",
        "AGPL-1.0",
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "Apache-1.1",
        "Apache-2.0",
        "Artistic-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSD-4-Clause",
        "BSL-1.0",
        "CC-BY-3.0",
        "CC-BY-4.0",
        "CC-BY-SA-4.0",
        "CC0-1.0",
        "CDDL-1.0",
        "CDDL-1.1",
        "EPL-1.0",
        "EPL-2.0",
        "EUPL-1.2",
        "GPL-1.0",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MPL-1.1",
        "MPL-2.0",
        "MS-PL",
        "NOASSERTION",
        "NONE",
        "OFL-1.1",
        "OpenSSL",
        "PHP-3.0",
        "PostgreSQL",
        "Python-2.0",
        "Unlicense",
        "WTFPL",
        "Zlib",
        "ZPL-2.1",
    }
)

# 已知废弃（deprecated）标识符 —— audit 时给出警告
DEPRECATED_IDENTIFIERS = frozenset(
    {
        "GPL-1.0",
        "GPL-2.0",
        "GPL-3.0",
        "LGPL-2.1",
        "LGPL-3.0",
        "AGPL-1.0",
        "AGPL-3.0",
        "Apache-1.1",
        "BSD-4-Clause",
        "eCos-2.0",
        "StandardML-NJ",
        "bzip2-1.0.5",
        "bzip2-1.0.6",
    }
)

# 强 copyleft 许可证（策略默认告警）
STRONG_COPYLEFT = frozenset(
    {
        "AGPL-1.0",
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "GPL-1.0",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "SSPL-1.0",
    }
)

WEAK_COPYLEFT = frozenset(
    {
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-1.1",
        "MPL-2.0",
        "EPL-1.0",
        "EPL-2.0",
        "CDDL-1.0",
        "CDDL-1.1",
    }
)


def is_known(identifier: str) -> bool:
    """判断一个 SPDX 表达式中的基础标识符是否已知。"""
    token = identifier.strip()
    if token in {"NOASSERTION", "NONE"}:
        return True
    if token.startswith("LicenseRef-") or token.startswith("DocumentRef-"):
        return True
    # WITH 异常
    if " WITH " in token:
        left, right = token.split(" WITH ", 1)
        return is_known(left) and (
            right.strip().endswith("-exception") or right.strip() in KNOWN_IDENTIFIERS
        )
    # 复合表达式：AND / OR / 括号
    for op in (" AND ", " OR "):
        if op in token:
            return all(is_known(part.strip(" ()")) for part in token.split(op))
    return token in KNOWN_IDENTIFIERS
