# Contributing to SBOMScope

感谢你考虑为 SBOMScope 做贡献！本项目坚持**零依赖、离线优先、确定性**三大原则，贡献请遵守以下约定。

## 开发环境

- Python 3.8+（仅标准库，无需安装任何运行时依赖）
- 可选：`pip install -e ".[dev]"` 安装构建/发布工具

## 提交规范（Angular Convention）

提交信息格式：

```
<type>(<scope>): <subject>

<body>

<footer>
```

- `type`：`feat` / `fix` / `docs` / `refactor` / `test` / `chore` / `perf`
- `scope`：可选，如 `parser` / `rules` / `cli` / `reporting`
- `subject`：祈使句，不超过 72 字符，句尾不加句号

示例：

```
feat(rules): add SPDX 3.0 element relationship support
fix(parser): handle empty CycloneDX components array
docs: add Traditional Chinese README
```

## 新增规则

1. 在 `sbomscope/rules/` 中实现 `Rule` 子类并使用 `@register` 装饰；
2. 规则 ID 采用 `SBOM-<CLASS>-<NNN>` 格式，保持唯一；
3. **必须**在 `tests/test_sbomscope.py` 中补充对应用例；
4. 规则输出必须确定性（排序/去重），不得依赖网络或时间戳。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

要求：全量通过，覆盖率不低于现有水平。禁止提交半成品。

## Pull Request

- 一个 PR 只做一件事；
- 描述清楚动机、改动与验证方式；
- CI/自测全绿后才会合并。

## 行为准则

友善、尊重、就事论事。禁止提交任何含版权风险或闭源依赖的代码。
