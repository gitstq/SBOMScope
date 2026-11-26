<div align="center">

# 🎯 SBOMScope

**零依赖 · 离线优先的软件物料清单（SBOM）解析与合规审计引擎**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

</div>

---

## 🎉 介绍

供应链安全越来越重要，但现有的 SBOM 工具要么体积庞大、依赖成堆，要么必须联网才能工作。SBOMScope 就是为了填补这个空白而生的：它是一个**纯 Python 标准库实现**的审计引擎，把 SPDX 与 CycloneDX 文档归一化成统一模型，再用一组确定性的规则做合规体检。

它和 Syft、Trivy 这类工具的定位不同——**不负责生成 SBOM，也不扫描源码**，而是专注于「你手上已经有一份 SBOM，它到底靠不靠谱？」这个问题。缺少许可证、哈希用了 MD5、PURL 写错了、依赖指向了不存在的组件……这些细节 SBOMScope 都能离线帮你揪出来。

设计上坚持三个原则：

- **零依赖**：只靠 Python 标准库，装得上、跑得动，不联网也没问题。
- **离线优先**：所有校验本地完成，绝不外传你的供应链数据。
- **确定性**：同样的输入和策略，永远得到一模一样的结果，天然适合 CI 门禁。

## ✨ 特性

- 🔍 **双格式支持** —— 自动识别 SPDX 2.x/3.0 与 CycloneDX 1.x JSON，也可强制指定格式。
- 🧩 **统一数据模型** —— 不同格式归一成同一套组件/文档结构，规则与报告完全解耦。
- 📏 **19 条内置规则** —— 覆盖身份标识、许可证合规、完整性哈希、文档完整性四大类。
- 🧠 **许可证策略** —— 支持 `allow_licenses` 白名单与 `deny_licenses` 黑名单，内置 SPDX 标识符与强/弱 copyleft 知识库。
- 🔐 **完整性校验** —— 检测缺失哈希、弱算法（MD5/SHA-1）以及哈希值的十六进制格式与长度。
- 📊 **四种报告格式** —— 可读文本、结构化 JSON、SARIF 2.1.0、GitHub Actions 注解，一条命令搞定。
- 🎯 **CI 门禁就绪** —— `--fail-on` 控制退出码，评分 0–100，可无缝接入流水线。
- 🪶 **零依赖 & 跨平台** —— 纯标准库，Python 3.8+，Linux / macOS / Windows 通吃。

## 🚀 快速开始

无需安装任何依赖，克隆即可运行：

```bash
git clone https://github.com/gitstq/SBOMScope.git
cd SBOMScope

# 审计一份 SBOM（文本报告）
python3 -m sbomscope audit examples/sample.cyclonedx.json

# 或者用 pip 安装后使用命令行
pip install .
sbomscope audit your-sbom.spdx.json -f text
```

一次干净的审计输出大致如下：

```text
====================================================================
  SBOMScope Audit Report
====================================================================
  Format     : cyclonedx 1.5
  Name       : demo-app
  Components : 1
  Rules run  : 19
--------------------------------------------------------------------
  Score      : 100/100   ERROR=0 WARN=0 INFO=0
  Verdict    : PASS
====================================================================
```

## 📖 使用指南

### 命令行

```bash
# 审计：指定报告格式与失败阈值
sbomscope audit sbom.json -f json -o report.json
sbomscope audit sbom.json -f sarif --fail-on warning
sbomscope audit sbom.json -f github          # GitHub Actions 注解

# 从标准输入读取
cat sbom.json | sbomscope audit - -f text

# 强制指定格式（跳过自动检测）
sbomscope audit sbom.json --fmt spdx

# 归一化成统一结构
sbomscope normalize sbom.json -o normalized.json

# 自动检测格式 / 列出所有规则
sbomscope detect sbom.json
sbomscope rules -f json
```

`--fail-on` 可选值：`error`（默认，有 ERROR 才返回 1）、`warning`（有 WARN 即返回 1）、`none`（始终返回 0）。

### 作为库集成

```python
from sbomscope import audit_sbom, render_report, AuditEngine

# 方式一：一行审计字典
result = audit_sbom(sbom_dict)
print(result.score.value, result.score.passed)

# 方式二：加载文件 + 自定义策略
engine = AuditEngine({"deny_licenses": ["GPL-3.0-only"]})
result = engine.audit_file("sbom.json")
print(render_report(result, "sarif"))
```

### 策略文件

```json
{
  "allow_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
  "deny_licenses": ["AGPL-3.0-only", "SSPL-1.0"]
}
```

使用时传入 `sbomscope audit sbom.json -p policy.json`，完整示例见 [`examples/policy.example.json`](examples/policy.example.json)。

### 规则一览

| 类别 | 规则 ID | 说明 |
| --- | --- | --- |
| 身份 | `SBOM-ID-001~005` | 名称、版本、PURL、PURL 语法、重复组件 |
| 许可证 | `SBOM-LIC-001~006` | 缺失、NOASSERTION、非标准标识符、废弃标识符、copyleft 策略、白名单 |
| 完整性 | `SBOM-INT-001~003` | 缺失哈希、弱算法、哈希格式非法 |
| 文档 | `SBOM-DOC-001~005` | 空文档、规范版本、生成时间、供应商、悬空依赖 |

运行 `sbomscope rules` 可查看完整列表。

## 💡 设计迭代

- **v1.0.0** —— 首个稳定版本。确立「解析 → 归一化 → 规则引擎 → 报告」四层架构，19 条规则与四种报告格式全部落地，30 个单元测试全绿。
- **为什么统一模型**：SPDX 用 `licenseDeclared`，CycloneDX 用 `licenses[]`；如果让规则直接读原始文档，就得写两套逻辑。归一化后规则只认组件模型，新增格式只需加一个解析器。
- **为什么确定性**：审计结果要能进 CI 门禁，就必须可复现。所有发现项按「级别 → 规则 → 组件 → 字段 → 消息」排序，评分权重固定，不涉及时间戳或网络。
- **为什么不做生成**：SBOM 生成已有 Syft 等成熟方案，重复造轮子没有价值。SBOMScope 专注「审计」这一被忽视的环节，把一件事做透。
- **后续方向**：SBOM 文件之间的漂移对比、SPDX 3.0 `elements` 完整支持、自定义规则的插件机制。

## 📦 打包部署

```bash
# 一键构建：自测 -> sdist + wheel -> 校验和
bash scripts/build.sh

# 产物位于 dist/：
#   sbomscope-1.0.0-py3-none-any.whl
#   sbomscope-1.0.0.tar.gz
```

安装与验证：

```bash
pip install dist/sbomscope-1.0.0-py3-none-any.whl
sbomscope --version
sha256sum dist/*
```

由于是纯 Python 库，无需编译，wheel 可在任意平台直接安装。

## 🤝 贡献

欢迎提交 Issue 与 Pull Request！请先阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。提交遵循 Angular 规范（如 `feat(rules): add new license rule`），新增规则必须附带单元测试。请确保 `python3 -m unittest discover -s tests -v` 全量通过。

## 📄 协议

本项目基于 [MIT License](LICENSE) 开源，可自由使用、修改与分发。© 2026 gitstq
