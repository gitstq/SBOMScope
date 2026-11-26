<div align="center">

# 🎯 SBOMScope

**零依賴 · 離線優先的軟體物料清單（SBOM）解析與合規稽核引擎**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

</div>

---

## 🎉 介紹

供應鏈安全日漸受到重視，然而現有的 SBOM 工具不是體積龐大、套件依賴成堆，就是得連上網路才能運作。SBOMScope 正是為了補上這塊缺口而生：它是一個**純 Python 標準庫實作**的稽核引擎，將 SPDX 與 CycloneDX 文件正規化為統一的資料模型，再透過一組確定性的規則進行合規健檢。

它與 Syft、Trivy 這類工具的定位不同——**不負責產生 SBOM，也不掃描原始碼**，而是專注在一個問題：「你手上這份 SBOM，到底可不可靠？」缺少授權、雜湊用了 MD5、PURL 寫錯、依賴指向不存在的元件……這些細節 SBOMScope 都能離線幫你揪出來。

設計上堅持三個原則：

- **零依賴**：只靠 Python 標準庫，裝得上、跑得動，沒有網路也沒問題。
- **離線優先**：所有驗證在本機完成，絕不對外傳送你的供應鏈資料。
- **確定性**：相同的輸入與策略，永遠得到一模一樣的結果，非常適合 CI 閘道。

## ✨ 特性

- 🔍 **雙格式支援** —— 自動辨識 SPDX 2.x/3.0 與 CycloneDX 1.x JSON，也可強制指定格式。
- 🧩 **統一資料模型** —— 不同格式正規化為同一套元件／文件結構，規則與報告完全解耦。
- 📏 **19 條內建規則** —— 涵蓋身份識別、授權合規、完整性雜湊、文件完整性四大類。
- 🧠 **授權策略** —— 支援 `allow_licenses` 白名單與 `deny_licenses` 黑名單，內建 SPDX 識別碼與強／弱 copyleft 知識庫。
- 🔐 **完整性驗證** —— 偵測缺少雜湊、弱演算法（MD5/SHA-1），以及雜湊值的十六進位格式與長度。
- 📊 **四種報告格式** —— 可讀文字、結構化 JSON、SARIF 2.1.0、GitHub Actions 註解，一個指令搞定。
- 🎯 **CI 閘道就緒** —— `--fail-on` 控制退出碼，評分 0–100，可無縫接入流水線。
- 🪶 **零依賴 & 跨平台** —— 純標準庫，Python 3.8+，Linux / macOS / Windows 都能用。

## 🚀 快速開始

無需安裝任何依賴，複製即可執行：

```bash
git clone https://github.com/gitstq/SBOMScope.git
cd SBOMScope

# 稽核一份 SBOM（文字報告）
python3 -m sbomscope audit examples/sample.cyclonedx.json

# 或用 pip 安裝後使用指令
pip install .
sbomscope audit your-sbom.spdx.json -f text
```

一次乾淨的稽核輸出大致如下：

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

### 命令列

```bash
# 稽核：指定報告格式與失敗閾值
sbomscope audit sbom.json -f json -o report.json
sbomscope audit sbom.json -f sarif --fail-on warning
sbomscope audit sbom.json -f github          # GitHub Actions 註解

# 從標準輸入讀取
cat sbom.json | sbomscope audit - -f text

# 強制指定格式（跳過自動偵測）
sbomscope audit sbom.json --fmt spdx

# 正規化為統一結構
sbomscope normalize sbom.json -o normalized.json

# 自動偵測格式／列出所有規則
sbomscope detect sbom.json
sbomscope rules -f json
```

`--fail-on` 可選值：`error`（預設，有 ERROR 才回傳 1）、`warning`（有 WARN 即回傳 1）、`none`（永遠回傳 0）。

### 作為函式庫整合

```python
from sbomscope import audit_sbom, render_report, AuditEngine

# 方式一：一行稽核字典
result = audit_sbom(sbom_dict)
print(result.score.value, result.score.passed)

# 方式二：載入檔案 + 自訂策略
engine = AuditEngine({"deny_licenses": ["GPL-3.0-only"]})
result = engine.audit_file("sbom.json")
print(render_report(result, "sarif"))
```

### 策略檔

```json
{
  "allow_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
  "deny_licenses": ["AGPL-3.0-only", "SSPL-1.0"]
}
```

使用時傳入 `sbomscope audit sbom.json -p policy.json`，完整範例見 [`examples/policy.example.json`](examples/policy.example.json)。

### 規則一覽

| 類別 | 規則 ID | 說明 |
| --- | --- | --- |
| 身份 | `SBOM-ID-001~005` | 名稱、版本、PURL、PURL 語法、重複元件 |
| 授權 | `SBOM-LIC-001~006` | 缺少、NOASSERTION、非標準識別碼、廢棄識別碼、copyleft 策略、白名單 |
| 完整性 | `SBOM-INT-001~003` | 缺少雜湊、弱演算法、雜湊格式非法 |
| 文件 | `SBOM-DOC-001~005` | 空文件、規範版本、產生時間、供應商、懸空依賴 |

執行 `sbomscope rules` 可查看完整清單。

## 💡 設計迭代

- **v1.0.0** —— 首個穩定版本。確立「解析 → 正規化 → 規則引擎 → 報告」四層架構，19 條規則與四種報告格式全部落地，30 個單元測試全數通過。
- **為何要統一模型**：SPDX 用 `licenseDeclared`，CycloneDX 用 `licenses[]`；若讓規則直接讀原始文件，就得寫兩套邏輯。正規化後規則只認元件模型，新增格式只需加一個解析器。
- **為何要確定性**：稽核結果要能進 CI 閘道，就必須可重現。所有發現項目按「層級 → 規則 → 元件 → 欄位 → 訊息」排序，評分權重固定，不涉及時間戳記或網路。
- **為何不做產生**：SBOM 產生已有 Syft 等成熟方案，重複造輪子沒有價值。SBOMScope 專注在「稽核」這個被忽略的環節，把一件事做透。
- **後續方向**：SBOM 檔案之間的漂移比對、SPDX 3.0 `elements` 完整支援、自訂規則的外掛機制。

## 📦 打包部署

```bash
# 一鍵構建：自測 -> sdist + wheel -> 檢查碼
bash scripts/build.sh

# 產物位於 dist/：
#   sbomscope-1.0.0-py3-none-any.whl
#   sbomscope-1.0.0.tar.gz
```

安裝與驗證：

```bash
pip install dist/sbomscope-1.0.0-py3-none-any.whl
sbomscope --version
sha256sum dist/*
```

由於是純 Python 函式庫，無需編譯，wheel 可在任意平台直接安裝。

## 🤝 貢獻

歡迎提交 Issue 與 Pull Request！請先閱讀 [`CONTRIBUTING.md`](CONTRIBUTING.md)。提交遵循 Angular 規範（如 `feat(rules): add new license rule`），新增規則必須附上單元測試。請確保 `python3 -m unittest discover -s tests -v` 全數通過。

## 📄 授權

本專案基於 [MIT License](LICENSE) 開源，可自由使用、修改與散發。© 2026 gitstq
