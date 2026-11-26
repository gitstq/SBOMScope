<div align="center">

# 🎯 SBOMScope

**Zero-dependency, offline-first SBOM parsing and compliance audit engine**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · [English](README.en.md)

</div>

---

## 🎉 Introduction

Supply-chain security matters more than ever, yet existing SBOM tools are either bloated with dependencies or require a network connection to do their job. SBOMScope fills that gap: a **pure-Python-standard-library** audit engine that normalizes SPDX and CycloneDX documents into one unified model, then runs a deterministic rule set to check their compliance.

It takes a different stance from tools like Syft or Trivy — it **does not generate SBOMs and does not scan source code**. Instead it answers a single question: *you already have an SBOM — how trustworthy is it?* Missing licenses, MD5 hashes, malformed PURLs, dependencies pointing at nonexistent components — SBOMScope surfaces all of it, offline.

Three principles guide the design:

- **Zero dependencies** — the Python standard library only. Install it anywhere, run it anywhere, no network required.
- **Offline-first** — every check runs locally; your supply-chain data never leaves the machine.
- **Deterministic** — identical input and policy produce byte-for-byte identical results, making it a natural fit for CI gates.

## ✨ Features

- 🔍 **Dual-format support** — auto-detects SPDX 2.x/3.0 and CycloneDX 1.x JSON, with an override flag.
- 🧩 **Unified data model** — formats normalize into one component/document structure; rules and reporters stay decoupled.
- 📏 **19 built-in rules** — spanning identity, license compliance, hash integrity, and document completeness.
- 🧠 **License policy** — `allow_licenses` allowlist and `deny_licenses` denylist, with a built-in SPDX identifier and strong/weak copyleft knowledge base.
- 🔐 **Integrity checks** — detect missing hashes, weak algorithms (MD5/SHA-1), and invalid hex format or length.
- 📊 **Four report formats** — human-readable text, structured JSON, SARIF 2.1.0, and GitHub Actions annotations.
- 🎯 **CI-gate ready** — `--fail-on` controls exit codes; a 0–100 score drops straight into your pipeline.
- 🪶 **Zero-dependency & cross-platform** — pure stdlib, Python 3.8+, works on Linux / macOS / Windows.

## 🚀 Quick Start

No dependencies to install — clone and run:

```bash
git clone https://github.com/gitstq/SBOMScope.git
cd SBOMScope

# Audit an SBOM (text report)
python3 -m sbomscope audit examples/sample.cyclonedx.json

# Or install with pip and use the CLI
pip install .
sbomscope audit your-sbom.spdx.json -f text
```

A clean audit looks like this:

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

## 📖 Usage Guide

### Command line

```bash
# Audit: choose a report format and failure threshold
sbomscope audit sbom.json -f json -o report.json
sbomscope audit sbom.json -f sarif --fail-on warning
sbomscope audit sbom.json -f github          # GitHub Actions annotations

# Read from standard input
cat sbom.json | sbomscope audit - -f text

# Force a format (skip auto-detection)
sbomscope audit sbom.json --fmt spdx

# Normalize into the unified structure
sbomscope normalize sbom.json -o normalized.json

# Detect the format / list every rule
sbomscope detect sbom.json
sbomscope rules -f json
```

`--fail-on` accepts: `error` (default — exit 1 only on ERROR), `warning` (exit 1 on any WARN), `none` (always exit 0).

### Library integration

```python
from sbomscope import audit_sbom, render_report, AuditEngine

# Option 1: one-liner audit of a dict
result = audit_sbom(sbom_dict)
print(result.score.value, result.score.passed)

# Option 2: load a file with a custom policy
engine = AuditEngine({"deny_licenses": ["GPL-3.0-only"]})
result = engine.audit_file("sbom.json")
print(render_report(result, "sarif"))
```

### Policy file

```json
{
  "allow_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
  "deny_licenses": ["AGPL-3.0-only", "SSPL-1.0"]
}
```

Pass it with `sbomscope audit sbom.json -p policy.json`. See [`examples/policy.example.json`](examples/policy.example.json) for a full example.

### Rule catalog

| Category | Rule IDs | Covers |
| --- | --- | --- |
| Identity | `SBOM-ID-001~005` | name, version, PURL, PURL syntax, duplicate components |
| License | `SBOM-LIC-001~006` | missing, NOASSERTION, non-standard IDs, deprecated IDs, copyleft policy, allowlist |
| Integrity | `SBOM-INT-001~003` | missing hash, weak algorithm, malformed hash |
| Document | `SBOM-DOC-001~005` | empty doc, spec version, timestamp, supplier, dangling dependencies |

Run `sbomscope rules` for the complete list.

## 💡 Design & Iteration

- **v1.0.0** — first stable release. Established the four-layer architecture of *parse → normalize → rule engine → report*, with all 19 rules and four reporters shipped and 30 unit tests green.
- **Why a unified model**: SPDX uses `licenseDeclared`, CycloneDX uses `licenses[]`. If rules read raw documents, you write the logic twice. After normalization, rules only know the component model — adding a format means adding one parser.
- **Why deterministic**: an audit result destined for a CI gate must be reproducible. Every finding is sorted by *severity → rule → component → field → message*, score weights are fixed, and nothing touches timestamps or the network.
- **Why not generation**: SBOM generation is already well served by Syft and friends; rebuilding that wheel adds no value. SBOMScope focuses on the overlooked half — auditing — and does it thoroughly.
- **What's next**: drift comparison between two SBOMs, full SPDX 3.0 `elements` support, and a plugin mechanism for custom rules.

## 📦 Build & Deploy

```bash
# One-click build: test -> sdist + wheel -> checksums
bash scripts/build.sh

# Artifacts land in dist/:
#   sbomscope-1.0.0-py3-none-any.whl
#   sbomscope-1.0.0.tar.gz
```

Install and verify:

```bash
pip install dist/sbomscope-1.0.0-py3-none-any.whl
sbomscope --version
sha256sum dist/*
```

Being a pure-Python library, there is nothing to compile — the wheel installs on any platform.

## 🤝 Contributing

Issues and pull requests are welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Commits follow the Angular convention (e.g. `feat(rules): add new license rule`), and every new rule must come with unit tests. Make sure `python3 -m unittest discover -s tests -v` passes in full.

## 📄 License

Released under the [MIT License](LICENSE). Free to use, modify, and distribute. © 2026 gitstq
