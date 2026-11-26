"""SBOMScope 全量单元测试（标准库 unittest，零依赖）。"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_TESTS_DIR))
sys.path.insert(0, _TESTS_DIR)

from sbomscope import (  # noqa: E402
    AuditEngine,
    __version__,
    audit_sbom,
    parse_sbom,
    render_report,
)
from sbomscope.cli import main as cli_main  # noqa: E402
from sbomscope.detect import detect_format  # noqa: E402
from sbomscope.exceptions import ParseError, PolicyError, UnsupportedFormatError  # noqa: E402
from sbomscope.models import Severity  # noqa: E402
from sbomscope.rules import REGISTRY  # noqa: E402

from fixtures_spdx import (  # noqa: E402
    CDX_CLEAN,
    CDX_DIRTY,
    SPDX_CLEAN,
    SPDX_DIRTY,
)


class TestDetection(unittest.TestCase):
    def test_spdx(self):
        self.assertEqual(detect_format(SPDX_CLEAN), ("spdx", "SPDX-2.3"))

    def test_cyclonedx(self):
        self.assertEqual(detect_format(CDX_CLEAN)[0], "cyclonedx")

    def test_unknown(self):
        self.assertEqual(detect_format({"foo": 1}), ("unknown", ""))

    def test_non_dict(self):
        self.assertEqual(detect_format([]), ("unknown", ""))


class TestParsers(unittest.TestCase):
    def test_spdx_parse(self):
        sbom = parse_sbom(SPDX_CLEAN)
        self.assertEqual(sbom.document.format, "spdx")
        self.assertEqual(len(sbom.components), 1)
        c = sbom.components[0]
        self.assertEqual(c.name, "requests")
        self.assertEqual(c.version, "2.31.0")
        self.assertEqual(c.purl, "pkg:pypi/requests@2.31.0")
        self.assertEqual(c.supplier, "Python Software Foundation")
        self.assertEqual(c.licenses, ["Apache-2.0"])
        self.assertEqual(c.hashes["SHA256"], "a" * 64)
        self.assertEqual(c.identity, "pkg:pypi/requests@2.31.0")

    def test_cyclonedx_parse(self):
        sbom = parse_sbom(CDX_CLEAN)
        self.assertEqual(sbom.document.format, "cyclonedx")
        self.assertEqual(sbom.document.spec_version, "1.5")
        c = sbom.components[0]
        self.assertEqual(c.name, "lodash")
        self.assertEqual(c.licenses, ["MIT"])
        self.assertEqual(c.hashes["SHA-256"], "b" * 64)

    def test_unsupported(self):
        with self.assertRaises(UnsupportedFormatError):
            parse_sbom({"foo": 1})

    def test_to_dict_json_safe(self):
        sbom = parse_sbom(SPDX_CLEAN)
        self.assertIsInstance(json.dumps(sbom.to_dict()), str)


class TestEngine(unittest.TestCase):
    def test_clean_spdx_passes(self):
        result = audit_sbom(SPDX_CLEAN)
        self.assertTrue(result.score.passed, result.to_dict())
        self.assertEqual(result.score.errors, 0)

    def test_clean_cdx_passes(self):
        result = audit_sbom(CDX_CLEAN)
        self.assertTrue(result.score.passed, result.to_dict())

    def test_dirty_spdx_has_findings(self):
        result = audit_sbom(SPDX_DIRTY)
        self.assertFalse(result.score.passed)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("SBOM-LIC-002", rule_ids)   # NOASSERTION
        self.assertIn("SBOM-INT-001", rule_ids)   # missing hash for bar
        self.assertIn("SBOM-INT-002", rule_ids)   # MD5
        self.assertIn("SBOM-INT-003", rule_ids)   # malformed hash
        self.assertIn("SBOM-ID-004", rule_ids)    # malformed PURL
        self.assertIn("SBOM-LIC-005", rule_ids)   # GPL copyleft
        self.assertIn("SBOM-DOC-005", rule_ids)   # dangling dep

    def test_dirty_cdx_detects_issues(self):
        result = audit_sbom(CDX_DIRTY)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("SBOM-ID-005", rule_ids)    # duplicate
        self.assertIn("SBOM-LIC-003", rule_ids)   # non-standard license
        self.assertIn("SBOM-INT-002", rule_ids)   # SHA1

    def test_deterministic(self):
        a = audit_sbom(SPDX_DIRTY).to_dict()
        b = audit_sbom(SPDX_DIRTY).to_dict()
        self.assertEqual(a, b)

    def test_deny_policy(self):
        result = audit_sbom(SPDX_CLEAN, None)
        engine = AuditEngine({"deny_licenses": ["Apache-2.0"]})
        r2 = engine.audit(parse_sbom(SPDX_CLEAN))
        self.assertFalse(r2.score.passed)
        self.assertTrue(any(f.rule_id == "SBOM-LIC-005" for f in r2.findings))
        self.assertTrue(result.score.passed)

    def test_allow_policy(self):
        engine = AuditEngine({"allow_licenses": ["MIT"]})
        r = engine.audit(parse_sbom(SPDX_CLEAN))
        self.assertTrue(any(f.rule_id == "SBOM-LIC-006" for f in r.findings))

    def test_all_rules_registered(self):
        ids = [c.rule_id for c in REGISTRY]
        self.assertGreaterEqual(len(ids), 15)
        self.assertEqual(len(ids), len(set(ids)))


class TestReports(unittest.TestCase):
    def test_text(self):
        out = render_report(audit_sbom(SPDX_DIRTY), "text")
        self.assertIn("SBOMScope Audit Report", out)
        self.assertIn("Verdict", out)
        self.assertIn("SBOM-LIC-002", out)

    def test_json(self):
        out = render_report(audit_sbom(SPDX_DIRTY), "json")
        data = json.loads(out)
        self.assertEqual(data["tool"]["name"], "SBOMScope")
        self.assertIn("findings", data)

    def test_sarif(self):
        out = render_report(audit_sbom(SPDX_DIRTY), "sarif")
        data = json.loads(out)
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("runs", data)
        self.assertGreater(len(data["runs"][0]["results"]), 0)

    def test_github(self):
        out = render_report(audit_sbom(SPDX_DIRTY), "github")
        self.assertIn("::error::", out)

    def test_unknown_format(self):
        with self.assertRaises(ValueError):
            render_report(audit_sbom(SPDX_CLEAN), "xml")


class TestCLI(unittest.TestCase):
    def test_version(self):
        buf = io.StringIO()
        with redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            cli_main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_audit_text(self):
        path = os.path.join(os.path.dirname(__file__), "_tmp_spdx.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(SPDX_CLEAN, fh)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_main(["audit", path, "-f", "text"])
            self.assertEqual(code, 0)
            self.assertIn("PASS", buf.getvalue())
        finally:
            os.remove(path)

    def test_audit_json_fail_on_error(self):
        path = os.path.join(os.path.dirname(__file__), "_tmp_dirty.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(SPDX_DIRTY, fh)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_main(["audit", path, "-f", "json", "--fail-on", "error"])
            self.assertEqual(code, 1)
            json.loads(buf.getvalue())
        finally:
            os.remove(path)

    def test_detect(self):
        path = os.path.join(os.path.dirname(__file__), "_tmp_cdx.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(CDX_CLEAN, fh)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_main(["detect", path])
            self.assertEqual(code, 0)
            self.assertIn("cyclonedx", buf.getvalue())
        finally:
            os.remove(path)

    def test_rules(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(["rules", "-f", "json"])
        self.assertEqual(code, 0)
        self.assertGreater(len(json.loads(buf.getvalue())), 10)

    def test_missing_file(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(["audit", "/nonexistent/file.json"])
        self.assertEqual(code, 2)


class TestExceptions(unittest.TestCase):
    def test_parse_error(self):
        err = ParseError("bad", "file.json")
        self.assertIn("file.json", str(err))

    def test_policy_error(self):
        with self.assertRaises(PolicyError):
            from sbomscope.engine import load_policy
            load_policy("/nonexistent/policy.json")


class TestVersion(unittest.TestCase):
    def test_version_format(self):
        parts = __version__.split(".")
        self.assertEqual(len(parts), 3)
        self.assertTrue(all(p.isdigit() for p in parts))


if __name__ == "__main__":
    unittest.main(verbosity=2)
