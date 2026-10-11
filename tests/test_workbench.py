"""Validação integrada do catálogo, dos SCOs STIX e do casebook."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pattern_catalog import CATALOG, validate_catalog
from stix_export import build_bundle, candidate
from casebook import build_casebook, as_markdown, valid_record
from osint_regex import extract

def rec(kind, value, source="report.txt", line=2, column=3):
    return {"type": kind, "value": value, "source": source,
            "line": line, "column": column, "raw": value}

class CatalogTests(unittest.TestCase):
    def test_all_examples_valid(self):
        self.assertEqual(validate_catalog(), [])
        self.assertEqual(len(CATALOG), 23)

    def test_catalog_json_search(self):
        p = subprocess.run(
            [sys.executable, str(ROOT / "pattern_catalog.py"),
             "--search", "fraqueza", "--json"],
            capture_output=True, text=True, check=True)
        self.assertTrue(any(x["type"] == "cwe" for x in json.loads(p.stdout)))

    def test_catalog_cli_check(self):
        p = subprocess.run(
            [sys.executable, str(ROOT / "pattern_catalog.py"), "--check"],
            capture_output=True, text=True, check=True)
        self.assertIn("23", p.stdout)

class StixTests(unittest.TestCase):
    def test_bundle_scos_only(self):
        b, evidence = build_bundle([
            rec("ipv4", "192.0.2.10"), rec("domain", "example.org"),
            rec("sha256", "a" * 64)])
        self.assertEqual(b["type"], "bundle")
        self.assertEqual({x["type"] for x in b["objects"]},
                         {"ipv4-addr", "domain-name", "file"})
        self.assertTrue(all(x["spec_version"] == "2.1" for x in b["objects"]))
        self.assertNotIn("indicator", [x["type"] for x in b["objects"]])
        self.assertEqual(b["objects"][2]["hashes"]["SHA-256"], "a" * 64)
        self.assertEqual(len(evidence), 3)

    def test_bundle_duplicate_positions(self):
        b, evidence = build_bundle([
            rec("ipv4", "192.0.2.1", line=1),
            rec("ipv4", "192.0.2.1", line=3)])
        self.assertEqual(len(b["objects"]), 1)
        self.assertEqual([p["line"] for p in evidence], [1, 3])

    def test_invalid_and_private_inputs(self):
        self.assertIsNone(candidate(rec("cve", "CVE-2024-12345")))
        self.assertIsNone(candidate(rec("ipv4", "999.1.2.3")))
        self.assertIsNone(candidate(rec("domain", "invalid_domain.org")))
        self.assertIsNone(candidate(rec("email", "test@example.org")))
        self.assertIsNotNone(candidate(rec("email", "test@example.org"), True))
        self.assertIsNone(candidate(rec("url", "https://example.org/x?token=abc")))
        self.assertIsNotNone(candidate(rec("url", "https://example.org/x?token=abc"), True))
        self.assertIsNotNone(candidate(rec("url", "https://example.org/x")))

    def test_cli_bundle_and_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            source, out = Path(temp) / "iocs.jsonl", Path(temp) / "evidence.jsonl"
            source.write_text("\n".join([
                json.dumps(rec("ipv4", "192.0.2.9", line=1)),
                json.dumps(rec("ipv4", "192.0.2.9", line=2)),
                json.dumps(rec("email", "test@example.org"))
            ]), encoding="utf-8")
            p = subprocess.run(
                [sys.executable, str(ROOT / "stix_export.py"), str(source),
                 "--provenance-out", str(out)],
                capture_output=True, text=True, check=True)
            self.assertEqual(len(json.loads(p.stdout)["objects"]), 1)
            self.assertEqual(len(out.read_text().splitlines()), 2)
            again = subprocess.run(
                [sys.executable, str(ROOT / "stix_export.py"), str(source),
                 "--provenance-out", str(out)],
                capture_output=True, text=True)
            self.assertEqual(again.returncode, 2)
            overwrite = subprocess.run(
                [sys.executable, str(ROOT / "stix_export.py"), str(source),
                 "--provenance-out", str(source)],
                capture_output=True, text=True)
            self.assertNotEqual(overwrite.returncode, 0)

class CasebookTests(unittest.TestCase):
    def test_group_counts_and_markdown(self):
        a = rec("ipv4", "192.0.2.8", line=1)
        report = build_casebook([a, a, rec("ipv4", "192.0.2.8", line=3),
                                 rec("cwe", "CWE-79")])
        self.assertEqual(report["summary"]["unique_candidates"], 2)
        self.assertEqual(report["summary"]["occurrences"], 3)
        self.assertEqual(report["summary"]["by_type"]["ipv4"], 2)
        self.assertIn("192.0.2.8", as_markdown(report))

    def test_validate_location_and_semantics(self):
        self.assertFalse(valid_record(rec("ipv4", "999.1.2.3")))
        self.assertFalse(valid_record(rec("ipv4", "192.0.2.8", line=True)))
        self.assertFalse(valid_record({"type": "cwe", "value": "CWE-79"}))

    def test_cli_report(self):
        p = subprocess.run(
            [sys.executable, str(ROOT / "casebook.py"), "--format", "markdown"],
            input=json.dumps(rec("cwe", "CWE-79")) + "\n",
            text=True, capture_output=True, check=True)
        self.assertIn("CWE-79", p.stdout)

class EndToEndTests(unittest.TestCase):
    def test_extract_to_report_and_stix(self):
        items = list(extract("CWE-79 e 192.0.2.10\nGHSA-2c3f-gh4j-5m6q",
                             source="amostra"))
        report = build_casebook(items)
        self.assertIn("ghsa", report["summary"]["by_type"])
        bundle, evidence = build_bundle(items)
        self.assertTrue(any(x["type"] == "ipv4-addr" for x in bundle["objects"]))
        self.assertTrue(evidence)

if __name__ == "__main__":
    unittest.main()
