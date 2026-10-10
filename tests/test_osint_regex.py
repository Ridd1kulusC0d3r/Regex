"""Testes sem rede e sem dependencias externas."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from osint_regex import PATTERNS, extract, extract_line  # noqa: E402


class ExtractorTests(unittest.TestCase):
    def hits(self, text, kind):
        return [item["value"] for item in extract(text) if item["type"] == kind]

    def test_network_indicators(self):
        text = "IPv4 198.51.100.7; IP ruim 999.1.2.3; v6 2001:db8::1; 198.51.100.7/24"
        self.assertIn("198.51.100.7", self.hits(text, "ipv4"))
        self.assertNotIn("999.1.2.3", self.hits(text, "ipv4"))
        self.assertIn("2001:db8::1", self.hits(text, "ipv6"))
        self.assertIn("198.51.100.7/24", self.hits(text, "ipv4_cidr"))

    def test_refang_without_fetching(self):
        text = "hxxps[:]//portal[.]example/path e 203[.]0[.]113[.]9 e mail@demo[.]example"
        self.assertIn("https://portal.example/path", self.hits(text, "url"))
        self.assertIn("203.0.113.9", self.hits(text, "ipv4"))
        self.assertIn("mail@demo.example", self.hits(text, "email"))

    def test_domain_validation(self):
        self.assertIn("sub.example.org", self.hits("sub.example.org", "domain"))
        self.assertNotIn("-bad.example.org", self.hits("-bad.example.org", "domain"))
        self.assertNotIn("abc..example", self.hits("abc..example", "domain"))

    def test_hashes_exact_length(self):
        self.assertEqual(self.hits("a" * 64, "sha256"), ["a" * 64])
        self.assertEqual(self.hits("b" * 40, "sha1"), ["b" * 40])
        self.assertEqual(self.hits("c" * 32, "md5"), ["c" * 32])
        self.assertEqual(self.hits("a" * 64, "md5"), [])
        self.assertEqual(self.hits("a" * 65, "sha256"), [])

    def test_cti_identifiers(self):
        txt = "CVE-2024-12345 T1059.001 TA0001 AS64500"
        self.assertEqual(self.hits(txt, "cve"), ["CVE-2024-12345"])
        self.assertEqual(self.hits(txt, "attack_technique"), ["T1059.001"])
        self.assertEqual(self.hits(txt, "attack_tactic"), ["TA0001"])
        self.assertEqual(self.hits(txt, "asn"), ["AS64500"])

    def test_invalid_urls_and_secrets(self):
        self.assertEqual(self.hits("https://user:pass@example.org", "url"), [])
        self.assertEqual(self.hits("https://not_a_valid_host", "url"), [])
        self.assertEqual(self.hits("https://example.org.", "url"), ["https://example.org"])

    def test_mac_and_evidence(self):
        match = extract_line("eth 00:11:22:AA:bb:cc", "caso.txt", 3)
        mac = next(item for item in match if item["type"] == "mac")
        self.assertEqual(mac["value"], "00:11:22:aa:bb:cc")
        self.assertEqual(mac["source"], "caso.txt")
        self.assertEqual(mac["line"], 3)
        self.assertEqual(mac["column"], 5)

    def test_all_patterns_compiled(self):
        self.assertGreaterEqual(len(PATTERNS), 12)

    def test_stix_doi_and_sha512(self):
        valid = "indicator--e2e1a340-4415-4ba8-9671-f7343fbf0836"
        self.assertEqual(self.hits(valid, "stix_id"), [valid])
        self.assertEqual(self.hits("other--e2e1a340-4415-4ba8-9671-f7343fbf0836", "stix_id"), [])
        self.assertEqual(self.hits("indicator--00000000-0000-0000-0000-000000000000", "stix_id"), [])
        self.assertEqual(self.hits("10.1000/292.", "doi"), ["10.1000/292"])
        self.assertEqual(self.hits("10.1000/", "doi"), [])
        self.assertEqual(self.hits("f" * 128, "sha512"), ["f" * 128])
        self.assertEqual(self.hits("f" * 127, "sha512"), [])

    def test_cli_jsonl_stdin(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "osint_regex.py"), "--types", "cve,sha256", "--unique"],
            input="CVE-2023-1234 CVE-2023-1234\n", text=True,
            capture_output=True, check=True
        )
        data = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["type"], "cve")
        self.assertEqual(data[0]["source"], "stdin")

    def test_cli_csv_and_invalid_type(self):
        csv_proc = subprocess.run(
            [sys.executable, str(ROOT / "osint_regex.py"), "--types", "ipv4", "--format", "csv"],
            input="192.0.2.20\n", text=True, capture_output=True, check=True
        )
        self.assertIn("192.0.2.20", csv_proc.stdout)
        invalid = subprocess.run(
            [sys.executable, str(ROOT / "osint_regex.py"), "--types", "banana"],
            input="", text=True, capture_output=True
        )
        self.assertNotEqual(invalid.returncode, 0)


if __name__ == "__main__":
    unittest.main()
