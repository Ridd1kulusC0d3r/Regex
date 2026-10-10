"""Parser DNS, grafo de proveniencia e manifesto sem rede."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dns_osint import parse_record, build_graph
from evidence_manifest import file_evidence


class DNSOSINTTests(unittest.TestCase):
    def test_ipv4_ipv6(self):
        rec = parse_record("example.org. 300 IN A 192.0.2.4", "demo.zone", 2)
        self.assertEqual(rec["ttl"], 300)
        self.assertEqual(rec["owner"], "example.org")
        self.assertEqual(rec["line"], 2)
        self.assertEqual(parse_record("example.org. IN 300 AAAA 2001:db8::4")["value"],
                         "2001:db8::4")
        for text in ("example.org. IN A 999.2.2.2",
                     "example.org. IN AAAA 192.0.2.10"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_record(text)

    def test_mx_and_alias(self):
        rec = parse_record("example.org. 60 IN MX 10 mail.example.org.")
        self.assertEqual(rec["preference"], 10)
        self.assertEqual(rec["value"], "mail.example.org")
        self.assertEqual(parse_record("www.example.org. IN CNAME example.org.")["value"],
                         "example.org")

    def test_txt_privacy_and_dmarc(self):
        spf = parse_record('example.org. IN TXT "v=spf1 ip4:192.0.2.0/24 -all"')
        self.assertEqual(spf["policy"], "spf")
        dmarc = parse_record(
            '_dmarc.example.org. IN TXT "v=DMARC1; p=none; rua=mailto:reports@example.org"'
        )
        self.assertEqual(dmarc["policy"], "dmarc")
        txt = 'example.org. IN TXT "google-site-verification=secret-value"'
        self.assertIsNone(parse_record(txt))
        self.assertEqual(parse_record(txt, include_txt=True)["rrtype"], "TXT")
        with self.assertRaises(ValueError):
            parse_record('_dmarc.example.org. IN TXT "v=DMARC1; p=bogus"')

    def test_invalid(self):
        self.assertIsNone(parse_record("; comentario"))
        self.assertEqual(parse_record("example.org. IN A 192.0.2.4 ; nota")["value"],
                         "192.0.2.4")
        for text in ("$ORIGIN example.org.", "@ IN A 192.0.2.4",
                     "example.org. IN NS bad_domain.org.",
                     "example.org. IN MX 999999 mx.example.org.",
                     "example.org. 4294967296 IN A 192.0.2.4",
                     'example.org. IN TXT "sem fechar'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_record(text)

    def test_graph_evidence_and_no_cooccurrence(self):
        records = [
            parse_record("example.org. IN A 192.0.2.1", "z1", 1),
            parse_record("example.org. IN A 192.0.2.1", "z2", 3),
            parse_record("example.org. IN MX 10 mail.example.org.", "z1", 2),
            parse_record('example.org. IN TXT "v=spf1 -all"', "z1", 4)]
        graph = build_graph(records)
        self.assertEqual(graph["summary"]["edges"], 2)
        self.assertEqual(graph["summary"]["records_read"], 4)
        a = next(edge for edge in graph["edges"] if edge["relation"] == "dns_a")
        self.assertEqual(a["evidence"], [{"source": "z1", "line": 1},
                                         {"source": "z2", "line": 3}])
        self.assertEqual(a["target"], "ip:192.0.2.1")
        bad = build_graph([{"type": "dns_record", "rrtype": "A",
                            "owner": "example.org", "value": "999.1.2.3",
                            "source": "x", "line": 1}])
        self.assertEqual(bad["summary"]["edges"], 0)

    def test_cli_dns_pipeline(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "dns_osint.py"), "parse"],
            input="example.org. IN A 192.0.2.9\nexample.org. IN NS ns.example.org.\n",
            capture_output=True, text=True, check=True)
        self.assertEqual(len(result.stdout.splitlines()), 2)
        graph = subprocess.run(
            [sys.executable, str(ROOT / "dns_osint.py"), "graph"],
            input=result.stdout, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(graph.stdout)["summary"]["edges"], 2)


class EvidenceTests(unittest.TestCase):
    def test_hash_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "amostra.txt"
            file.write_bytes(b"sample")
            rec = file_evidence(file)
            self.assertEqual(rec["sha256"], hashlib.sha256(b"sample").hexdigest())
            self.assertEqual(rec["size_bytes"], 6)
            self.assertTrue(rec["mtime_utc"].endswith("Z"))

    def test_limits_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "amostra"
            file.write_bytes(b"abcdef")
            with self.assertRaises(ValueError):
                file_evidence(file, 2)
            link = Path(tmp) / "atalho"
            try:
                link.symlink_to(file)
            except (OSError, NotImplementedError):
                self.skipTest("symlink indisponivel")
            with self.assertRaises(ValueError):
                file_evidence(link)

    def test_cli_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "a"
            file.write_text("audit", encoding="utf-8")
            good = subprocess.run(
                [sys.executable, str(ROOT / "evidence_manifest.py"), str(file)],
                capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(good.stdout)["size_bytes"], 5)
            bad = subprocess.run(
                [sys.executable, str(ROOT / "evidence_manifest.py"),
                 "--max-size", "1", str(file)],
                capture_output=True, text=True)
            self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
