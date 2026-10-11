#!/usr/bin/env python3
"""Catálogo pesquisável de padrões, verificado contra o extrator."""
import argparse
import json
import sys
from osint_regex import PATTERNS, extract

# Tipo, grupo, propósito, exemplo positivo e valor normalizado esperado.
SAMPLES = [
 ("url","infraestrutura","URL HTTP(S), pode conter tokens","hxxps[:]//portal[.]example.org/a","https://portal.example.org/a"),
 ("email","identidade","Email sintático, titularidade não verificada","analista@demo.example.org","analista@demo.example.org"),
 ("ipv4_cidr","infraestrutura","IPv4 com prefixo CIDR","192.0.2.8/24","192.0.2.8/24"),
 ("ipv4","infraestrutura","IPv4 validado","192.0.2.8","192.0.2.8"),
 ("ipv6","infraestrutura","IPv6 validado","2001:db8::1","2001:db8::1"),
 ("domain","infraestrutura","FQDN ASCII, sem resolução DNS","portal[.]example.org","portal.example.org"),
 ("sha512","artefatos","Hash de 128 hexadecimais","a"*128,"a"*128),
 ("stix_id","cti","Identificador STIX e UUID v4/v5","indicator--e2e1a340-4415-4ba8-9671-f7343fbf0836","indicator--e2e1a340-4415-4ba8-9671-f7343fbf0836"),
 ("doi","documentos","DOI sintático, não prova publicação","10.1000/292","10.1000/292"),
 ("sha256","artefatos","Hash de 64 hexadecimais","b"*64,"b"*64),
 ("sha1","artefatos","Hash de 40 hexadecimais","c"*40,"c"*40),
 ("md5","artefatos","Hash de 32 hexadecimais","d"*32,"d"*32),
 ("cwe","vulnerabilidades","Classe de fraqueza, sem consulta MITRE","CWE-79","CWE-79"),
 ("capec","vulnerabilidades","Padrão de ataque, sem consulta MITRE","CAPEC-123","CAPEC-123"),
 ("ghsa","vulnerabilidades","Alfabeto oficial GHSA, não valida advisory","GHSA-2c3f-gh4j-5m6q","GHSA-2c3f-gh4j-5m6q"),
 ("attack_group","cti","Identificador de grupo, não atribuição","G0016","G0016"),
 ("attack_software","cti","Identificador de software ATT&CK","S0154","S0154"),
 ("attack_mitigation","cti","Identificador de mitigação ATT&CK","M1036","M1036"),
 ("cve","vulnerabilidades","Identificador CVE, sem confirmar existência","CVE-2024-12345","CVE-2024-12345"),
 ("attack_technique","cti","Técnica ATT&CK, apenas sintaxe","T1059.001","T1059.001"),
 ("attack_tactic","cti","Tática ATT&CK, apenas sintaxe","TA0001","TA0001"),
 ("asn","infraestrutura","ASN numérico, delegação não verificada","AS64500","AS64500"),
 ("mac","infraestrutura","MAC sintático, dispositivo não verificado","00:11:22:aa:bb:cc","00:11:22:aa:bb:cc"),
]
CATALOG = {
    name: {"type": name, "category": group, "description": purpose,
           "example": example, "expected": expected,
           "regex_python": PATTERNS[name].pattern if name in PATTERNS else None,
           "validation": "regex_and_semantic_normalization"}
    for name, group, purpose, example, expected in SAMPLES
}

def validate_catalog():
    errors = []
    if set(CATALOG) != set(PATTERNS):
        errors.append("Descompasso: " + repr(sorted(set(CATALOG) ^ set(PATTERNS))))
    for kind in sorted(set(CATALOG) & set(PATTERNS)):
        entry = CATALOG[kind]
        hits = [item["value"] for item in extract(entry["example"], types={kind})]
        if entry["expected"] not in hits:
            errors.append(f"{kind}: expected {entry['expected']!r}, received {hits!r}")
    return errors

def main(argv=None):
    parser = argparse.ArgumentParser(description="Catalogo de regex OSINT, sem rede.")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--search")
    parser.add_argument("--group")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        errors = validate_catalog()
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
        print(f"Catálogo validado: {len(CATALOG)} padrões")
        return 0
    rows = sorted(CATALOG.values(), key=lambda row: (row["category"], row["type"]))
    if args.group:
        rows = [row for row in rows if row["category"] == args.group.casefold()]
    if args.search:
        q = args.search.casefold()
        rows = [row for row in rows if q in
                (row["type"] + " " + row["category"] + " " + row["description"]).casefold()]
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        for row in rows:
            print(f"{row['category']:<17} {row['type']:<20} {row['description']}")
            print("  ex.: " + row["example"])
            print("  re.: " + row["regex_python"])
    return 0

if __name__ == "__main__":
    sys.exit(main())
