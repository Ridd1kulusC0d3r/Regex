#!/usr/bin/env python3
"""Exporta JSONL para STIX 2.1 SCOs sem assumir malícia, atribuição ou DNS ativo."""
from __future__ import annotations
import argparse
import contextlib
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4
from osint_regex import PATTERNS, _normalize

SCO_TYPES = {
    "ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name",
    "url": "url", "email": "email-addr", "md5": "file", "sha1": "file",
    "sha256": "file", "sha512": "file",
}
HASH_KEYS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}

def candidate(record: object, include_sensitive: bool = False):
    """Aceita somente saída normalizada do extrator, de tipos SCO conhecidos."""
    if not isinstance(record, dict):
        return None
    kind, value = record.get("type"), record.get("value")
    if not isinstance(kind, str) or kind not in SCO_TYPES:
        return None
    if not isinstance(value, str) or len(value) > 2048:
        return None
    if PATTERNS[kind].fullmatch(value) is None or _normalize(kind, value) != value:
        return None
    if kind == "email" and not include_sensitive:
        return None
    if kind == "url" and not include_sensitive:
        parsed = urlsplit(value)
        if parsed.query or parsed.fragment:
            return None
    return kind, value

def build_bundle(records: list[dict], include_sensitive: bool = False):
    objects, evidence = [], []
    seen = {}
    for record in records:
        item = candidate(record, include_sensitive)
        if item is None:
            continue
        kind, value = item
        key = kind, value
        if key not in seen:
            stype = SCO_TYPES[kind]
            ident = f"{stype}--{uuid4()}"
            obj = {"type": stype, "spec_version": "2.1", "id": ident}
            if kind in HASH_KEYS:
                obj["hashes"] = {HASH_KEYS[kind]: value}
            else:
                obj["value"] = value
            objects.append(obj)
            seen[key] = ident
        if (isinstance(record.get("source"), str) and
                type(record.get("line")) is int and record["line"] > 0 and
                type(record.get("column")) is int and record["column"] > 0):
            evidence.append({"stix_ref": seen[key], "source": record["source"],
                             "line": record["line"], "column": record["column"]})
    return {"type": "bundle", "id": f"bundle--{uuid4()}", "objects": objects}, evidence

def main(argv=None):
    parser = argparse.ArgumentParser(description="Exporta SCOs STIX 2.1 para triagem offline.")
    parser.add_argument("files", nargs="*", help="JSONL de osint_regex.py ou -")
    parser.add_argument("--include-sensitive", action="store_true",
                        help="Permite emails e URLs com query/fragment.")
    parser.add_argument("--provenance-out", help="Arquivo novo com refs e posições.")
    parser.add_argument("--max-line-length", type=int, default=50000)
    parser.add_argument("--max-records", type=int, default=10000)
    args = parser.parse_args(argv)
    if args.max_line_length < 1 or args.max_records < 1:
        parser.error("Limites devem ser positivos.")
    if args.provenance_out:
        out = Path(args.provenance_out)
        if args.provenance_out == "-" or any(
                p != "-" and out.resolve() == Path(p).resolve() for p in args.files):
            parser.error("Proveniência exige caminho novo e distinto da entrada.")
    records, rejected = [], 0
    try:
        for file in args.files or ["-"]:
            stream = (contextlib.nullcontext(sys.stdin) if file == "-"
                      else open(file, encoding="utf-8", errors="replace"))
            with stream as handle:
                for line in handle:
                    if len(line) > args.max_line_length:
                        rejected += 1
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        rejected += 1
                        continue
                    if candidate(record, args.include_sensitive) is None:
                        rejected += 1
                        continue
                    records.append(record)
                    if len(records) >= args.max_records:
                        print("AVISO: limite de registros atingido", file=sys.stderr)
                        break
            if len(records) >= args.max_records:
                break
    except OSError as error:
        print(f"ERRO: {error}", file=sys.stderr)
        return 2
    bundle, evidence = build_bundle(records, args.include_sensitive)
    if not bundle["objects"]:
        print("ERRO: nenhum objeto exportável", file=sys.stderr)
        return 2
    if args.provenance_out:
        try:
            with open(args.provenance_out, "x", encoding="utf-8") as output:
                for item in evidence:
                    output.write(json.dumps(item, ensure_ascii=False) + "\n")
        except OSError as error:
            print(f"ERRO ao gravar proveniência: {error}", file=sys.stderr)
            return 2
    print(json.dumps(bundle, indent=2, ensure_ascii=False, sort_keys=True))
    print(f"Objetos exportados: {len(bundle['objects'])}; linhas descartadas: {rejected}",
          file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
