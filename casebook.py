#!/usr/bin/env python3
"""Relatório local e auditável de candidatos com posições no arquivo-fonte."""
from __future__ import annotations
import argparse
import contextlib
import json
import sys
from collections import Counter
from osint_regex import PATTERNS, _normalize

def valid_record(record: object) -> bool:
    if not isinstance(record, dict):
        return False
    kind, value = record.get("type"), record.get("value")
    return (
        isinstance(kind, str) and kind in PATTERNS
        and isinstance(value, str) and len(value) <= 2048
        and PATTERNS[kind].fullmatch(value) is not None
        and _normalize(kind, value) == value
        and isinstance(record.get("source"), str)
        and len(record["source"]) <= 1024
        and type(record.get("line")) is int and record["line"] > 0
        and type(record.get("column")) is int and record["column"] > 0
    )

def build_casebook(records: list[dict]) -> dict:
    grouped, seen = {}, set()
    for record in records:
        if not valid_record(record):
            continue
        key = (record["type"], record["value"])
        pos = (record["source"], record["line"], record["column"])
        if (key, pos) in seen:
            continue
        seen.add((key, pos))
        if key not in grouped:
            grouped[key] = {"type": key[0], "value": key[1], "count": 0,
                            "evidence": []}
        grouped[key]["count"] += 1
        grouped[key]["evidence"].append(
            {"source": pos[0], "line": pos[1], "column": pos[2]}
        )
    entries = sorted(grouped.values(), key=lambda x: (x["type"], x["value"]))
    counts = Counter()
    for entry in entries:
        counts[entry["type"]] += entry["count"]
    return {
        "schema_version": "1.0",
        "classification": "unverified_candidates_not_threat_attribution",
        "summary": {"unique_candidates": len(entries),
                    "occurrences": len(seen), "by_type": dict(sorted(counts.items()))},
        "candidates": entries,
    }

def as_markdown(book: dict) -> str:
    def clean(value):
        return (str(value).replace("|", "\\|").replace(chr(96), "'")
                .replace("\n", " ").replace("\r", " "))
    s = book["summary"]
    lines = ["# Casebook OSINT: resultados preliminares", "",
             "**São candidatos não verificados; não inferir malícia ou autoria.**",
             "", f"Ocorrências: {s['occurrences']}. Valores únicos: {s['unique_candidates']}.",
             "", "| Tipo | Valor | Ocorrências | Origem (linha:coluna) |",
             "|---|---|---:|---|"]
    for entry in book["candidates"]:
        origins = ", ".join(
            f"{clean(x['source'])}:{x['line']}:{x['column']}"
            for x in entry["evidence"]
        )
        lines.append(f"| {clean(entry['type'])} | {clean(entry['value'])} | "
                     f"{entry['count']} | {origins} |")
    return "\n".join(lines) + "\n"

def main(argv=None):
    parser = argparse.ArgumentParser(description="Casebook local de achados OSINT.")
    parser.add_argument("files", nargs="*", help="JSONL do extrator ou - para stdin")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--max-records", type=int, default=10000)
    parser.add_argument("--max-line-length", type=int, default=50000)
    args = parser.parse_args(argv)
    if args.max_records < 1 or args.max_line_length < 1:
        parser.error("Limites devem ser positivos.")
    records, invalid = [], 0
    try:
        for path in args.files or ["-"]:
            stream = (contextlib.nullcontext(sys.stdin) if path == "-"
                      else open(path, encoding="utf-8", errors="replace"))
            with stream as handle:
                for line in handle:
                    if len(line) > args.max_line_length:
                        invalid += 1
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        invalid += 1
                        continue
                    if valid_record(record):
                        records.append(record)
                    else:
                        invalid += 1
                    if len(records) >= args.max_records:
                        print("AVISO: limite de registros atingido", file=sys.stderr)
                        break
            if len(records) >= args.max_records:
                break
    except OSError as error:
        print(f"ERRO: {error}", file=sys.stderr)
        return 2
    book = build_casebook(records)
    print(as_markdown(book) if args.format == "markdown" else
          json.dumps(book, ensure_ascii=False, indent=2, sort_keys=True), end="\n")
    if invalid:
        print(f"AVISO: {invalid} registros inválidos/ignorados", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
