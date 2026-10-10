#!/usr/bin/env python3
"""Extrator local de indicadores para OSINT/CTI. Sem rede ou dependencias externas."""
from __future__ import annotations

import argparse
import contextlib
import csv
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit

# Regex identifica candidatos; funcoes _normalize validam a semantica.
PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"(?<![A-Za-z0-9])(?:hxxps?|https?)(?::|\[:\])//[^\s<>\"'\x60]{1,2048}", re.I),
    "email": re.compile(
        r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@"
        r"(?:[A-Za-z0-9-]{1,63}(?:\.|\[\.\]))+[A-Za-z]{2,24}"
        r"(?![A-Za-z0-9_-])", re.I
    ),
    "ipv4_cidr": re.compile(
        r"(?<![A-Za-z0-9.])(?:[0-9]{1,3}(?:\.|\[\.\])){3}[0-9]{1,3}/[0-9]{1,2}(?![A-Za-z0-9])"
    ),
    "ipv4": re.compile(
        r"(?<![A-Za-z0-9.])(?:[0-9]{1,3}(?:\.|\[\.\])){3}[0-9]{1,3}(?![A-Za-z0-9]|\.[0-9])"
    ),
    "ipv6": re.compile(
        r"(?<![A-Za-z0-9:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![A-Za-z0-9:])", re.I
    ),
    "domain": re.compile(
        r"(?<![A-Za-z0-9_.@-])(?:[A-Za-z0-9-]{1,63}(?:\.|\[\.\]))+"
        r"[A-Za-z]{2,24}(?![A-Za-z0-9_-])", re.I
    ),
    "sha256": re.compile(r"(?<![A-Za-z0-9])[a-f0-9]{64}(?![A-Za-z0-9])", re.I),
    "sha1": re.compile(r"(?<![A-Za-z0-9])[a-f0-9]{40}(?![A-Za-z0-9])", re.I),
    "md5": re.compile(r"(?<![A-Za-z0-9])[a-f0-9]{32}(?![A-Za-z0-9])", re.I),
    "cve": re.compile(r"(?<![A-Za-z0-9])CVE-[0-9]{4}-[0-9]{4,}(?![A-Za-z0-9])", re.I),
    "attack_technique": re.compile(
        r"(?<![A-Za-z0-9])T[0-9]{4}(?:\.[0-9]{3})?(?![A-Za-z0-9.])", re.I
    ),
    "attack_tactic": re.compile(r"(?<![A-Za-z0-9])TA[0-9]{4}(?![A-Za-z0-9])", re.I),
    "asn": re.compile(r"(?<![A-Za-z0-9])AS[0-9]{1,10}(?![A-Za-z0-9])", re.I),
    "mac": re.compile(
        r"(?<![A-Za-z0-9:.\-])(?:[0-9a-f]{2}([:\-])[0-9a-f]{2}"
        r"(?:[:\-][0-9a-f]{2}){4}|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2})"
        r"(?![A-Za-z0-9:.\-])", re.I
    ),
}


def _refang(value: str) -> str:
    """Normaliza apenas o candidato, sem alterar o texto nem fazer requisicoes."""
    value = value.replace("[.]", ".").replace("[:]", ":")
    return re.sub(r"^hxxp(?=s?://)", "http", value, flags=re.I)


def _valid_domain(value: str) -> bool:
    if len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    if not (2 <= len(labels[-1]) <= 24 and labels[-1].isalpha() and labels[-1].isascii()):
        return False
    return all(
        1 <= len(label) <= 63
        and label[0].isalnum() and label[-1].isalnum()
        and label.isascii()
        and re.fullmatch(r"[A-Za-z0-9-]+", label) is not None
        for label in labels
    )


def _normalize(kind: str, raw: str) -> str | None:
    value = _refang(raw)
    try:
        if kind == "url":
            # Pontuacao editorial frequente ao redor de links em relatorios.
            value = value.rstrip(".,;!?)}")
            url = urlsplit(value)
            if url.scheme.lower() not in ("http", "https") or not url.hostname:
                return None
            if url.username is not None or url.password is not None:
                return None  # Nao publicar possiveis credenciais no resultado.
            if url.port is not None and not (1 <= url.port <= 65535):
                return None
            host = url.hostname
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if not _valid_domain(host):
                    return None
            return value
        if kind == "email":
            local, sep, domain = value.rpartition("@")
            if not sep or not local or not _valid_domain(domain):
                return None
            return local + "@" + domain.lower()
        if kind == "domain":
            return value.lower() if _valid_domain(value) else None
        if kind in ("ipv4", "ipv6"):
            address = ipaddress.ip_address(value)
            if address.version != (4 if kind == "ipv4" else 6):
                return None
            return str(address)
        if kind == "ipv4_cidr":
            interface = ipaddress.ip_interface(value)
            return str(interface) if interface.version == 4 else None
        if kind in ("sha256", "sha1", "md5"):
            return value.lower()
        if kind == "cve":
            year = int(value.split("-")[1])
            return value.upper() if 1999 <= year <= 2099 else None
        if kind in ("attack_technique", "attack_tactic"):
            return value.upper()
        if kind == "asn":
            number = int(value[2:])
            return "AS" + str(number) if 0 <= number <= 4294967295 else None
        if kind == "mac":
            hexdigits = re.sub(r"[:.\-]", "", value)
            return ":".join(hexdigits[i:i+2].lower() for i in range(0, 12, 2))
    except ValueError:
        return None
    return None


def extract_line(
    line: str, source: str, number: int, types: set[str] | None = None
) -> list[dict[str, object]]:
    """Retorna evidencias com linha/coluna 1-based e posicoes do texto original."""
    results: list[dict[str, object]] = []
    for kind, pattern in PATTERNS.items():
        if types is not None and kind not in types:
            continue
        for match in pattern.finditer(line):
            raw = match.group(0)
            normalized = _normalize(kind, raw)
            if normalized is None:
                continue
            results.append({
                "type": kind, "value": normalized, "raw": raw,
                "source": source, "line": number, "column": match.start() + 1,
            })
    return sorted(results, key=lambda item: (int(item["column"]), str(item["type"])))


def extract(text: str, source: str = "<text>", types: set[str] | None = None):
    """API Python para processar strings sem rede. Preserva cada ocorrencia."""
    for number, line in enumerate(text.splitlines(), 1):
        yield from extract_line(line, source, number, types)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extrai candidatos OSINT/CTI de arquivos locais ou stdin (sem rede)."
    )
    parser.add_argument("files", nargs="*", help="Arquivos UTF-8; use - para stdin.")
    parser.add_argument("--types", help="Tipos separados por virgula, ex.: ipv4,cve,sha256")
    parser.add_argument("--list-types", action="store_true", help="Lista categorias e sai.")
    parser.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")
    parser.add_argument("--unique", action="store_true", help="Deduplica por (tipo, valor).")
    parser.add_argument("--max-line-length", type=int, default=100000)
    parser.add_argument("--max-matches", type=int, default=10000)
    args = parser.parse_args(argv)
    if args.list_types:
        print("\n".join(PATTERNS))
        return 0
    if args.max_line_length < 1 or args.max_matches < 1:
        parser.error("Os limites devem ser maiores que zero.")
    types = None
    if args.types:
        types = {item.strip() for item in args.types.split(",") if item.strip()}
        invalid = types - PATTERNS.keys()
        if invalid or not types:
            parser.error("Tipos invalidos. Disponiveis: " + ", ".join(PATTERNS))

    writer = None
    if args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=(
            "type", "value", "raw", "source", "line", "column"
        ))
        writer.writeheader()
    seen: set[tuple[str, str]] = set()
    total = 0
    skipped = 0
    for path in args.files or ["-"]:
        source = "stdin" if path == "-" else path
        try:
            stream = contextlib.nullcontext(sys.stdin) if path == "-" else open(
                path, "r", encoding="utf-8", errors="replace"
            )
            with stream as handle:
                for number, line in enumerate(handle, 1):
                    if len(line) > args.max_line_length:
                        skipped += 1
                        continue
                    for indicator in extract_line(line, source, number, types):
                        key = (str(indicator["type"]), str(indicator["value"]))
                        if args.unique and key in seen:
                            continue
                        seen.add(key)
                        if writer:
                            writer.writerow(indicator)
                        else:
                            print(json.dumps(indicator, ensure_ascii=False))
                        total += 1
                        if total >= args.max_matches:
                            print("AVISO: limite de resultados atingido.", file=sys.stderr)
                            return 0
        except OSError as exc:
            print(f"Erro ao ler {source}: {exc}", file=sys.stderr)
            return 2
    if skipped:
        print(f"AVISO: {skipped} linhas ignoradas por tamanho.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
