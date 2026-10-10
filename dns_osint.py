#!/usr/bin/env python3
"""Parser de registros DNS locais e grafo de declaracoes, sem consultas de rede."""
from __future__ import annotations
import argparse
import contextlib
import ipaddress
import json
import re
import shlex
import sys

TYPES = {"A", "AAAA", "NS", "MX", "CNAME", "PTR", "TXT"}
RELATIONS = {"A": ("ip", "dns_a"), "AAAA": ("ip", "dns_aaaa"),
             "NS": ("domain", "dns_ns"), "MX": ("domain", "dns_mx"),
             "CNAME": ("domain", "dns_cname"), "PTR": ("domain", "dns_ptr")}


def dns_name(raw: str, service: bool = False) -> str:
    """Escopo intencional: FQDN ASCII; owners podem ter labels de servico."""
    name = raw.rstrip(".").lower()
    labels = name.split(".")
    if len(name) > 253 or not name.isascii() or len(labels) < 2:
        raise ValueError("FQDN invalido")
    for label in labels:
        rule = (r"_[a-z0-9][a-z0-9-]{0,61}" if service and label.startswith("_")
                else r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
        if not re.fullmatch(rule, label):
            raise ValueError("label DNS invalido")
    if not (2 <= len(labels[-1]) <= 24 and labels[-1].isalpha()):
        raise ValueError("TLD fora do escopo")
    return name


def dmarc_valid(value: str) -> bool:
    fields = [part.strip() for part in value.split(";") if part.strip()]
    if len(fields) < 2 or fields[0].lower() != "v=dmarc1":
        return False
    tags = {}
    for part in fields:
        if "=" not in part:
            return False
        key, val = part.split("=", 1)
        key = key.strip().lower()
        if not re.fullmatch("[a-z]{1,12}", key) or key in tags:
            return False
        tags[key] = val.strip().lower()
    return tags.get("p") in ("none", "quarantine", "reject")


def parse_record(line: str, source: str = "<text>", number: int = 1,
                 include_txt: bool = False) -> dict | None:
    """Somente formato: FQDN [TTL] [IN] TIPO RDATA (uma linha, sem $ORIGIN)."""
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ";"
    data = list(lexer)
    if not data:
        return None
    if data[0].startswith(("$", "@")):
        raise ValueError("nomes relativos/diretivas nao suportados")
    owner = dns_name(data[0], service=True)
    index, ttl, seen_in = 1, None, False
    for _ in range(2):
        if index < len(data) and data[index].upper() == "IN" and not seen_in:
            seen_in = True
        elif (index < len(data) and data[index].isascii() and
              data[index].isdigit() and ttl is None):
            ttl = int(data[index])
            if ttl > 4294967295:
                raise ValueError("TTL fora do intervalo")
        else:
            break
        index += 1
    if index >= len(data) or data[index].upper() not in TYPES:
        raise ValueError("tipo DNS ausente/nao suportado")
    rrtype = data[index].upper()
    payload = data[index+1:]
    if not payload:
        raise ValueError("RDATA ausente")
    preference, policy = None, None
    if rrtype in ("A", "AAAA"):
        if len(payload) != 1:
            raise ValueError("RDATA IP invalido")
        ip = ipaddress.ip_address(payload[0])
        if ip.version != (4 if rrtype == "A" else 6):
            raise ValueError("familia IP incorreta")
        value = str(ip)
    elif rrtype == "MX":
        if (len(payload) != 2 or not payload[0].isascii()
                or not payload[0].isdigit()):
            raise ValueError("MX requer prioridade e FQDN")
        preference = int(payload[0])
        if preference > 65535:
            raise ValueError("prioridade MX invalida")
        value = dns_name(payload[1])
    elif rrtype in ("NS", "CNAME", "PTR"):
        if len(payload) != 1:
            raise ValueError("RDATA FQDN invalido")
        value = dns_name(payload[0])
    else:
        value = "".join(payload)
        if len(value) > 4096:
            raise ValueError("TXT acima do limite")
        if re.match(r"^v=spf1(?:\s|$)", value, re.I):
            policy = "spf"
        elif re.match(r"^v=DMARC1\s*;", value, re.I):
            if not dmarc_valid(value):
                raise ValueError("DMARC invalido")
            policy = "dmarc"
        elif not include_txt:
            return None  # Outros TXT podem conter tokens privados.
    return {"type": "dns_record", "owner": owner, "rrtype": rrtype,
            "value": value, "ttl": ttl, "preference": preference, "policy": policy,
            "source": source, "line": number, "raw": line.rstrip("\r\n")}


def build_graph(records: list[dict]) -> dict:
    """So gera relacoes declaradas em registros tipados, nunca por coocorrencia."""
    nodes, edges = {}, {}
    for rec in records:
        rrtype = rec.get("rrtype")
        if rec.get("type") != "dns_record" or rrtype not in RELATIONS:
            continue
        try:
            owner = dns_name(rec["owner"], service=True)
            kind, relation = RELATIONS[rrtype]
            if kind == "ip":
                addr = ipaddress.ip_address(rec["value"])
                if addr.version != (4 if rrtype == "A" else 6):
                    continue
                value = str(addr)
            else:
                value = dns_name(rec["value"])
            priority = rec.get("preference") if rrtype == "MX" else None
            if priority is not None and (type(priority) is not int or
                                         not 0 <= priority <= 65535):
                continue
            source, line = str(rec["source"]), int(rec["line"])
            if line < 1:
                continue
        except (KeyError, ValueError, TypeError):
            continue
        sid, tid = "domain:" + owner, kind + ":" + value
        nodes[sid] = {"id": sid, "type": "domain", "value": owner}
        nodes[tid] = {"id": tid, "type": kind, "value": value}
        key = (sid, tid, relation, priority)
        if key not in edges:
            edges[key] = {"source": sid, "target": tid, "relation": relation,
                          "preference": priority, "evidence": []}
        evidence = {"source": source, "line": line}
        if evidence not in edges[key]["evidence"]:
            edges[key]["evidence"].append(evidence)
    for edge in edges.values():
        edge["evidence"].sort(key=lambda e: (e["source"], e["line"]))
    return {"schema_version": "1.0",
            "scope": "relacoes declaradas nos arquivos, nao DNS ao vivo",
            "nodes": sorted(nodes.values(), key=lambda x: x["id"]),
            "edges": sorted(edges.values(), key=lambda x: (
                x["source"], x["target"], x["relation"],
                -1 if x["preference"] is None else x["preference"])),
            "summary": {"records_read": len(records), "nodes": len(nodes),
                        "edges": len(edges)}}


def input_lines(paths: list[str]):
    for path in paths or ["-"]:
        source = "stdin" if path == "-" else path
        stream = (contextlib.nullcontext(sys.stdin) if path == "-"
                  else open(path, encoding="utf-8", errors="replace"))
        with stream as handle:
            for number, line in enumerate(handle, 1):
                yield source, number, line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DNS OSINT local: parser e grafo.")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("parse", "graph"):
        cmd = sub.add_parser(action)
        cmd.add_argument("files", nargs="*", help="Arquivos ou - (stdin).")
        cmd.add_argument("--max-line-length", type=int, default=100000)
        cmd.add_argument("--max-records", type=int, default=50000)
        if action == "parse":
            cmd.add_argument("--include-txt", action="store_true")
    args = parser.parse_args(argv)
    if args.max_line_length < 1 or args.max_records < 1:
        parser.error("Limites devem ser positivos.")
    count, warnings, records = 0, 0, []
    try:
        for source, number, line in input_lines(args.files):
            if len(line) > args.max_line_length:
                warnings += 1
                continue
            try:
                if args.action == "parse":
                    record = parse_record(line, source, number,
                                          include_txt=args.include_txt)
                else:
                    record = json.loads(line)
                    if not isinstance(record, dict) or record.get("type") != "dns_record":
                        raise ValueError("JSONL nao e registro DNS")
            except (ValueError, TypeError):
                warnings += 1
                continue
            if record is None:
                continue
            count += 1
            if args.action == "parse":
                print(json.dumps(record, ensure_ascii=False, sort_keys=True))
            else:
                records.append(record)
            if count >= args.max_records:
                print("AVISO: limite de registros atingido", file=sys.stderr)
                break
    except OSError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2
    if args.action == "graph":
        print(json.dumps(build_graph(records), ensure_ascii=False, indent=2,
                         sort_keys=True))
    if warnings:
        print(f"AVISO: {warnings} linhas invalidas/longas ignoradas",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
