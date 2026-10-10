#!/usr/bin/env python3
"""Inventario local de arquivos: SHA256, tamanho e mtime UTC, sem rede nem EXIF."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LIMIT = 100 * 1024 * 1024


def file_evidence(path: Path, max_size: int = DEFAULT_LIMIT) -> dict:
    if path.is_symlink():
        raise ValueError("symlink nao permitido")
    if not path.is_file():
        raise ValueError("arquivo regular nao encontrado")
    before = path.stat()
    if before.st_size > max_size:
        raise ValueError("arquivo acima do limite")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("arquivo foi alterado durante a leitura")
    return {"type": "file_evidence", "source": str(path),
            "size_bytes": after.st_size, "sha256": digest.hexdigest(),
            "mtime_utc": datetime.fromtimestamp(
                after.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "mtime_semantics": "filesystem_last_modified_not_creation"}


def main(argv=None):
    p = argparse.ArgumentParser(description="Manifesto SHA256 offline em JSONL.")
    p.add_argument("files", nargs="+")
    p.add_argument("--max-size", type=int, default=DEFAULT_LIMIT)
    args = p.parse_args(argv)
    if args.max_size < 0:
        p.error("--max-size nao pode ser negativo")
    errors = 0
    for name in args.files:
        try:
            print(json.dumps(file_evidence(Path(name), args.max_size),
                             ensure_ascii=False, sort_keys=True))
        except (OSError, ValueError) as exc:
            errors += 1
            print(f"AVISO: {name}: {exc}", file=sys.stderr)
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
