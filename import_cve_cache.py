#!/usr/bin/env python3
"""Carica un file CSV/JSON di CVE per CPE nella cache (cve_cache), senza
passare da nmap/vulners. Le CVE caricate si aggiungono a quelle già in
cache per la stessa CPE (merge), non la sovrascrivono.

Formati supportati (vedi cve_lookup.parse_cve_import):
- CSV con colonne: cpe,cve_id,cvss,url
- JSON oggetto: {"<cpe>": [{"id": "...", "cvss": 0, "url": "..."}]}
- JSON lista: [{"cpe": "...", "cve_id": "...", "cvss": 0, "url": "..."}]

Uso:
    python import_cve_cache.py mie_cve.csv
    python import_cve_cache.py export_nvd.json
"""

import argparse
import sys
from pathlib import Path

import cve_lookup
import scanner_db

BASE = Path(__file__).parent
DB_PATH = BASE / "instance" / "inventory.db"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="File CSV o JSON da caricare nella cache CVE")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"Errore: file non trovato: {path}", file=sys.stderr)
        sys.exit(1)

    parsed = cve_lookup.parse_cve_import(path.read_bytes(), path.name)
    if not parsed:
        print("Nessuna CPE/CVE valida trovata nel file (verifica formato/colonne).", file=sys.stderr)
        sys.exit(1)

    conn = scanner_db.connect(str(DB_PATH))
    scanner_db.init_db(conn)

    imported_cves = sum(len(cve_list) for cve_list in parsed.values())
    for cpe, cve_list in parsed.items():
        total_after = scanner_db.merge_cached_cve(conn, cpe, cve_list)
        print(f"  {cpe}: +{len(cve_list)} CVE (totale in cache: {total_after})")

    stats = scanner_db.cve_cache_stats(conn)
    conn.close()

    print(f"\nCaricate {imported_cves} CVE per {len(parsed)} CPE.")
    print(f"Cache CVE ora: {stats['cpes']} CPE, {stats['cves']} CVE totali.")


if __name__ == "__main__":
    main()
