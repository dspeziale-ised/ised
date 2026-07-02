#!/usr/bin/env python3
"""Estrae gli IP con status 'up' da uno o più file XML di nmap.

Gestisce anche file troncati (es. scansione ancora in corso / file
senza i tag di chiusura), tramite parsing incrementale. Se non viene
indicato nessun file, elabora TUTTI i file *.xml trovati in data/ (i
contenuti/nomi dei file in quella cartella possono variare da un
aggiornamento all'altro: nuove scansioni, subnet diverse, ecc.) e ne
unisce gli IP, deduplicati.
"""

import argparse
import sys
from pathlib import Path
from xml.etree.ElementTree import iterparse, ParseError

DATA_DIR = Path(__file__).parent / "data"


def extract_up_ips(xml_path):
    up_ips = []

    with open(xml_path, "rb") as f:
        parser = iterparse(f, events=("end",))
        try:
            for _, elem in parser:
                if elem.tag != "host":
                    continue

                status = elem.find("status")
                if status is not None and status.get("state") == "up":
                    for address in elem.findall("address"):
                        if address.get("addrtype") == "ipv4":
                            up_ips.append(address.get("addr"))
                            break

                elem.clear()
        except ParseError:
            # File troncato (es. scansione ancora in corso): teniamo
            # tutti gli host completi già letti fino a quel punto.
            pass

    return up_ips


def discover_xml_files():
    """Tutti i file *.xml in data/, ordinati per nome (ordine deterministico)."""
    if not DATA_DIR.is_dir():
        return []
    return sorted(DATA_DIR.glob("*.xml"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "xml_files",
        nargs="*",
        help="File XML di nmap da elaborare (default: tutti i *.xml in data/)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Se specificato, scrive gli IP (uniti e deduplicati) anche su questo file",
    )
    args = parser.parse_args()

    xml_paths = [Path(p) for p in args.xml_files] if args.xml_files else discover_xml_files()

    missing = [p for p in xml_paths if not p.exists()]
    if missing:
        for p in missing:
            print(f"Errore: file non trovato: {p}", file=sys.stderr)
        sys.exit(1)

    if not xml_paths:
        print(f"Nessun file XML trovato (cercato in {DATA_DIR}).", file=sys.stderr)
        sys.exit(1)

    seen = set()
    merged_ips = []
    for xml_path in xml_paths:
        file_ips = extract_up_ips(xml_path)
        new_count = 0
        for ip in file_ips:
            if ip not in seen:
                seen.add(ip)
                merged_ips.append(ip)
                new_count += 1
        print(f"{xml_path.name}: {len(file_ips)} host up ({new_count} nuovi)", file=sys.stderr)

    for ip in merged_ips:
        print(ip)

    if args.output:
        Path(args.output).write_text("\n".join(merged_ips) + "\n", encoding="utf-8")

    print(f"\nTotale host up (da {len(xml_paths)} file, deduplicati): {len(merged_ips)}", file=sys.stderr)


if __name__ == "__main__":
    main()
