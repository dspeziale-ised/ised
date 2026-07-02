#!/usr/bin/env python3
"""Estrae gli IP con status 'up' da un file XML di nmap.

Gestisce anche file troncati (es. scansione ancora in corso / file
senza i tag di chiusura), tramite parsing incrementale.
"""

import argparse
import sys
from pathlib import Path
from xml.etree.ElementTree import iterparse, ParseError


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "xml_file",
        nargs="?",
        default=str(Path(__file__).parent / "data" / "ised.xml"),
        help="Percorso del file XML di nmap (default: data/ised.xml)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Se specificato, scrive gli IP anche su questo file (uno per riga)",
    )
    args = parser.parse_args()

    xml_path = Path(args.xml_file)
    if not xml_path.exists():
        print(f"Errore: file non trovato: {xml_path}", file=sys.stderr)
        sys.exit(1)

    up_ips = extract_up_ips(xml_path)

    for ip in up_ips:
        print(ip)

    if args.output:
        Path(args.output).write_text("\n".join(up_ips) + "\n", encoding="utf-8")

    print(f"\nTotale host up: {len(up_ips)}", file=sys.stderr)


if __name__ == "__main__":
    main()
