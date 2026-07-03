#!/usr/bin/env python3
"""Scansione nmap "libera": target e argomenti nmap arbitrari (costruiti
dal form in Inventario -> Scansione nmap, o passati a mano), risultati
salvati negli host esattamente come scan_and_store.py (stesso
scanner_db.upsert_host, stessa euristica classify.classify_device).

A differenza di scan_and_store.py (pensato per batch di IP da un file, con
un set fisso di flag) questo script accetta QUALSIASI combinazione di
opzioni nmap: la UI espone praticamente tutte le categorie (discovery,
tecnica di scansione, porte, versione/OS, script NSE, timing, evasione),
ma resta comunque possibile passare argomenti extra a mano per qualunque
flag non coperto esplicitamente dal form.

Uso:
    python custom_scan.py --target "10.1.26.0/24" --args "-sS -sV -O -T4 --top-ports 200"
    python custom_scan.py --target "10.1.26.5 10.1.26.6" --args "-p 22,80,443 -sV"
"""

import argparse
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import classify
import nmap_parser
import nmap_proxy_client
import scanner_db
from job_lock import JobLock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
LOCK_FILE = BASE / "customscan.lock"
LOG_DIR = BASE / "logs"

# Flag di output/input file: forzando sempre il nostro -oX, un utente che li
# digita a mano negli "argomenti extra" andrebbe in conflitto (nmap non
# accetta due -oX) — vengono rimossi (col loro valore) prima di aggiungere
# il nostro -oX obbligatorio.
_STRIP_FLAGS_WITH_VALUE = {"-oX", "-oN", "-oG", "-oA", "-iL"}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sanitize_extra_args(args_list):
    """Rimuove eventuali flag di output/input file dagli argomenti extra
    (vedi _STRIP_FLAGS_WITH_VALUE) per non entrare in conflitto col nostro
    -oX obbligatorio, mantenendo intatto il resto."""
    cleaned = []
    skip_next = False
    for arg in args_list:
        if skip_next:
            skip_next = False
            continue
        if arg in _STRIP_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        cleaned.append(arg)
    return cleaned


def build_command(target, extra_args_str, xml_out):
    extra_args = sanitize_extra_args(shlex.split(extra_args_str or ""))
    targets = shlex.split(target)
    return extra_args + ["-oX", str(xml_out)] + targets


def run_scan(target, extra_args_str, db_path, scans_dir, timeout=1800):
    """Esegue la scansione, parsa l'XML e salva/aggiorna gli host trovati.
    Ritorna un dict di riepilogo {'hosts_found', 'hosts_up', 'status'}."""
    scans_dir = Path(scans_dir)
    scans_dir.mkdir(parents=True, exist_ok=True)
    ts = now_iso().replace(":", "-")
    xml_out = scans_dir / f"customscan_{ts}.xml"

    cmd = build_command(target, extra_args_str, xml_out)
    print(f"Comando: nmap {' '.join(cmd)}", flush=True)

    started = now_iso()
    status = "ok"
    try:
        nmap_proxy_client.run_nmap(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        status = "timeout"
        print(f"Timeout dopo {timeout}s: uso i risultati parziali eventualmente scritti.", flush=True)
    except Exception as e:
        status = "error"
        print(f"Errore durante la scansione: {e}", flush=True)
    finished = now_iso()

    hosts = []
    if xml_out.exists():
        try:
            hosts = nmap_parser.parse_nmap_xml(xml_out)
        except ET.ParseError as e:
            print(f"Output XML non valido/incompleto: {e}", flush=True)

    conn = scanner_db.connect(db_path)
    scanner_db.init_db(conn)

    hosts_up = 0
    for host in hosts:
        if host["state"] != "up":
            continue
        hosts_up += 1
        device_type, device_vendor = classify.classify_device(
            host["os_matches"], host["services"], ip=host["ip"], ttl=host.get("ttl")
        )
        host["device_type"] = device_type
        host["device_vendor"] = device_vendor
        host["last_scanned"] = finished
        host["raw_xml_path"] = str(xml_out)
        scanner_db.upsert_host(conn, host)
        print(f"  {host['ip']}: {len(host['services'])} servizi, tipo dedotto '{device_type}'", flush=True)

    scanner_db.log_scan(conn, started, finished, len(hosts) or 1, str(xml_out), "nmap " + " ".join(cmd), status)
    conn.commit()
    conn.close()

    return {"hosts_found": len(hosts), "hosts_up": hosts_up, "status": status}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True,
                         help="Target nmap: IP, range, CIDR, hostname (anche più di uno separati da spazio)")
    parser.add_argument("--args", default="", help="Argomenti nmap aggiuntivi (es. '-sS -sV -O -T4')")
    parser.add_argument(
        "--db", default=scanner_db.resolve_db_target(BASE / "instance" / "inventory.db"),
        help="Percorso database SQLite, oppure URL postgresql://... (default: DATABASE_URL se impostata)",
    )
    parser.add_argument("--scans-dir", default=str(BASE / "scans"), help="Cartella per gli XML grezzi")
    parser.add_argument("--timeout", type=int, default=1800, help="Timeout (s) dell'intera scansione")
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        print(f"Avvio scansione nmap personalizzata su: {args.target}", flush=True)
        result = run_scan(args.target, args.args, args.db, args.scans_dir, args.timeout)
        print(
            f"Completato ({result['status']}): {result['hosts_up']}/{result['hosts_found']} "
            f"host up registrati/aggiornati."
        )


if __name__ == "__main__":
    main()
