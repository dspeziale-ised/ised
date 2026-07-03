#!/usr/bin/env python3
"""Monitoraggio periodico della raggiungibilità degli host noti (ping-sweep
nmap -sn a batch), con storico in host_status_checks.

Registra una riga solo al cambio di stato o dopo un "battito" periodico
(default ogni 60 minuti anche senza cambi), per contenere la crescita della
tabella pur mantenendo uno storico utile per calcolare l'uptime%.

Uso:
    python host_monitor.py                       # un ciclo di controllo su tutti gli host noti
    python host_monitor.py --batch-size 100       # host per chiamata nmap -sn (default 60)
    python host_monitor.py --heartbeat-minutes 30 # battito periodico anche senza cambi di stato
"""

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import nmap_proxy_client
import scanner_db
from job_lock import JobLock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
DB_PATH = scanner_db.resolve_db_target(BASE / "instance" / "inventory.db")
LOCK_FILE = BASE / "monitor.lock"
DEFAULT_BATCH_SIZE = 60
DEFAULT_HEARTBEAT_MINUTES = 60


def _parse_up_ips(xml_bytes):
    """Estrae il set di IPv4 con status 'up' da un output nmap -oX (bytes)."""
    up = set()
    if not xml_bytes:
        return up
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return up
    for host in root.iter("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                up.add(address.get("addr"))
                break
    return up


def ping_sweep(ips, timeout=120):
    """Esegue nmap -sn su un batch di IP, ritorna il set di IP risultati up.
    Punto di innesto per il proxy nmap (in ambiente containerizzato senza
    nmap locale, questa funzione verrà sostituita da una chiamata HTTP)."""
    if not ips:
        return set()
    try:
        result = nmap_proxy_client.run_nmap(
            ["-sn", "-n", "-oX", "-", *ips], capture_output=True, text=False, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  [!] Errore/timeout ping-sweep su batch di {len(ips)} host: {e}")
        return set()
    return _parse_up_ips(result.stdout)


def run_monitor_cycle(conn, batch_size=DEFAULT_BATCH_SIZE, heartbeat_minutes=DEFAULT_HEARTBEAT_MINUTES):
    """Esegue un ciclo completo di controllo su tutti gli host noti. Ritorna
    un riepilogo {'total', 'up', 'down', 'written'}."""
    hosts = conn.execute("SELECT id, ip FROM hosts ORDER BY ip").fetchall()
    now_str = datetime.now().isoformat(timespec="seconds")
    up_count = down_count = written = 0

    for i in range(0, len(hosts), batch_size):
        batch = hosts[i:i + batch_size]
        up_ips = ping_sweep([h["ip"] for h in batch])
        for h in batch:
            status = "up" if h["ip"] in up_ips else "down"
            if status == "up":
                up_count += 1
            else:
                down_count += 1
            if scanner_db.record_host_status_if_needed(conn, h["id"], status, now_str, heartbeat_minutes):
                written += 1

    return {"total": len(hosts), "up": up_count, "down": down_count, "written": written}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                         help="Quanti host per chiamata nmap -sn (default 60)")
    parser.add_argument("--heartbeat-minutes", type=int, default=DEFAULT_HEARTBEAT_MINUTES,
                         help="Registra comunque un check dopo N minuti anche senza cambi (default 60)")
    parser.add_argument("--db", default=str(DB_PATH))
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        conn = scanner_db.connect(args.db)
        scanner_db.ensure_monitor_tables(conn)
        result = run_monitor_cycle(conn, args.batch_size, args.heartbeat_minutes)
        conn.close()
        print(
            f"Ciclo di monitoraggio completato: {result['total']} host controllati "
            f"({result['up']} up, {result['down']} down), {result['written']} righe di storico scritte."
        )


if __name__ == "__main__":
    main()
