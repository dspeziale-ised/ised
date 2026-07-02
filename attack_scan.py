#!/usr/bin/env python3
"""Mappa i servizi/vulnerabilità/tipo dispositivo di ogni host sulle
tecniche MITRE ATT&CK Enterprise applicabili (attack_mapping.py), usando la
matrice ufficiale scaricata da MITRE (attack_data.py, cachata in
instance/attack_enterprise.json).

La mappatura è euristica e interamente locale (nessuna chiamata esterna a
parte l'eventuale download/aggiornamento della matrice): viene sempre
ricalcolata per tutti gli host ad ogni esecuzione, dato il costo trascurabile.

Uso:
    python attack_scan.py                  # carica la matrice (se manca) e mappa tutti gli host
    python attack_scan.py --update-matrix   # forza il ri-download della matrice ufficiale MITRE
    python attack_scan.py --limit 50        # solo i primi N host (per test)
"""

import argparse
import sys
from pathlib import Path

import attack_data
import attack_mapping
import scanner_db
from job_lock import JobLock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
DB_PATH = BASE / "instance" / "inventory.db"
LOCK_FILE = BASE / "attack.lock"


def load_host_context(conn, host_id):
    services = [dict(r) for r in conn.execute(
        "SELECT port, service_name, product FROM services WHERE host_id = ? AND state = 'open'",
        (host_id,),
    )]
    vulnerabilities = [dict(r) for r in conn.execute(
        "SELECT cvss FROM host_vulnerabilities WHERE host_id = ?", (host_id,)
    )]
    return services, vulnerabilities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-matrix", action="store_true",
                         help="Forza il ri-download della matrice ufficiale MITRE ATT&CK")
    parser.add_argument("--limit", type=int, help="Limita il numero di host da elaborare (per test)")
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        conn = scanner_db.connect(str(DB_PATH))
        scanner_db.init_db(conn)
        scanner_db.ensure_attack_tables(conn)

        print("Verifico/carico la matrice MITRE ATT&CK...")
        result = attack_data.ensure_loaded(conn, force=args.update_matrix)
        if result.get("skipped"):
            n_tactics = conn.execute("SELECT COUNT(*) c FROM attack_tactics").fetchone()["c"]
            n_techniques = conn.execute("SELECT COUNT(*) c FROM attack_techniques").fetchone()["c"]
            print(f"  Matrice già in cache: {n_tactics} tattiche, {n_techniques} tecniche.")
        else:
            print(f"  Matrice caricata: {result['tactics']} tattiche, {result['techniques']} tecniche.")

        hosts = conn.execute("SELECT id, ip, device_type FROM hosts ORDER BY ip").fetchall()
        if args.limit:
            hosts = hosts[: args.limit]

        print(f"\nMappatura euristica su {len(hosts)} host...")
        total_techniques = 0
        hosts_with_exposure = 0

        for host in hosts:
            services, vulnerabilities = load_host_context(conn, host["id"])
            techniques = attack_mapping.map_host_techniques(dict(host), services, vulnerabilities)
            scanner_db.set_host_attack_techniques(conn, host["id"], techniques, source="heuristic")
            if techniques:
                hosts_with_exposure += 1
                total_techniques += len(techniques)

        conn.close()
        print(
            f"\nCompletato: {hosts_with_exposure}/{len(hosts)} host con almeno una tecnica "
            f"potenziale mappata, {total_techniques} associazioni host/tecnica totali."
        )


if __name__ == "__main__":
    main()
