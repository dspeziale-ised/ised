#!/usr/bin/env python3
"""Rigenera up_ips.txt da TUTTI i file *.xml presenti in data/ (i file
possono cambiare/aumentare da un aggiornamento all'altro: nuove scansioni,
subnet diverse, ecc. — extract_up_ips.py li unisce e deduplica) e avvia
scan_and_store.py in modalità --resume, così vengono scansionati solo gli
IP nuovi/non ancora registrati.

Pensato per essere lanciato sia da riga di comando sia dall'app web (route
/scan/start), che lo esegue come sottoprocesso in background.
"""

import argparse
import subprocess
import sys
from pathlib import Path

from job_lock import JobLock

BASE = Path(__file__).parent
PY = sys.executable
LOCK_FILE = BASE / "rescan.lock"


def run(cmd):
    print("$ " + " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=BASE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timing", choices=["1", "2", "3", "4", "5"],
                         help="Timing template nmap -T1..-T5 per scan_and_store.py "
                              "(default 4 se non indicato: vedi scan_and_store.py)")
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        print("== Aggiornamento up_ips.txt da tutti i file data/*.xml ==", flush=True)
        run([
            PY, str(BASE / "extract_up_ips.py"),
            "-o", str(BASE / "up_ips.txt"),
        ])

        print("== Avvio scan_and_store.py --resume (salta IP già scansionati) ==", flush=True)
        scan_cmd = [
            # --db non passato: scan_and_store.py risolve da sé DATABASE_URL
            # (Postgres, se il container la imposta) o il file SQLite di default.
            PY, str(BASE / "scan_and_store.py"),
            "--input", str(BASE / "up_ips.txt"),
            "--scans-dir", str(BASE / "scans"),
            "--resume",
        ]
        if args.timing:
            scan_cmd += ["--timing", args.timing]
        run(scan_cmd)

        print("== Completato ==", flush=True)


if __name__ == "__main__":
    main()
