#!/usr/bin/env python3
"""Rigenera up_ips.txt da TUTTI i file *.xml presenti in data/ (i file
possono cambiare/aumentare da un aggiornamento all'altro: nuove scansioni,
subnet diverse, ecc. — extract_up_ips.py li unisce e deduplica) e avvia
scan_and_store.py in modalità --resume, così vengono scansionati solo gli
IP nuovi/non ancora registrati.

Pensato per essere lanciato sia da riga di comando sia dall'app web (route
/scan/start), che lo esegue come sottoprocesso in background.
"""

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
    with JobLock(LOCK_FILE):
        print("== Aggiornamento up_ips.txt da tutti i file data/*.xml ==", flush=True)
        run([
            PY, str(BASE / "extract_up_ips.py"),
            "-o", str(BASE / "up_ips.txt"),
        ])

        print("== Avvio scan_and_store.py --resume (salta IP già scansionati) ==", flush=True)
        run([
            PY, str(BASE / "scan_and_store.py"),
            "--input", str(BASE / "up_ips.txt"),
            "--db", str(BASE / "instance" / "inventory.db"),
            "--scans-dir", str(BASE / "scans"),
            "--resume",
        ])

        print("== Completato ==", flush=True)


if __name__ == "__main__":
    main()
