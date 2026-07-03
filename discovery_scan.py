#!/usr/bin/env python3
"""Discovery host attivi su 10.0.0.0/8 (ping-sweep -sn), un file XML per
subnet /16, con parallelismo — equivalente Python di
scripts/nmap-discovery-10net.ps1, ma passando da nmap_proxy_client invece
di invocare nmap direttamente.

Usato al posto dello script PowerShell quando l'app gira containerizzata
(NMAP_PROXY_URL impostata): un container Linux non ha PowerShell né nmap
nativo, ma nmap_proxy_client inoltra comunque le scansioni all'host tramite
il proxy. In esecuzione nativa (NMAP_PROXY_URL non impostata) funziona
comunque, nmap_proxy_client esegue nmap in locale come sempre — ma per uso
nativo su Windows resta preferibile lo script PowerShell originale (più
maturo, in uso da tempo).

Uso:
    python discovery_scan.py                          # 256 subnet, batch 8, output in data/
    python discovery_scan.py --batch-size 16 --output-dir C:\\scans
"""

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import nmap_proxy_client
from job_lock import JobLock

BASE = Path(__file__).parent
LOCK_FILE = BASE / "discovery.lock"
DEFAULT_BATCH_SIZE = 8
DEFAULT_TIMEOUT = 900
DEFAULT_TIMING = "3"
TOTAL_SUBNETS = 256


def scan_subnet(subnet_id, output_dir, timeout=DEFAULT_TIMEOUT, timing=DEFAULT_TIMING):
    """Esegue nmap -sn sulla subnet 10.<subnet_id>.0.0/16, scrive l'XML in
    output_dir. Ritorna (subnet_id, ok, errore_o_None). timing: template
    nmap -T0..-T5 (valori bassi = meno pacchetti/probe al secondo, per non
    affaticare firewall/IDS, a costo di una scansione più lenta)."""
    xml_path = Path(output_dir) / f"scan_10.{subnet_id}.0.0.xml"
    try:
        nmap_proxy_client.run_nmap(
            ["-sn", "-n", f"-T{timing}", f"10.{subnet_id}.0.0/16", "-oX", str(xml_path)],
            timeout=timeout,
        )
        return subnet_id, True, None
    except subprocess.TimeoutExpired:
        return subnet_id, False, "timeout"
    except Exception as e:
        return subnet_id, False, str(e)


def run_discovery(output_dir, batch_size=DEFAULT_BATCH_SIZE, timeout=DEFAULT_TIMEOUT,
                   timing=DEFAULT_TIMING, subnet_ids=range(TOTAL_SUBNETS)):
    """Lancia il ping-sweep su tutte le subnet indicate con parallelismo
    limitato a batch_size. Ritorna {'ok': N, 'failed': N}."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    subnet_ids = list(subnet_ids)
    total = len(subnet_ids)
    results = {"ok": 0, "failed": 0}

    with ThreadPoolExecutor(max_workers=batch_size) as executor:
        futures = {executor.submit(scan_subnet, i, output_dir, timeout, timing): i for i in subnet_ids}
        for future in as_completed(futures):
            subnet_id, ok, error = future.result()
            if ok:
                results["ok"] += 1
            else:
                results["failed"] += 1
            done = results["ok"] + results["failed"]
            status = "OK" if ok else f"FALLITA ({error})"
            print(f"[{done:3d}/{total}] 10.{subnet_id}.0.0/16 {status}", flush=True)

    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                         help="Subnet scansionate in parallelo (default 8)")
    parser.add_argument("--output-dir", default=str(BASE / "data"))
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                         help="Timeout per singola subnet in secondi (default 900)")
    parser.add_argument("--timing", default=DEFAULT_TIMING, choices=["0", "1", "2", "3", "4", "5"],
                         help="Timing template nmap -T0..-T5 (default 3): valori bassi per non "
                              "affaticare firewall/IDS")
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        print(f"Avvio discovery XML su 10.0.0.0/8 ({TOTAL_SUBNETS} subnet /16), "
              f"batch size {args.batch_size}, timing -T{args.timing}, output in {args.output_dir}...", flush=True)
        results = run_discovery(args.output_dir, args.batch_size, args.timeout, args.timing)
        print(f"Completato: {results['ok']} OK, {results['failed']} fallite su {TOTAL_SUBNETS} subnet.")


if __name__ == "__main__":
    main()
