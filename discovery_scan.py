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
DEFAULT_TIMING = "4"
TOTAL_SUBNETS = 256

# -T0/-T1/-T2 serializzano le probe con un ritardo FISSO per host (T1 =
# ~15s, T2 = ~0.4s, T0 ancora più lento): su un /16 (65536 indirizzi) questo
# significa ORE o GIORNI per singola subnet, verificato empiricamente (T2
# non ha completato un solo /16 in 120s). Per una discovery "silenziosa" su
# un intero /16 lo strumento giusto resta --max-rate (limite pacchetti/
# secondo complessivo, che non esplode col numero di indirizzi), non il
# timing template. T0-T2 restano comunque accettati su richiesta esplicita
# (vedi scan_effort.py, profilo 'low'): chi li sceglie accetta che la
# discovery possa non completare mai in un tempo ragionevole.
TIMING_CHOICES = ("0", "1", "2", "3", "4", "5")


def scan_subnet(subnet_id, output_dir, timeout=DEFAULT_TIMEOUT, timing=DEFAULT_TIMING, max_rate=None):
    """Esegue nmap -sn sulla subnet 10.<subnet_id>.0.0/16, scrive l'XML in
    output_dir. Ritorna (subnet_id, ok, errore_o_None). max_rate (pacchetti/
    secondo) è la leva pratica per una scansione discreta su un intero /16
    — riduce il traffico senza rendere la scansione impossibilmente lenta
    come farebbero i timing template bassi."""
    xml_path = Path(output_dir) / f"scan_10.{subnet_id}.0.0.xml"
    args = ["-sn", "-n", f"-T{timing}"]
    if max_rate:
        args += ["--max-rate", str(max_rate)]
    args += [f"10.{subnet_id}.0.0/16", "-oX", str(xml_path)]
    try:
        nmap_proxy_client.run_nmap(args, timeout=timeout)
        return subnet_id, True, None
    except subprocess.TimeoutExpired:
        return subnet_id, False, "timeout"
    except Exception as e:
        return subnet_id, False, str(e)


def run_discovery(output_dir, batch_size=DEFAULT_BATCH_SIZE, timeout=DEFAULT_TIMEOUT,
                   timing=DEFAULT_TIMING, max_rate=None, subnet_ids=range(TOTAL_SUBNETS)):
    """Lancia il ping-sweep su tutte le subnet indicate con parallelismo
    limitato a batch_size. Ritorna {'ok': N, 'failed': N}."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    subnet_ids = list(subnet_ids)
    total = len(subnet_ids)
    results = {"ok": 0, "failed": 0}

    with ThreadPoolExecutor(max_workers=batch_size) as executor:
        futures = {
            executor.submit(scan_subnet, i, output_dir, timeout, timing, max_rate): i
            for i in subnet_ids
        }
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
    parser.add_argument("--timing", default=DEFAULT_TIMING, choices=list(TIMING_CHOICES),
                         help="Timing template nmap -T0..-T5 (default 4). -T0/-T1/-T2 sono "
                              "impraticabili nella maggior parte dei casi su un intero /16 (vedi "
                              "--max-rate per una scansione discreta che completi comunque)")
    parser.add_argument("--max-rate", type=int, default=None,
                         help="Limite pacchetti/secondo (nmap --max-rate): riduce il traffico per "
                              "non affaticare firewall/IDS senza rendere la scansione "
                              "impraticabilmente lenta. Consigliato 50-150 per una scansione discreta")
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        rate_desc = f", max-rate {args.max_rate} pkt/s" if args.max_rate else ""
        print(f"Avvio discovery XML su 10.0.0.0/8 ({TOTAL_SUBNETS} subnet /16), "
              f"batch size {args.batch_size}, timing -T{args.timing}{rate_desc}, "
              f"output in {args.output_dir}...", flush=True)
        results = run_discovery(args.output_dir, args.batch_size, args.timeout, args.timing, args.max_rate)
        print(f"Completato: {results['ok']} OK, {results['failed']} fallite su {TOTAL_SUBNETS} subnet.")


if __name__ == "__main__":
    main()
