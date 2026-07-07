#!/usr/bin/env python3
"""Arricchimento automatico degli host senza sistema operativo rilevato:
trova gli host con os_name vuoto/nullo (tipicamente scoperti da una
scansione "leggera" senza -O/-sV, es. Discovery iniziale o una Scansione
reti registrate con solo -sn) e lancia su di loro una scansione nmap -O -sV
per completarne il profilo, a basso effort per costruzione (-T3,
--max-parallelism 4 di default: al massimo 4 host sondati in parallelo per
invocazione, mai tutti insieme anche su liste lunghe).

Pensato per girare periodicamente in background (vedi
auto_enrich_schedule.py e app.py:run_scheduled_auto_enrich_if_due), con lo
stesso pattern di host_monitor.py/monitor_schedule.py — non è un job
avviabile dalla UI come Discovery/Aggiorna scansione/Scansione nmap, ma
resta eseguibile a mano da riga di comando per un ciclo singolo.

A differenza della scansione SNMP singola dal dettaglio host (vedi
app.py:host_snmp_scan, che usa scanner_db.merge_scanned_services per non
toccare le altre porte), qui si tratta di host SENZA alcun dato OS/servizi
ancora noto: usare scan_pipeline.run_and_store (upsert_host, sostituzione
completa) è corretto, non c'è nulla di preesistente da preservare.

Uso:
    python auto_enrich.py                        # un ciclo su tutti gli host senza OS
    python auto_enrich.py --max-parallelism 2 --timing 2
"""

import argparse
import sys
import tempfile
from pathlib import Path

import scan_pipeline
import scanner_db
from job_lock import JobLock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
LOCK_FILE = BASE / "auto_enrich.lock"

DEFAULT_TIMING = "3"
DEFAULT_MAX_PARALLELISM = 4
DEFAULT_TOP_PORTS = 200
DEFAULT_HOST_TIMEOUT = "3m"
DEFAULT_MAX_RETRIES = 1
# Host per invocazione nmap: come in custom_scan.py, un'unica invocazione su
# una lista molto lunga darebbe un riscontro solo alla fine (nmap non
# riporta progresso "per host" durante l'esecuzione) — a batch, i risultati
# si registrano progressivamente. --max-parallelism resta il limite VERO di
# quanti host sono sondati contemporaneamente, indipendentemente da questo.
#
# 16, non un numero più comodo come 50: senza --host-timeout un host che non
# risponde a un probe può far rimanere nmap in attesa per un tempo lungo
# (nessun limite assoluto, solo timeout adattivi per singola probe) — con
# --host-timeout impostato, il caso peggiore per un intero batch è
# (batch_size / max_parallelism) * host_timeout. Con batch_size=50 questo
# arrivava a superare abbondantemente il timeout esterno di run_and_store
# (1800s/30min) PRIMA che un solo host completasse, lasciando il ciclo
# "fermo" (nessun host arricchito, nessun progresso visibile) anche se il
# processo nmap era vivo e lavorava — bug verificato e corretto. Con
# batch_size=16 e host_timeout=3m il caso peggiore è (16/4)*3=12min, con
# ampio margine sotto i 30 minuti.
DEFAULT_BATCH_SIZE = 16
_STATUS_RANK = {"ok": 0, "timeout": 1, "error": 2}


def find_hosts_without_os(conn):
    """Host con os_name vuoto/nullo, candidati per l'arricchimento
    automatico. Ritorna [{'id', 'ip'}, ...] ordinati per id (i più vecchi/
    scoperti prima hanno priorità, coerente con l'idea di 'colmare' il
    profilo di host già noti da tempo prima dei nuovissimi)."""
    rows = conn.execute(
        "SELECT id, ip FROM hosts WHERE os_name IS NULL OR os_name = '' ORDER BY id"
    ).fetchall()
    return [{"id": r["id"], "ip": r["ip"]} for r in rows]


def run_enrich_cycle(conn, scans_dir, timing=DEFAULT_TIMING, max_parallelism=DEFAULT_MAX_PARALLELISM,
                      batch_size=DEFAULT_BATCH_SIZE, top_ports=DEFAULT_TOP_PORTS,
                      host_timeout=DEFAULT_HOST_TIMEOUT, max_retries=DEFAULT_MAX_RETRIES, timeout=900):
    """Esegue un ciclo di arricchimento su tutti gli host senza OS noto, a
    batch (vedi il docstring del modulo per il perché). Ritorna
    {'hosts_found', 'hosts_enriched', 'status'} — hosts_enriched conta solo
    gli host per cui è stato effettivamente determinato un OS (una porta
    filtrata/host irraggiungibile in questo momento non viene contata come
    arricchita, anche se resta comunque nella tabella per il prossimo ciclo)."""
    scans_dir = Path(scans_dir)
    scans_dir.mkdir(parents=True, exist_ok=True)

    targets = find_hosts_without_os(conn)
    if not targets:
        return {"hosts_found": 0, "hosts_enriched": 0, "status": "ok"}

    total_enriched = 0
    worst_status = "ok"

    for i in range(0, len(targets), batch_size):
        batch = targets[i:i + batch_size]
        batch_label = f"[batch {i // batch_size + 1}] "
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("\n".join(h["ip"] for h in batch))
            ip_list_file = Path(f.name)
        ts = scan_pipeline.now_iso().replace(":", "-")
        xml_out = scans_dir / f"autoenrich_{ts}.xml"
        cmd = [
            "-Pn", "-O", "-sV", "--osscan-guess", f"-T{timing}",
            "--max-parallelism", str(max_parallelism), "--max-retries", str(max_retries),
            "--host-timeout", host_timeout, "--top-ports", str(top_ports),
            "-oX", str(xml_out), "-iL", str(ip_list_file),
        ]
        print(f"{batch_label}{len(batch)} host senza OS -> nmap {' '.join(cmd)}", flush=True)
        try:
            result = scan_pipeline.run_and_store(cmd, xml_out, conn, target_count=len(batch), timeout=timeout)
        finally:
            ip_list_file.unlink(missing_ok=True)

        if result["status"] == "timeout":
            print(f"{batch_label}Timeout dopo {timeout}s: uso i risultati parziali.", flush=True)
        elif result["status"] == "error":
            print(f"{batch_label}Errore durante la scansione: {result['error_detail']}", flush=True)
        for host in result["hosts_up"]:
            os_label = host.get("os_name") or "OS ancora sconosciuto"
            print(f"  {host['ip']}: {len(host['services'])} servizi, {os_label}", flush=True)
            if host.get("os_name"):
                total_enriched += 1
        if _STATUS_RANK[result["status"]] > _STATUS_RANK[worst_status]:
            worst_status = result["status"]

    return {"hosts_found": len(targets), "hosts_enriched": total_enriched, "status": worst_status}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", default=scanner_db.resolve_db_target(BASE / "instance" / "inventory.db"),
        help="Percorso database SQLite, oppure URL postgresql://... (default: DATABASE_URL se impostata)",
    )
    parser.add_argument("--scans-dir", default=str(BASE / "scans"), help="Cartella per gli XML grezzi")
    parser.add_argument("--timing", default=DEFAULT_TIMING, help="Timing nmap -T0..-T5 (default 3)")
    parser.add_argument("--max-parallelism", type=int, default=DEFAULT_MAX_PARALLELISM,
                         help="Host sondati in parallelo al massimo per invocazione (default 4)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                         help="Host per invocazione nmap (default 16, vedi il docstring del modulo per il perché "
                              "non un numero più alto)")
    parser.add_argument("--top-ports", type=int, default=DEFAULT_TOP_PORTS)
    parser.add_argument("--host-timeout", default=DEFAULT_HOST_TIMEOUT,
                         help="Timeout nmap per singolo host (default 3m) — essenziale per bounded il caso "
                              "peggiore di un batch, vedi il docstring del modulo")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("--timeout", type=int, default=900, help="Timeout (s) di ogni invocazione nmap (per batch)")
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        conn = scanner_db.connect(args.db)
        scanner_db.init_db(conn)
        result = run_enrich_cycle(
            conn, args.scans_dir, timing=args.timing, max_parallelism=args.max_parallelism,
            batch_size=args.batch_size, top_ports=args.top_ports, host_timeout=args.host_timeout,
            max_retries=args.max_retries, timeout=args.timeout,
        )
        conn.close()
        print(
            f"Completato ({result['status']}): {result['hosts_enriched']}/{result['hosts_found']} "
            f"host arricchiti con OS rilevato."
        )


if __name__ == "__main__":
    main()
