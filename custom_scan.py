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

Se il target si espande in più di un host (CIDR, range, lista), la
scansione viene eseguita a BATCH invece che in un'unica invocazione nmap:
ogni batch è un'invocazione nmap indipendente che completa e registra i
propri risultati/traffico (vedi scan_pipeline.run_and_store) in pochi
minuti anziché alla fine dell'intero target — nmap non espone alcun
contatore di pacchetti/byte "in diretta" durante una singola invocazione
(la riga "Raw packets sent" viene stampata solo al termine), quindi questo
è l'unico modo per dare un riscontro progressivo su una scansione lunga
(es. un intero /24 con timing basso/--max-rate) invece che vederla come
un'unica attesa senza nessun dato fino alla fine.

Uso:
    python custom_scan.py --target "10.1.26.0/24" --args "-sS -sV -O -T4 --top-ports 200"
    python custom_scan.py --target "10.1.26.5 10.1.26.6" --args "-p 22,80,443 -sV"
"""

import argparse
import shlex
import sys
import tempfile
from pathlib import Path

import enrich
import nmap_parser
import nmap_proxy_client
import scan_pipeline
import scanner_db
from job_lock import JobLock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
LOCK_FILE = BASE / "customscan.lock"
LOG_DIR = BASE / "logs"

DEFAULT_BATCH_SIZE = 20
# Oltre questa soglia il batching per host smette di convenire (l'overhead
# di avvio di migliaia di invocazioni nmap separate supererebbe il beneficio
# di un riscontro progressivo) — per target enormi si torna a un'unica
# invocazione, come prima. Per una discovery/scan sistematica di reti così
# grandi esistono già discovery_scan.py/scan_and_store.py.
MAX_HOSTS_TO_BATCH = 2000

# Flag di output/input file: forzando sempre il nostro -oX, un utente che li
# digita a mano negli "argomenti extra" andrebbe in conflitto (nmap non
# accetta due -oX) — vengono rimossi (col loro valore) prima di aggiungere
# il nostro -oX obbligatorio.
_STRIP_FLAGS_WITH_VALUE = {"-oX", "-oN", "-oG", "-oA", "-iL"}
_STATUS_RANK = {"ok": 0, "timeout": 1, "error": 2}


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


def build_command(extra_args_str, xml_out, target=None, ip_list_file=None):
    """Costruisce gli argomenti nmap (senza binario): -oX obbligatorio +
    argomenti extra ripuliti + il target, passato come stringa libera
    (singolo host/lista/CIDR non espanso) oppure come file -iL (un batch di
    IP già espansi, durante una scansione multi-host)."""
    extra_args = sanitize_extra_args(shlex.split(extra_args_str or ""))
    cmd = extra_args + ["-oX", str(xml_out)]
    if ip_list_file is not None:
        cmd += ["-iL", str(ip_list_file)]
    else:
        cmd += shlex.split(target or "")
    return cmd


def _exclude_args(extra_args_str):
    """Estrae --exclude/--excludefile (con il loro valore) dagli argomenti
    extra, se presenti: vanno rispettati anche nell'espansione del target
    (altrimenti gli host esclusi finirebbero comunque in un batch)."""
    tokens = shlex.split(extra_args_str or "")
    result = []
    i = 0
    while i < len(tokens):
        if tokens[i] in ("--exclude", "--excludefile") and i + 1 < len(tokens):
            result += [tokens[i], tokens[i + 1]]
            i += 2
        else:
            i += 1
    return result


def expand_targets(target, extra_args_str, timeout=120):
    """Espande target (CIDR/range/lista/hostname) nell'elenco di IP che nmap
    scansionerebbe davvero, usando il list-scan di nmap stesso (-sL, nessuna
    sonda inviata) invece di reimplementare la sintassi target di nmap.
    Ritorna [] se l'espansione fallisce o produce un solo host: in quel
    caso il chiamante scansiona il target originale in un'unica invocazione,
    senza batching (nessun beneficio a spezzare un target già singolo)."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path = Path(f.name)
    try:
        cmd = ["-sL", "-n", *_exclude_args(extra_args_str), "-oX", str(xml_path), *shlex.split(target)]
        nmap_proxy_client.run_nmap(cmd, capture_output=True, text=True, timeout=timeout)
        if not xml_path.exists():
            return []
        hosts = nmap_parser.parse_nmap_xml(xml_path)
        ips = [h["ip"] for h in hosts if h.get("ip")]
        return ips if len(ips) > 1 else []
    except Exception:
        return []
    finally:
        xml_path.unlink(missing_ok=True)


def _enrich_and_store(conn, host):
    """Raccoglie le stesse evidenze extra usate per la classificazione AI
    (banner HTTP, condivisioni SMB, banner TCP grezzi — vedi enrich.py) per
    UN host già registrato, e le salva subito invece di aspettare che uno
    finisca per calcolarle solo transitoriamente. A differenza di
    classify_devices.py (che chiama enrich_host una volta per gruppo di
    host con fingerprint identico, per limitare le richieste) qui viene
    chiamata per ogni singolo host trovato: una Scansione nmap personalizzata
    è per sua natura mirata/su pochi host, non l'intera rete."""
    try:
        evidence = enrich.enrich_host(host["ip"], host["services"])
    except Exception as e:
        evidence = {"error": str(e)}
    scanner_db.set_host_enrichment(conn, host["id"], evidence)
    return evidence


def _run_batch(cmd, xml_out, conn, target_count, timeout):
    result = scan_pipeline.run_and_store(cmd, xml_out, conn, target_count=target_count, timeout=timeout)
    if result["status"] == "timeout":
        print(f"Timeout dopo {timeout}s: uso i risultati parziali eventualmente scritti.", flush=True)
    elif result["status"] == "error":
        print(f"Errore durante la scansione: {result['error_detail']}", flush=True)
    for host in result["hosts_up"]:
        print(f"  {host['ip']}: {len(host['services'])} servizi, tipo dedotto '{host['device_type']}'", flush=True)
        if any(s.get("state") == "open" for s in host["services"]):
            evidence = _enrich_and_store(conn, host)
            if evidence:
                print(f"    arricchito: {', '.join(evidence.keys())}", flush=True)
    return result


def run_scan(target, extra_args_str, db_path, scans_dir, timeout=1800, batch_size=DEFAULT_BATCH_SIZE):
    """Esegue la scansione, parsa l'XML e salva/aggiorna gli host trovati
    (pipeline comune con scan_and_store.py, vedi scan_pipeline.py). Se il
    target si espande in più host, esegue a batch (vedi il docstring del
    modulo). Ritorna un dict di riepilogo {'hosts_found', 'hosts_up', 'status'}."""
    scans_dir = Path(scans_dir)
    scans_dir.mkdir(parents=True, exist_ok=True)

    conn = scanner_db.connect(db_path)
    scanner_db.init_db(conn)

    expanded = expand_targets(target, extra_args_str)
    if len(expanded) > MAX_HOSTS_TO_BATCH:
        print(f"Target espanso in {len(expanded)} host: troppi per il batching per host "
              f"(oltre {MAX_HOSTS_TO_BATCH}), eseguito in un'unica invocazione come prima.", flush=True)
        expanded = []

    if not expanded:
        ts = scan_pipeline.now_iso().replace(":", "-")
        xml_out = scans_dir / f"customscan_{ts}.xml"
        cmd = build_command(extra_args_str, xml_out, target=target)
        print(f"Comando: nmap {' '.join(cmd)}", flush=True)
        result = _run_batch(cmd, xml_out, conn, None, timeout)
        conn.close()
        return {
            "hosts_found": result["hosts_found"], "hosts_up": len(result["hosts_up"]),
            "status": result["status"],
        }

    batches = [expanded[i:i + batch_size] for i in range(0, len(expanded), batch_size)]
    print(f"Target espanso in {len(expanded)} host: eseguito a {len(batches)} batch da {batch_size} "
          f"(risultati/traffico si aggiornano batch per batch, non solo a fine scansione).", flush=True)

    total_found = total_up = 0
    worst_status = "ok"
    for idx, batch_ips in enumerate(batches, start=1):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("\n".join(batch_ips))
            ip_list_file = Path(f.name)
        ts = scan_pipeline.now_iso().replace(":", "-")
        xml_out = scans_dir / f"customscan_batch{idx:03d}_{ts}.xml"
        cmd = build_command(extra_args_str, xml_out, ip_list_file=ip_list_file)
        print(f"[batch {idx}/{len(batches)}] {len(batch_ips)} host -> nmap {' '.join(cmd)}", flush=True)
        try:
            result = _run_batch(cmd, xml_out, conn, len(batch_ips), timeout)
        finally:
            ip_list_file.unlink(missing_ok=True)
        total_found += result["hosts_found"]
        total_up += len(result["hosts_up"])
        if _STATUS_RANK[result["status"]] > _STATUS_RANK[worst_status]:
            worst_status = result["status"]
        print(f"[batch {idx}/{len(batches)}] completato ({result['status']}): "
              f"{len(result['hosts_up'])}/{len(batch_ips)} host registrati", flush=True)

    conn.close()
    return {"hosts_found": total_found, "hosts_up": total_up, "status": worst_status}


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
    parser.add_argument("--timeout", type=int, default=1800, help="Timeout (s) di ogni invocazione nmap (per batch)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                         help="Host per invocazione nmap quando il target si espande in più host (default 20)")
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        print(f"Avvio scansione nmap personalizzata su: {args.target}", flush=True)
        result = run_scan(args.target, args.args, args.db, args.scans_dir, args.timeout, args.batch_size)
        print(
            f"Completato ({result['status']}): {result['hosts_up']}/{result['hosts_found']} "
            f"host up registrati/aggiornati."
        )


if __name__ == "__main__":
    main()
