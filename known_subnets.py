#!/usr/bin/env python3
"""Reti registrate nell'inventario aziendale (tabella known_subnets),
importate da data/reti.txt (una subnet CIDR e il numero di host attivi
rilevati su quella subnet in una scansione precedente, per riga, separati
da spazi/tab) e scansionabili in blocco dal menu Scansioni.

A differenza di Scansione nmap personalizzata (custom_scan.py: target
libero, tipicamente pochi host digitati a mano) qui il target sono le RETI
note dell'organizzazione, potenzialmente centinaia di /24 (data/reti.txt ne
contiene oltre 1000): ogni subnet è scansionata come invocazione nmap
indipendente (stessa logica di "risultati progressivi batch per batch" di
custom_scan.run_scan), ma SENZA passare per custom_scan.expand_targets
(che farebbe un -sL preliminare per espandere in singoli IP: impraticabile
su centinaia di migliaia di indirizzi totali, e comunque inutile qui dato
che la granularità di batch voluta è già "una subnet" e non "un host").

DUE PASSATE SEPARATE PER SUBNET (main + SNMP): una singola invocazione nmap
che mescola scan TCP+UDP pesante (molte porte, -sV, -O) con --script SNMP
si è dimostrata SISTEMATICAMENTE inaffidabile per la cattura degli script
SNMP durante i test manuali di questa funzionalità — verificato su un
router Cisco reale (10.20.0.3): la porta UDP 161 risultava "open" con
banner SNMP valido, eppure lo script snmp-info non produceva mai output
nella stessa invocazione pesante, mentre una passata SNMP-only leggera e
indipendente (anche eseguita IMMEDIATAMENTE dopo lo scan pesante sullo
stesso host) lo cattura sempre in modo affidabile. Causa più probabile:
molti dispositivi di rete (soprattutto router/switch più datati) applicano
un rate-limiting sul proprio control-plane (CoPP) quando ricevono troppe
probe in sequenza ravvicinata, rendendo il servizio SNMP temporaneamente
non responsivo proprio nel momento in cui NSE tenta di interrogarlo (dopo
la scansione porte + version detection + OS detection). La soluzione
adottata qui è quindi eseguire, per ogni subnet, DUE invocazioni nmap
indipendenti: una principale (TCP: invisibilità/evasione, OS, servizi) e
una separata e più leggera dedicata solo a UDP 161/162 (script SNMP) — non
solo più affidabile, ma anche più "invisibile" nel senso richiesto (poche
probe mirate sulla porta SNMP, invece di mischiarle nel mezzo di uno scan
pesante).

Uso:
    python known_subnets.py --import data/reti.txt
    python known_subnets.py --args "-sn"
    python known_subnets.py --only-active --args "-Pn -T3 --top-ports 50" --snmp-args ""
"""

import argparse
import ipaddress
import sys
from pathlib import Path

import custom_scan
import scan_pipeline
import scanner_db
from job_lock import JobLock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
LOCK_FILE = BASE / "known_subnets_scan.lock"

_STATUS_RANK = {"ok": 0, "timeout": 1, "error": 2}

# Preset di default per il tab "Reti registrate" (vedi templates/custom_scan.html
# e app.py:nmap_scan_page, che li passa al template come valori pre-compilati/
# ripristinabili). Pensati per essere il più "invisibili" possibile (evasione
# firewall/IDS) mantenendo comunque l'obiettivo di rilevare OS e servizi, a
# basso effort (T2, --max-parallelism 2, --max-retries basso): vedi il
# docstring del modulo per il perché SNMP è un preset separato.
# '--stats-every 15s': nmap stampa periodicamente un riepilogo di
# avanzamento ("Stats: ... hosts completed, ... undergoing Service Scan",
# percentuale/ETA per fase) invece di restare silenzioso fino alla fine —
# essenziale con T2 su un /24 intero, dove una singola invocazione può
# durare minuti senza alcun output. Visibile nel log del job grazie allo
# streaming dell'output di nmap non appena prodotto (vedi
# nmap_proxy_client.run_nmap/nmap_conn_count.run_and_count_connections).
DEFAULT_MAIN_ARGS = (
    "-sS -T2 --max-parallelism 2 --max-retries 1 --randomize-hosts "
    "-f --data-length 20 "
    "-Pn "
    "-p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5900,8080 "
    "-sV --version-intensity 2 -O --osscan-guess "
    "--host-timeout 5m --stats-every 15s --script default"
)
DEFAULT_SNMP_ARGS = (
    "-sU -p 161,162 -T2 --max-parallelism 2 --max-retries 1 --host-timeout 3m --stats-every 15s "
    "--script snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat,snmp-processes,"
    "snmp-win32-software,snmp-win32-services,snmp-win32-shares,snmp-win32-users,snmp-ios-config"
)


def parse_reti_file(path):
    """Legge un file con una subnet CIDR per riga, spazi/tab come separatore
    e terminatore di riga CR/LF o LF, in una delle due forme:
      - 'CIDR' (solo la subnet, es. data/subnets.txt): known_active_hosts
        resta None (nessun dato storico disponibile per quella subnet).
      - 'CIDR  known_active_hosts' (es. data/reti.txt): il secondo campo è
        il numero di host attivi rilevati su quella subnet in una scansione
        precedente (NON un codice sito/gruppo).
    Ritorna [(cidr, known_active_hosts_o_None), ...]. Righe vuote o non
    conformi (CIDR non valido, più di 2 colonne, campo numerico presente ma
    non numerico) sono segnalate su stderr e saltate, invece di interrompere
    l'intero import per una singola riga malformata."""
    rows = []
    for lineno, raw_line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) not in (1, 2):
            print(f"riga {lineno} ignorata (attese 1 o 2 colonne, trovate {len(parts)}): {raw_line!r}",
                  file=sys.stderr)
            continue
        cidr = parts[0]
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            print(f"riga {lineno} ignorata (CIDR non valido '{cidr}'): {e}", file=sys.stderr)
            continue
        known_active_hosts = None
        if len(parts) == 2:
            try:
                known_active_hosts = int(parts[1])
            except ValueError:
                print(f"riga {lineno} ignorata (numero host attivi non numerico '{parts[1]}')", file=sys.stderr)
                continue
        rows.append((str(network), known_active_hosts))
    return rows


def import_from_file(db_path, path, replace=False):
    """Importa/aggiorna le subnet note dal file indicato. Se replace,
    elimina PRIMA tutte le subnet note esistenti (reset completo, es. per
    cambiare sorgente dati) invece di limitarsi a un upsert su cidr — perde
    last_scanned_at di tutte, non solo di quelle assenti dal nuovo file.
    Ritorna {'parsed', 'imported'} (righe valide trovate / righe
    effettivamente importate nel DB, uguali salvo bug: nessuna deduplica
    qui, l'upsert su cidr in scanner_db.import_known_subnets se ne occupa)."""
    rows = parse_reti_file(path)
    conn = scanner_db.connect(db_path)
    scanner_db.init_db(conn)
    try:
        if replace:
            scanner_db.clear_known_subnets(conn)
        imported = scanner_db.import_known_subnets(conn, rows)
    finally:
        conn.close()
    return {"parsed": len(rows), "imported": imported}


def run_scan(only_active, extra_args_str, snmp_args_str, db_path, scans_dir, timeout=1800, auto_enrich=True,
             limit=None, cidrs=None):
    """Scandisce le subnet note. Se 'cidrs' è indicato (lista di CIDR scelti
    manualmente, es. dalle caselle di selezione della UI), scandisce
    ESATTAMENTE quelle, ignorando only_active/limit. Altrimenti, scandisce
    la selezione automatica (tutte, o solo quelle con host attivi noti da un
    rilevamento precedente se only_active), al massimo 'limit' per questo
    avvio (le mai scansionate/scansionate meno di recente hanno priorità —
    vedi scanner_db.list_known_subnets — così avvii ripetuti con lo stesso
    limit progrediscono sulle successive invece di ripetere sempre le
    stesse). Per ogni subnet, esegue DUE invocazioni nmap indipendenti (vedi
    il docstring del modulo per il perché): una principale con
    extra_args_str (TCP/OS/servizi), e — se snmp_args_str non è vuoto — una
    separata con snmp_args_str (tipicamente solo UDP 161/162 + script SNMP).
    Ritorna {'hosts_found', 'hosts_up', 'status', 'subnets_scanned'}
    (conteggi basati sulla sola passata principale: la passata SNMP
    arricchisce gli stessi host, non ne trova di nuovi)."""
    scans_dir = Path(scans_dir)
    scans_dir.mkdir(parents=True, exist_ok=True)

    conn = scanner_db.connect(db_path)
    scanner_db.init_db(conn)

    if cidrs:
        subnets = [{"cidr": c} for c in cidrs]
    else:
        subnets = scanner_db.list_known_subnets(conn, only_with_known_hosts=only_active, limit=limit)
    if not subnets:
        conn.close()
        print("Nessuna subnet nota trovata (importarle prima con --import data/reti.txt, "
              "oppure nessuna ha host attivi noti se --only-active è stato usato).", flush=True)
        return {"hosts_found": 0, "hosts_up": 0, "status": "ok", "subnets_scanned": 0}

    enrichment_args = custom_scan.build_enrichment_args(extra_args_str) if auto_enrich else None
    if auto_enrich and enrichment_args is None:
        print("Rilevamento OS/versione già incluso negli argomenti scelti: nessuna passata di "
              "arricchimento automatico aggiuntiva.", flush=True)

    total_found = total_up = 0
    worst_status = "ok"
    for idx, subnet in enumerate(subnets, start=1):
        cidr = subnet["cidr"]
        batch_label = f"[{idx}/{len(subnets)}] {cidr}: "

        ts = scan_pipeline.now_iso().replace(":", "-")
        xml_out = scans_dir / f"netscan_{idx:04d}_{ts}.xml"
        cmd = custom_scan.build_command(extra_args_str, xml_out, target=cidr)
        print(f"{batch_label}nmap {' '.join(cmd)}", flush=True)
        result = custom_scan._run_batch(
            cmd, xml_out, conn, None, timeout, scans_dir=scans_dir,
            batch_label=batch_label, enrichment_args=enrichment_args,
        )
        total_found += result["hosts_found"]
        total_up += len(result["hosts_up"])
        if _STATUS_RANK[result["status"]] > _STATUS_RANK[worst_status]:
            worst_status = result["status"]
        print(f"{batch_label}completato ({result['status']}): "
              f"{len(result['hosts_up'])}/{result['hosts_found']} host up", flush=True)

        if snmp_args_str.strip():
            ts_snmp = scan_pipeline.now_iso().replace(":", "-")
            xml_out_snmp = scans_dir / f"netscan_{idx:04d}_snmp_{ts_snmp}.xml"
            cmd_snmp = custom_scan.build_command(snmp_args_str, xml_out_snmp, target=cidr)
            snmp_label = f"{batch_label}(SNMP) "
            print(f"{snmp_label}nmap {' '.join(cmd_snmp)}", flush=True)
            snmp_result = custom_scan._run_batch(
                cmd_snmp, xml_out_snmp, conn, None, timeout, scans_dir=scans_dir, batch_label=snmp_label,
            )
            if _STATUS_RANK[snmp_result["status"]] > _STATUS_RANK[worst_status]:
                worst_status = snmp_result["status"]
            print(f"{snmp_label}completato ({snmp_result['status']}): "
                  f"{len(snmp_result['hosts_up'])} host con risposta SNMP", flush=True)

        scanner_db.mark_subnet_scanned(conn, cidr)

    conn.close()
    return {"hosts_found": total_found, "hosts_up": total_up, "status": worst_status,
            "subnets_scanned": len(subnets)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--import", dest="import_path", metavar="FILE",
                         help="Importa/aggiorna le subnet note da questo file invece di scandire "
                              "(es. data/reti.txt), poi esce")
    parser.add_argument("--only-active", action="store_true",
                         help="Scandisce solo le subnet con host attivi noti da un rilevamento "
                              "precedente (default: tutte, incluse quelle note come vuote)")
    parser.add_argument("--args", default=DEFAULT_MAIN_ARGS,
                         help="Argomenti nmap per la passata principale (TCP/OS/servizi)")
    parser.add_argument("--snmp-args", default=DEFAULT_SNMP_ARGS,
                         help="Argomenti nmap per la passata SNMP separata (tipicamente -sU -p161,162 "
                              "--script snmp-*); vuoto per disabilitarla")
    parser.add_argument(
        "--db", default=scanner_db.resolve_db_target(BASE / "instance" / "inventory.db"),
        help="Percorso database SQLite, oppure URL postgresql://... (default: DATABASE_URL se impostata)",
    )
    parser.add_argument("--scans-dir", default=str(BASE / "scans"), help="Cartella per gli XML grezzi")
    parser.add_argument("--timeout", type=int, default=1800, help="Timeout (s) di ogni invocazione nmap (per subnet)")
    parser.add_argument("--limit", type=int, default=None,
                         help="Numero massimo di subnet da scansionare in questo avvio, per selezione "
                              "automatica per priorità (default: nessun limite; ignorato se --cidrs è indicato)")
    parser.add_argument("--cidrs", default="",
                         help="Lista di CIDR separati da virgola da scansionare ESATTAMENTE (selezione "
                              "manuale, es. dalle caselle della UI): se indicato, ha priorità su "
                              "--only-active/--limit, che vengono ignorati")
    parser.add_argument("--no-auto-enrich", action="store_true",
                         help="Disabilita la seconda passata automatica -O -sV sugli host trovati quando "
                              "gli argomenti della passata principale non la includono già (attiva per default)")
    args = parser.parse_args()

    if args.import_path:
        summary = import_from_file(args.db, args.import_path)
        print(f"Importate {summary['imported']}/{summary['parsed']} subnet da {args.import_path}.")
        return

    cidrs = [c.strip() for c in args.cidrs.split(",") if c.strip()] or None

    with JobLock(LOCK_FILE):
        if cidrs:
            label = f"{len(cidrs)} subnet selezionate manualmente"
        else:
            label = "solo subnet con host attivi noti" if args.only_active else "tutte le reti registrate"
            label += f", limite {args.limit} subnet" if args.limit else ""
        print(f"Avvio scansione reti registrate ({label})", flush=True)
        result = run_scan(args.only_active, args.args, args.snmp_args, args.db, args.scans_dir, args.timeout,
                           auto_enrich=not args.no_auto_enrich, limit=args.limit, cidrs=cidrs)
        print(
            f"Completato ({result['status']}): {result['subnets_scanned']} subnet, "
            f"{result['hosts_up']}/{result['hosts_found']} host up registrati/aggiornati."
        )


if __name__ == "__main__":
    main()
