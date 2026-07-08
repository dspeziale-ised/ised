#!/usr/bin/env python3
"""Arricchimento NetBIOS/SMB per gli host già identificati come Windows
(os_name/os_family da una scansione -O precedente):
  - nbstat (UDP 137): nome NetBIOS della macchina, workgroup/domain,
    indirizzo MAC — utile anche quando SMB è filtrato ma NetBIOS resta
    raggiungibile.
  - smb-os-discovery (TCP 445): OS/build, nome NetBIOS, domain/workgroup,
    ora di sistema — spesso più dettagliato di nbstat quando SMB è aperto.
  - smb-enum-* (TCP 445): famiglia di script SMB (condivisioni, utenti,
    sessioni, domini, gruppi, processi — quanto effettivamente disponibile
    dipende dai permessi anonimi/guest consentiti dal host).

Usata in due punti:
- auto_enrich.py: dopo ogni batch di arricchimento OS/servizi, sugli host
  di QUEL batch risultati Windows (arricchimento "a catena": chi ha appena
  scoperto l'OS Windows riceve subito anche questi script, senza aspettare
  un ciclo separato).
- app.py (bottone 'Arricchisci Windows' nella pagina Host): su TUTTI gli
  host già noti come Windows, indipendentemente da quando sono stati
  scoperti — copre anche quelli arricchiti prima che questa funzionalità
  esistesse.

Usa scanner_db.merge_scanned_services (aggiorna/aggiunge SOLO le porte
137/udp e 445/tcp), non scan_pipeline.run_and_store (che sostituirebbe
interamente le porte note dell'host, sostituzione corretta per una
scansione OS/servizi completa ma NON per questa scansione mirata a due
porte specifiche) — stesso motivo/pattern di app.py:host_snmp_scan.

Uso:
    python enrich_windows.py                  # tutti gli host Windows noti
    python enrich_windows.py --batch-size 10
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

import custom_scan
import nmap_parser
import nmap_proxy_client
import scanner_db
from job_lock import JobLock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
LOCK_FILE = BASE / "enrich_windows.lock"

DEFAULT_BATCH_SIZE = 20
DEFAULT_HOST_TIMEOUT = "90s"
DEFAULT_MAX_PARALLELISM = 4
# -sS -sU insieme + porte T:/U: separate: TCP 445 (SMB) per smb-os-discovery/
# smb-enum-*, UDP 137 (NetBIOS) per nbstat — a differenza della passata
# principale/SNMP di known_subnets.py (dove mischiare TCP+UDP+script nella
# stessa invocazione si era rivelato inaffidabile, vedi la nota nel
# docstring di known_subnets.py), qui gli script agiscono su porte diverse
# e ciascuno tipicamente su un solo probe diretto (non un port/OS scan
# pesante che affoga il device) — nessun problema analogo osservato.
DEFAULT_ARGS = (
    "-Pn -sS -sU -p T:445,U:137 "
    "--script nbstat,smb-os-discovery,smb-enum-* --max-retries 1"
)


def is_windows(os_name, os_family):
    text = f"{os_name or ''} {os_family or ''}".lower()
    return "windows" in text


def find_windows_hosts(conn):
    """Host già noti come Windows (os_name/os_family da una scansione -O
    precedente). Ritorna [{'id', 'ip'}, ...]."""
    rows = conn.execute("SELECT id, ip, os_name, os_family FROM hosts").fetchall()
    return [{"id": r["id"], "ip": r["ip"]} for r in rows if is_windows(r["os_name"], r["os_family"])]


def enrich_hosts(conn, ips, scans_dir, batch_size=DEFAULT_BATCH_SIZE, host_timeout=DEFAULT_HOST_TIMEOUT,
                  max_parallelism=DEFAULT_MAX_PARALLELISM, timeout=180, label_prefix=""):
    """Esegue nmap --script nbstat sugli IP indicati, a batch, unendo il
    risultato (porta 137/udp + script nbstat) nei rispettivi host già
    esistenti (per IP) — non crea nuovi host, un IP senza host già
    registrato viene ignorato silenziosamente (non dovrebbe capitare, dato
    che gli IP arrivano da host già noti come Windows). Ritorna
    {'hosts_found', 'hosts_enriched', 'status'}."""
    if not ips:
        return {"hosts_found": 0, "hosts_enriched": 0, "status": "ok"}

    scans_dir = Path(scans_dir)
    scans_dir.mkdir(parents=True, exist_ok=True)

    total_enriched = 0
    worst_status = "ok"
    status_rank = {"ok": 0, "timeout": 1, "error": 2}

    for i in range(0, len(ips), batch_size):
        batch = ips[i:i + batch_size]
        batch_label = f"{label_prefix}[nbstat {i // batch_size + 1}] "
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("\n".join(batch))
            ip_list_file = Path(f.name)

        args = f"{DEFAULT_ARGS} --max-parallelism {max_parallelism} --host-timeout {host_timeout}"
        xml_out = scans_dir / f"nbstat_{i // batch_size + 1}_{i}.xml"
        cmd = custom_scan.build_command(args, xml_out, ip_list_file=ip_list_file)
        print(f"{batch_label}{len(batch)} host -> nmap {' '.join(cmd)}", flush=True)

        status = "ok"
        try:
            nmap_proxy_client.run_nmap(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            status = "timeout"
            print(f"{batch_label}Timeout dopo {timeout}s: uso i risultati parziali.", flush=True)
        except Exception as e:
            status = "error"
            print(f"{batch_label}Errore durante la scansione: {e}", flush=True)
        finally:
            ip_list_file.unlink(missing_ok=True)

        if xml_out.exists():
            for host in nmap_parser.parse_nmap_xml(xml_out):
                row = conn.execute("SELECT id FROM hosts WHERE ip = ?", (host["ip"],)).fetchone()
                if not row:
                    continue
                scanner_db.merge_scanned_services(conn, row["id"], host.get("services", []))
                script_ids = [
                    script.get("id")
                    for svc in host.get("services", [])
                    for script in svc.get("scripts", [])
                ]
                # nbstat/smb-os-discovery/smb-enum-* sono script A LIVELLO
                # HOST (<hostscript> nell'XML), non legati a una porta
                # specifica — un parser che guardasse solo dentro <port>
                # (come qui sopra per script_ids) li perderebbe del tutto.
                # Vanno quindi uniti alle evidenze extra dell'host (stesso
                # meccanismo di enrich.py per i banner HTTP/SMB), non a
                # service_scripts (pensata per script legati a una porta).
                host_scripts = host.get("host_scripts") or []
                if host_scripts:
                    evidence = {s["id"]: s["output"] for s in host_scripts if s.get("id")}
                    scanner_db.merge_host_enrichment(conn, row["id"], {"netbios_smb": evidence})
                    script_ids.extend(evidence.keys())
                if script_ids:
                    total_enriched += 1
                    print(f"  {host['ip']}: arricchito ({', '.join(script_ids)})", flush=True)
            xml_out.unlink(missing_ok=True)

        if status_rank[status] > status_rank[worst_status]:
            worst_status = status

    return {"hosts_found": len(ips), "hosts_enriched": total_enriched, "status": worst_status}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", default=scanner_db.resolve_db_target(BASE / "instance" / "inventory.db"),
        help="Percorso database SQLite, oppure URL postgresql://... (default: DATABASE_URL se impostata)",
    )
    parser.add_argument("--scans-dir", default=str(BASE / "scans"), help="Cartella per gli XML grezzi")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--host-timeout", default=DEFAULT_HOST_TIMEOUT)
    parser.add_argument("--max-parallelism", type=int, default=DEFAULT_MAX_PARALLELISM)
    parser.add_argument("--timeout", type=int, default=180, help="Timeout (s) di ogni invocazione nmap (per batch)")
    args = parser.parse_args()

    with JobLock(LOCK_FILE):
        conn = scanner_db.connect(args.db)
        scanner_db.init_db(conn)
        targets = find_windows_hosts(conn)
        print(f"Avvio arricchimento NetBIOS su {len(targets)} host Windows noti.", flush=True)
        result = enrich_hosts(
            conn, [h["ip"] for h in targets], args.scans_dir, batch_size=args.batch_size,
            host_timeout=args.host_timeout, max_parallelism=args.max_parallelism, timeout=args.timeout,
        )
        conn.close()
        print(
            f"Completato ({result['status']}): {result['hosts_enriched']}/{result['hosts_found']} "
            f"host Windows arricchiti con dati NetBIOS."
        )


if __name__ == "__main__":
    main()
