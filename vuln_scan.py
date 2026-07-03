#!/usr/bin/env python3
"""Scansiona le vulnerabilità (CVE) note per i servizi con CPE identificata.

Fonte primaria: l'API pubblica NVD (nvd_client.py), interrogata direttamente
con la CPE — non richiede nessuna scansione dal vivo, solo la stringa CPE
già rilevata durante lo scan -sV. Se NVD non risponde o non trova nulla, si
ricorre allo script NSE 'vulners' di nmap (interroga vulners.com) su un
host rappresentativo come fallback.

Per limitare il numero di richieste esterne, i servizi vengono raggruppati
per CPE identica (stesso prodotto/versione, es. cpe:/a:openbsd:openssh:8.2):
il lookup avviene una sola volta per CPE, il risultato viene messo in cache
(tabella cve_cache) e applicato a TUTTI gli host che condividono quella CPE.

Uso:
    python vuln_scan.py                    # tutte le CPE non ancora in cache (o scadute)
    python vuln_scan.py --force             # riesegue il lookup anche se già in cache
    python vuln_scan.py --max-age-days 7    # considera 'fresca' la cache solo per 7 giorni
    python vuln_scan.py --limit 5           # solo le prime N CPE (per test)
    python vuln_scan.py --no-nvd            # salta NVD, usa solo nmap/vulners
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path
from xml.etree import ElementTree as ET

import cve_lookup
import nmap_proxy_client
import nvd_client
import scanner_db
from job_lock import JobLock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
DB_PATH = scanner_db.resolve_db_target(BASE / "instance" / "inventory.db")
LOCK_FILE = BASE / "vuln.lock"
# Rate limit pubblico NVD senza API key: 5 richieste/30s (con key: 50/30s).
# Una pausa conservativa evita di beccare il rate limit su run lunghi.
NVD_SLEEP_NO_KEY = 6.5
NVD_SLEEP_WITH_KEY = 0.7


def build_cpe_groups(conn):
    """Ritorna dict {cpe: [(host_id, ip, port), ...]} per i servizi aperti
    con una CPE nota."""
    rows = conn.execute(
        """SELECT s.cpe AS cpe, s.port AS port, h.id AS host_id, h.ip AS ip
           FROM services s
           JOIN hosts h ON h.id = s.host_id
           WHERE s.cpe IS NOT NULL AND s.cpe != '' AND s.state = 'open'
           ORDER BY h.ip, s.port"""
    ).fetchall()

    groups = {}
    for r in rows:
        groups.setdefault(r["cpe"], []).append((r["host_id"], r["ip"], r["port"]))
    return groups


def fetch_vulners_output(ip, port, timeout=90):
    """Esegue nmap --script vulners su un singolo host:porta e ritorna
    l'output testuale dello script 'vulners' (o None se assente/errore)."""
    try:
        result = nmap_proxy_client.run_nmap(
            ["-Pn", "-p", str(port), "--script", "vulners", "-oX", "-", ip],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  [!] Timeout nmap/vulners su {ip}:{port}")
        return None

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError:
        print(f"  [!] Output nmap non valido per {ip}:{port}")
        return None

    for script in root.iter("script"):
        if script.get("id") == "vulners":
            return script.get("output")
    return None


def fetch_cves(cpe, rep_ip, rep_port, use_nvd=True):
    """Cerca le CVE per una CPE: prima l'API NVD (diretta, nessuna
    scansione dal vivo), poi nmap --script vulners come fallback se NVD
    non risponde o non trova nulla. Ritorna (cve_list, source)."""
    if use_nvd:
        try:
            cves = nvd_client.fetch_cves_for_cpe(cpe)
            if cves:
                return cves, "nvd"
            print(f"  NVD: nessuna CVE per {cpe}, provo vulners come conferma...")
        except nvd_client.NvdError as e:
            print(f"  [!] NVD non disponibile per {cpe} ({e}), passo a vulners...")

    print(f"Lookup CVE per {cpe} via nmap/vulners (host {rep_ip}:{rep_port})...")
    output = fetch_vulners_output(rep_ip, rep_port)
    return (cve_lookup.parse_vulners_output(output) if output else []), "vulners"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Riesegue il lookup anche per CPE già in cache")
    parser.add_argument("--max-age-days", type=int, default=30, help="Validità della cache CVE in giorni")
    parser.add_argument("--limit", type=int, help="Limita il numero di CPE da elaborare (per test)")
    parser.add_argument("--no-nvd", action="store_true", help="Salta l'API NVD, usa solo nmap/vulners")
    args = parser.parse_args()
    use_nvd = not args.no_nvd
    nvd_sleep = NVD_SLEEP_WITH_KEY if nvd_client.has_api_key() else NVD_SLEEP_NO_KEY

    with JobLock(LOCK_FILE):
        conn = scanner_db.connect(str(DB_PATH))
        scanner_db.init_db(conn)
        scanner_db.ensure_service_columns(conn)

        groups = build_cpe_groups(conn)
        print(f"{len(groups)} CPE distinte trovate tra i servizi scansionati "
              f"(su {sum(len(v) for v in groups.values())} servizio/host totali).")
        if use_nvd:
            print(f"Fonte primaria: API NVD ({'con' if nvd_client.has_api_key() else 'senza'} "
                  f"API key, pausa {nvd_sleep}s tra le richieste).")

        items = list(groups.items())
        if args.limit:
            items = items[: args.limit]

        cached_hits = 0
        fresh_lookups = 0
        total_cves_assigned = 0
        sources = {}

        for cpe, host_ports in items:
            rep_host_id, rep_ip, rep_port = host_ports[0]
            source_holder = {}

            def fetch():
                cve_list, source = fetch_cves(cpe, rep_ip, rep_port, use_nvd=use_nvd)
                source_holder["source"] = source
                return cve_list

            if args.force:
                cve_list = fetch()
                scanner_db.set_cached_cve(conn, cpe, cve_list)
                from_cache = False
            else:
                cve_list, from_cache = cve_lookup.get_or_fetch(
                    conn, cpe, fetch, max_age_days=args.max_age_days
                )

            source = source_holder.get("source", "cache")
            if from_cache:
                cached_hits += 1
            else:
                fresh_lookups += 1
                sources[source] = sources.get(source, 0) + 1
                if use_nvd and source == "nvd":
                    time.sleep(nvd_sleep)

            for host_id, ip, port in host_ports:
                scanner_db.set_host_vulnerabilities(conn, host_id, port, cpe, cve_list, source=source)
            total_cves_assigned += len(cve_list) * len(host_ports)

            tag = "(cache)" if from_cache else f"(nuovo, {source})"
            if cve_list:
                print(f"  {cpe} {tag}: {len(cve_list)} CVE -> applicate a {len(host_ports)} host/porta")
            else:
                print(f"  {cpe} {tag}: nessuna CVE nota")

        conn.close()
        if sources:
            print(f"\nFonti usate per i lookup nuovi: {sources}")
        print(
            f"\nCompletato: {len(items)} CPE elaborate "
            f"({fresh_lookups} lookup nuovi, {cached_hits} da cache), "
            f"{total_cves_assigned} associazioni host/CVE aggiornate."
        )


if __name__ == "__main__":
    main()
