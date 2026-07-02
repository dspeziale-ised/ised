"""Estrazione e caching dei CVE trovati dagli script NSE 'vulners' di nmap.

Il matching vero e proprio con i CVE avviene dentro nmap stesso (lo script
NSE 'vulners' interroga vulners.com usando la CPE del servizio); qui ci
occupiamo di: (1) parsare l'output testuale dello script per estrarre
CVE/CVSS/URL in una lista di dict, (2) cachare il risultato per CPE così non
serve ripetere la query per la stessa combinazione prodotto/versione.
"""

import datetime
import re

import scanner_db

# Righe tipiche dell'output di vulners.nse:
#   CVE-2021-41617  7.0     https://vulners.com/cve/CVE-2021-41617
#   CVE-2020-14145  5.9     https://vulners.com/cve/CVE-2020-14145 *EXPLOIT*
_CVE_LINE_RE = re.compile(r"(CVE-\d{4}-\d+)\s+([\d.]+)\s+(\S+)", re.IGNORECASE)


def parse_vulners_output(output):
    """Estrae le CVE da un output NSE di 'vulners'. Ritorna una lista di
    dict {id, cvss, url}, deduplicata per CVE (tiene il punteggio più alto
    se compare più volte) e ordinata per punteggio decrescente."""
    if not output:
        return []
    found = {}
    for match in _CVE_LINE_RE.finditer(output):
        cve_id, cvss_raw, url = match.group(1).upper(), match.group(2), match.group(3)
        try:
            cvss = float(cvss_raw)
        except ValueError:
            cvss = None
        url = url.rstrip("*").strip()
        if cve_id not in found or (cvss or 0) > (found[cve_id]["cvss"] or 0):
            found[cve_id] = {"id": cve_id, "cvss": cvss, "url": url}
    return sorted(found.values(), key=lambda c: c["cvss"] or 0, reverse=True)


def _is_fresh(fetched_at, max_age_days):
    if not fetched_at:
        return False
    try:
        age = datetime.datetime.now() - datetime.datetime.fromisoformat(fetched_at)
    except (ValueError, TypeError):
        return False
    return age.days < max_age_days


def get_or_fetch(conn, cpe, fetch_fn, max_age_days=30):
    """Ritorna (cve_list, from_cache). Usa la cache se presente e più
    recente di max_age_days, altrimenti chiama fetch_fn() e aggiorna la
    cache con il risultato (anche se è una lista vuota, per non ripetere
    inutilmente lookup su prodotti senza CVE note)."""
    cached = scanner_db.get_cached_cve(conn, cpe)
    if cached is not None:
        cve_list, fetched_at = cached
        if _is_fresh(fetched_at, max_age_days):
            return cve_list, True

    cve_list = fetch_fn()
    scanner_db.set_cached_cve(conn, cpe, cve_list)
    return cve_list, False
