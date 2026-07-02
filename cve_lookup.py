"""Estrazione e caching dei CVE trovati dagli script NSE 'vulners' di nmap.

Il matching vero e proprio con i CVE avviene dentro nmap stesso (lo script
NSE 'vulners' interroga vulners.com usando la CPE del servizio); qui ci
occupiamo di: (1) parsare l'output testuale dello script per estrarre
CVE/CVSS/URL in una lista di dict, (2) cachare il risultato per CPE così non
serve ripetere la query per la stessa combinazione prodotto/versione.
"""

import csv
import datetime
import io
import json
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


def _normalize_cve_record(row):
    """Normalizza un record grezzo (da CSV o JSON) in {id, cvss, url}."""
    cvss_raw = row.get("cvss")
    cvss = None
    if cvss_raw not in (None, ""):
        try:
            cvss = float(cvss_raw)
        except (TypeError, ValueError):
            cvss = None
    cve_id = (row.get("id") or row.get("cve_id") or row.get("cve") or "").strip().upper()
    return {"id": cve_id, "cvss": cvss, "url": (row.get("url") or "").strip()}


def parse_cve_import(content_bytes, filename=""):
    """Parsa un file di import per pre-popolare la cache CVE. Formati
    supportati (rilevati da estensione, altrimenti dal primo carattere):

    - CSV con colonne: cpe,cve_id,cvss,url (una riga per CVE)
    - JSON come oggetto {"<cpe>": [{"id":.., "cvss":.., "url":..}, ...], ...}
    - JSON come lista di record: [{"cpe":.., "cve_id":.., "cvss":.., "url":..}, ...]

    Ritorna dict {cpe: [ {id, cvss, url}, ... ]}. Righe/record senza cpe o
    senza id CVE vengono scartati silenziosamente."""
    text = content_bytes.decode("utf-8-sig", errors="replace")
    name = (filename or "").lower()
    stripped = text.lstrip()
    looks_like_json = stripped[:1] in "{["

    if name.endswith(".json") or (not name.endswith(".csv") and looks_like_json):
        data = json.loads(text)
        result = {}
        if isinstance(data, dict):
            for cpe, items in data.items():
                cpe = (cpe or "").strip()
                if not cpe:
                    continue
                normalized = [_normalize_cve_record(it) for it in items]
                result[cpe] = [c for c in normalized if c["id"]]
        elif isinstance(data, list):
            for row in data:
                cpe = (row.get("cpe") or "").strip()
                if not cpe:
                    continue
                normalized = _normalize_cve_record(row)
                if normalized["id"]:
                    result.setdefault(cpe, []).append(normalized)
        return result

    result = {}
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        cpe = (row.get("cpe") or "").strip()
        if not cpe:
            continue
        normalized = _normalize_cve_record(row)
        if normalized["id"]:
            result.setdefault(cpe, []).append(normalized)
    return result
