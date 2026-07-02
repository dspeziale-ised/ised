"""Client per l'API pubblica NVD (National Vulnerability Database, NIST) —
recupera le CVE note per una CPE direttamente da internet, senza passare da
nmap/vulners e senza bisogno di scansionare dal vivo un host: basta la
stringa CPE già rilevata durante lo scan -sV (services.cpe).

Documentazione: https://nvd.nist.gov/developers/vulnerabilities
Senza API key il rate limit pubblico è di 5 richieste ogni 30s; con una
API key gratuita (richiedibile su https://nvd.nist.gov/developers/request-an-api-key)
sale a 50 ogni 30s.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_KEY_FILE = Path(__file__).parent / ".nvd_api_key"
BROWSER_LIKE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) net-inventory-vulnscan/1.0"
)


class NvdError(RuntimeError):
    """Errore generico nella chiamata a NVD."""


class NvdRateLimitError(NvdError):
    """Rate limit NVD superato (HTTP 403/429): attendere e ritentare."""


def is_configured():
    # L'API NVD è pubblica: funziona anche senza key (con rate limit più basso).
    return True


def has_api_key():
    return bool(_load_api_key())


def _load_api_key():
    key = os.environ.get("NVD_API_KEY")
    if key:
        return key.strip()
    if _KEY_FILE.exists():
        return _KEY_FILE.read_text(encoding="utf-8").strip()
    return None


def cpe22_to_23(cpe22):
    """Converte una CPE 2.2 (es. 'cpe:/a:openbsd:openssh:8.2', il formato
    prodotto da nmap) nell'URI 2.3 richiesto dall'API NVD
    ('cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*'). Ritorna None se il
    formato non è riconosciuto."""
    if cpe22.startswith("cpe:2.3:"):
        return cpe22
    if not cpe22.startswith("cpe:/"):
        return None

    body = cpe22[len("cpe:/"):]
    parts = body.split(":")
    parts = (parts + [""] * 5)[:5]
    parts = [p if p else "*" for p in parts]
    tail = ["*"] * (11 - len(parts))
    return "cpe:2.3:" + ":".join(parts + tail)


def _extract_cvss(metrics):
    """Preferisce CVSS v3.1, poi v3.0, poi v2 (in quest'ordine di priorità)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def fetch_cves_for_cpe(cpe, timeout=30, results_per_page=200):
    """Interroga l'API NVD per una CPE (formato 2.2 o 2.3 di nmap). Ritorna
    una lista di dict {id, cvss, url}, ordinata per CVSS decrescente."""
    cpe23 = cpe if cpe.startswith("cpe:2.3:") else cpe22_to_23(cpe)
    if not cpe23:
        return []

    params = {"cpeName": cpe23, "resultsPerPage": str(results_per_page)}
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"

    headers = {"User-Agent": BROWSER_LIKE_USER_AGENT}
    api_key = _load_api_key()
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        if e.code in (403, 429):
            raise NvdRateLimitError(f"NVD rate limit/accesso negato (HTTP {e.code}): {detail}") from e
        raise NvdError(f"NVD HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        raise NvdError(f"Errore di rete verso NVD: {e}") from e

    results = []
    for vuln in body.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        results.append({
            "id": cve_id,
            "cvss": _extract_cvss(cve.get("metrics", {})),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return sorted(results, key=lambda c: c["cvss"] or 0, reverse=True)
