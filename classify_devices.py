#!/usr/bin/env python3
"""Classifica il tipo di dispositivo degli host nel DB usando un LLM, con
fallback automatico tra provider (Groq -> Gemini -> Ollama di default).

Per limitare l'uso delle API key, gli host vengono raggruppati per
fingerprint identico (stesso OS rilevato + stessa combinazione di porte/
servizi aperti): l'arricchimento (banner HTTP/SMB/TCP) e la chiamata LLM
avvengono una sola volta per gruppo, non per singolo host, e il risultato
viene applicato a tutti gli host del gruppo. Più gruppi vengono inoltre
raggruppati in una singola richiesta (batch) per ridurre il numero di
chiamate HTTP.

Se il provider attivo esaurisce la quota (giornaliera o di frequenza) o va
in errore, si passa automaticamente al provider successivo nella catena per
lo stesso batch, senza fermare l'intero run. Se un batch supera i limiti di
token del provider, viene diviso automaticamente in due e ritentato.

Per default classifica SOLO gli host nuovi/non ancora classificati
(ai_device_type IS NULL) — utile per rilanciarlo dopo ogni aggiornamento
della scansione senza sprecare chiamate su chi è già stato classificato.
Per riclassificare anche quelli già fatti, passa esplicitamente --force
(o gli alias --all / --reclassify-all).

Uso:
    python classify_devices.py                      # solo host nuovi/non ancora classificati
    python classify_devices.py --force               # riclassifica ANCHE quelli già fatti
    python classify_devices.py --limit-groups 5       # solo i primi N gruppi (test)
    python classify_devices.py --providers groq,ollama
"""

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import gemini_client
import groq_client
import ollama_client
import scanner_db
from enrich import enrich_host
from job_lock import JobLock
from llm_common import LLMDailyLimitError, LLMError, LLMRateLimitError, LLMTooLargeError

# Su console Windows lo stdout di default non è UTF-8: testo generato dai
# provider AI (es. caratteri unicode particolari) può altrimenti far
# crashare i print con UnicodeEncodeError a metà run.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).parent
DB_PATH = scanner_db.resolve_db_target(BASE / "instance" / "inventory.db")
LOCK_FILE = BASE / "classify.lock"
GROUPS_PER_REQUEST = 6
SLEEP_BETWEEN_REQUESTS = 3.0
MAX_RATE_LIMIT_RETRIES = 5
MAX_STRING_LEN = 350

ALL_PROVIDERS = {
    "groq": groq_client,
    "gemini": gemini_client,
    "ollama": ollama_client,
}

# Ollama (nemotron-3-super:cloud) per primo, poi gli altri come fallback.
DEFAULT_PROVIDER_ORDER = ["ollama", "groq", "gemini"]


def build_provider_chain(names=None):
    names = names or DEFAULT_PROVIDER_ORDER
    chain = []
    for name in names:
        module = ALL_PROVIDERS.get(name)
        if module is None:
            print(f"  [!] Provider '{name}' sconosciuto, ignorato.")
            continue
        if not module.is_configured():
            print(f"  [!] Provider '{name}' non configurato (manca API key), ignorato.")
            continue
        chain.append((name, module))
    if not chain:
        raise SystemExit("Nessun provider LLM configurato/disponibile. Configura almeno una API key.")
    return chain


def build_signature(host, services):
    """Chiave di raggruppamento: host con stesso OS + stesse porte/servizi
    aperti sono trattati come lo stesso identico dispositivo."""
    ports_sig = sorted(
        (s["port"], s["protocol"], s["service_name"] or "", s["product"] or "")
        for s in services if s["state"] == "open"
    )
    payload = {
        "os_name": host["os_name"],
        "os_family": host["os_family"],
        "os_gen": host["os_gen"],
        "mac_vendor": host["mac_vendor"],
        "ports": ports_sig,
    }
    raw = json.dumps(payload, sort_keys=True)
    signature = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return signature, payload


def build_groups(conn, force=False):
    where = "" if force else "WHERE ai_device_type IS NULL"
    hosts = conn.execute(f"SELECT * FROM hosts {where}").fetchall()

    groups = {}
    for h in hosts:
        services = conn.execute(
            "SELECT * FROM services WHERE host_id = ?", (h["id"],)
        ).fetchall()
        signature, payload = build_signature(h, services)
        conn.execute(
            "UPDATE hosts SET fingerprint_signature = ? WHERE id = ?", (signature, h["id"])
        )
        group = groups.setdefault(signature, {
            "payload": payload, "host_ids": [], "representative_ip": None, "services": None,
        })
        group["host_ids"].append(h["id"])
        if group["representative_ip"] is None:
            group["representative_ip"] = h["ip"]
            group["services"] = [dict(s) for s in services]
    conn.commit()
    return hosts, groups


def _truncate(value):
    if isinstance(value, str) and len(value) > MAX_STRING_LEN:
        return value[:MAX_STRING_LEN] + "…"
    return value


def trim_evidence(evidence):
    """Limita la lunghezza di banner/output SMB per non gonfiare il prompt."""
    trimmed = {}
    for key, val in evidence.items():
        if isinstance(val, dict):
            trimmed[key] = {k: _truncate(v) for k, v in val.items()}
        else:
            trimmed[key] = _truncate(val)
    return trimmed


def build_payload(signature, group):
    evidence = enrich_host(group["representative_ip"], group["services"])
    services = [
        {
            "port": s["port"], "protocol": s["protocol"],
            "service_name": s["service_name"], "product": s["product"],
            "version": _truncate(s["version"]), "extrainfo": _truncate(s["extrainfo"]),
        }
        for s in group["services"]
    ]
    return {
        "signature_id": signature,
        "os": group["payload"],
        "services": services,
        "evidence": trim_evidence(evidence),
    }


def apply_results(conn, batch, results, provider_name):
    applied = 0
    for signature, group, _payload in batch:
        result = results.get(signature)
        if not result:
            print(f"  [!] Nessun risultato per il gruppo {signature}")
            continue

        device_type_raw = (result.get("device_type") or "").strip().lower() or None
        ai_device_type = device_type_raw
        vendor = result.get("vendor") or None
        roles = [r.strip().lower() for r in (result.get("roles") or []) if r and r.strip()]

        for host_id in group["host_ids"]:
            # Non toccare device_type/device_vendor se l'utente li ha impostati
            # manualmente dal dettaglio host (device_type_manual = 1).
            conn.execute(
                """UPDATE hosts SET ai_device_type = ?, ai_confidence = ?,
                       ai_reasoning = ?, ai_classified_at = ?, ai_provider = ?,
                       device_type = CASE WHEN device_type_manual = 1 THEN device_type
                                           ELSE COALESCE(?, device_type) END,
                       device_vendor = CASE WHEN device_type_manual = 1 THEN device_vendor
                                             ELSE COALESCE(?, device_vendor) END
                   WHERE id = ?""",
                (
                    ai_device_type,
                    result.get("confidence"),
                    result.get("reasoning"),
                    datetime.now().isoformat(timespec="seconds"),
                    provider_name,
                    device_type_raw,
                    vendor,
                    host_id,
                ),
            )
            scanner_db.set_host_roles(conn, host_id, roles, source="ai")
        applied += 1
        roles_txt = f" [{', '.join(roles)}]" if roles else ""
        print(
            f"  {signature}: {device_type_raw or '?'}{roles_txt} "
            f"({result.get('confidence', '?')}%) -> {len(group['host_ids'])} host"
        )
    conn.commit()
    return applied


def process_batch(conn, batch, providers, provider_idx=0, retries=0):
    """Classifica un batch [(signature, group, payload), ...] con il provider
    providers[provider_idx]. Se troppo grande lo divide in due (stesso
    provider), se rate-limited attende e ritenta, se la quota è esaurita o
    va in errore passa al provider successivo nella catena.

    Ritorna l'indice del provider che ha avuto successo (o l'ultimo provato),
    così il chiamante può ripartire da lì per il batch successivo invece di
    ri-sondare da capo un provider già noto come esaurito."""
    if not batch:
        return provider_idx
    if provider_idx >= len(providers):
        print("  [!] Tutti i provider disponibili hanno fallito per questo batch, salto.")
        return provider_idx

    name, module = providers[provider_idx]
    payloads = [p for _, _, p in batch]

    try:
        results = module.classify_signature_groups(payloads)
    except LLMTooLargeError:
        if len(batch) == 1:
            print(f"  [!] Gruppo {batch[0][0]} troppo grande anche da solo per {name}, "
                  f"provo il prossimo provider...")
            return process_batch(conn, batch, providers, provider_idx + 1)
        mid = len(batch) // 2
        print(f"  Batch troppo grande per {name} ({len(batch)} gruppi): lo divido in due...")
        idx1 = process_batch(conn, batch[:mid], providers, provider_idx)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        idx2 = process_batch(conn, batch[mid:], providers, provider_idx)
        return max(idx1, idx2)
    except LLMDailyLimitError as e:
        print(f"  [!] {name}: quota esaurita ({e}); passo al provider successivo...")
        return process_batch(conn, batch, providers, provider_idx + 1)
    except LLMRateLimitError as e:
        if retries >= MAX_RATE_LIMIT_RETRIES:
            print(f"  [!] {name}: rate limit persistente dopo {retries} tentativi, "
                  f"passo al provider successivo...")
            return process_batch(conn, batch, providers, provider_idx + 1)
        wait = e.retry_after or 15
        print(f"  {name}: rate limit, attendo {wait:.0f}s e ritento (tentativo {retries + 1})...")
        time.sleep(wait)
        return process_batch(conn, batch, providers, provider_idx, retries=retries + 1)
    except LLMError as e:
        print(f"  [!] {name}: errore ({e}), passo al provider successivo...")
        return process_batch(conn, batch, providers, provider_idx + 1)

    print(f"  (classificato da: {name})")
    apply_results(conn, batch, results, name)
    return provider_idx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force", "--all", "--reclassify-all", dest="force", action="store_true",
        help="Riclassifica ANCHE gli host già classificati (default: solo quelli nuovi)",
    )
    parser.add_argument("--limit-groups", type=int, help="Limita il numero di gruppi (per test)")
    parser.add_argument("--groups-per-request", type=int, default=GROUPS_PER_REQUEST)
    parser.add_argument(
        "--providers", default=",".join(DEFAULT_PROVIDER_ORDER),
        help="Ordine dei provider da provare, separati da virgola (default: %(default)s)",
    )
    args = parser.parse_args()

    providers = build_provider_chain(args.providers.split(","))
    print("Catena provider: " + " -> ".join(name for name, _ in providers))

    with JobLock(LOCK_FILE):
        conn = scanner_db.connect(str(DB_PATH))
        scanner_db.ensure_ai_columns(conn)

        total_hosts = conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
        already_classified = conn.execute(
            "SELECT COUNT(*) c FROM hosts WHERE ai_device_type IS NOT NULL"
        ).fetchone()["c"]

        if args.force:
            print(f"--force attivo: riclassifico TUTTI gli host ({total_hosts} totali, "
                  f"di cui {already_classified} già classificati in precedenza).")
        else:
            print(f"Modalità solo-nuovi (default): {already_classified}/{total_hosts} host "
                  f"già classificati vengono saltati. Usa --force per riclassificarli tutti.")

        hosts, groups = build_groups(conn, force=args.force)
        print(f"Host da classificare in questo run: {len(hosts)} -> {len(groups)} gruppi con fingerprint unico")

        if not hosts:
            print("Niente da fare: nessun host nuovo da classificare.")
            conn.close()
            return

        items = list(groups.items())
        if args.limit_groups:
            items = items[: args.limit_groups]

        start_provider_idx = 0
        for i in range(0, len(items), args.groups_per_request):
            chunk = items[i : i + args.groups_per_request]
            print(f"Arricchimento evidenze per {len(chunk)} gruppi ({i + 1}-{i + len(chunk)} di {len(items)})...")
            batch = [(signature, group, build_payload(signature, group)) for signature, group in chunk]

            print(f"Classificazione: gruppi {i + 1}-{i + len(chunk)} di {len(items)}...")
            result_idx = process_batch(conn, batch, providers, provider_idx=start_provider_idx)
            # Se il batch ha fallito su TUTTI i provider, result_idx è fuori
            # range: si riparte dal primo provider per il prossimo batch,
            # invece di restare bloccati per il resto del run (bug corretto:
            # prima un fallimento totale disabilitava ogni tentativo futuro).
            start_provider_idx = result_idx if result_idx < len(providers) else 0

            if i + args.groups_per_request < len(items):
                time.sleep(SLEEP_BETWEEN_REQUESTS)

        conn.close()
        print("Classificazione completata.")


if __name__ == "__main__":
    main()
