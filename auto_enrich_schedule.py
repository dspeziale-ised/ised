"""Configurazione e stato dell'arricchimento automatico degli host senza
sistema operativo rilevato (vedi auto_enrich.py), letta/scritta da un file
JSON in instance/ — stesso schema di monitor_schedule.py/report_schedule.py.
Attivo di default: l'obiettivo è che i nuovi host scoperti da una scansione
"leggera" (es. solo -sn) vengano arricchiti da soli, senza un intervento
manuale per ognuno.
"""

import json_settings

CONFIG_FILE = "auto_enrich_schedule.json"

DEFAULT_CONFIG = {
    "enabled": True,
    "continuous": False,
    "interval_minutes": 15,
    "timing": "3",
    "max_parallelism": 4,
    "last_run_at": None,
    "last_run_summary": None,
}


def load():
    return json_settings.load(CONFIG_FILE, DEFAULT_CONFIG)


def save(config):
    return json_settings.save(CONFIG_FILE, DEFAULT_CONFIG, config)


def is_due(config, now):
    """True se un nuovo ciclo può partire. In modalità 'continuous' ignora
    interval_minutes: appena il ciclo precedente si libera (lock rilasciato
    in app.py._run_auto_enrich_cycle_now), il prossimo può partire subito,
    invece di aspettare una pausa fissa tra un ciclo completo e il
    successivo — utile per svuotare rapidamente un grosso arretrato di host
    senza OS, o per accorgersi prima di host nuovi scoperti nel frattempo."""
    if not config.get("enabled"):
        return False
    if config.get("continuous"):
        return True
    last_run_at = config.get("last_run_at")
    if not last_run_at:
        return True
    from datetime import datetime
    try:
        last = datetime.fromisoformat(last_run_at)
    except ValueError:
        return True
    interval_minutes = config.get("interval_minutes") or 15
    elapsed_minutes = (now - last).total_seconds() / 60
    return elapsed_minutes >= interval_minutes


def mark_run(now, summary=None):
    config = load()
    config["last_run_at"] = now.isoformat(timespec="seconds")
    config["last_run_summary"] = summary
    return save(config)
