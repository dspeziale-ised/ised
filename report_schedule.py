"""Configurazione e stato della schedulazione periodica del report PDF
(generazione + invio automatico via Telegram/Gmail), letta/scritta da un
file JSON in instance/ (stesso posto del DB, già escluso da git).

Non usa un vero scheduler esterno (cron/Task Scheduler): un thread interno
in app.py controlla periodicamente is_due() e, se vero, genera/invia il
report e chiama mark_sent().
"""

import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "instance" / "report_schedule.json"

DEFAULT_CONFIG = {
    "enabled": False,
    "interval_hours": 24,
    "kinds": ["summary", "hosts"],
    "send_telegram": False,
    "send_gmail": False,
    "gmail_to": "",
    "last_sent_at": None,
}


def load():
    if not CONFIG_PATH.exists():
        return dict(DEFAULT_CONFIG)
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return dict(DEFAULT_CONFIG)
    config = dict(DEFAULT_CONFIG)
    config.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
    return config


def save(config):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    merged = dict(DEFAULT_CONFIG)
    merged.update({k: v for k, v in config.items() if k in DEFAULT_CONFIG})
    CONFIG_PATH.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged


def is_due(config, now):
    """True se la schedulazione è attiva e l'intervallo configurato è
    trascorso dall'ultimo invio (o non è mai stato inviato)."""
    if not config.get("enabled"):
        return False
    last_sent_at = config.get("last_sent_at")
    if not last_sent_at:
        return True
    try:
        from datetime import datetime
        last = datetime.fromisoformat(last_sent_at)
    except ValueError:
        return True
    interval_hours = config.get("interval_hours") or 24
    elapsed_hours = (now - last).total_seconds() / 3600
    return elapsed_hours >= interval_hours


def mark_sent(now):
    config = load()
    config["last_sent_at"] = now.isoformat(timespec="seconds")
    return save(config)
