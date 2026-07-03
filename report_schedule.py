"""Configurazione e stato della schedulazione periodica del report PDF
(generazione + invio automatico via Telegram/Gmail), letta/scritta da un
file JSON in instance/ (stesso posto del DB, già escluso da git).

Non usa un vero scheduler esterno (cron/Task Scheduler): un thread interno
in app.py controlla periodicamente is_due() e, se vero, genera/invia il
report e chiama mark_sent().
"""

import json_settings

CONFIG_FILE = "report_schedule.json"

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
    return json_settings.load(CONFIG_FILE, DEFAULT_CONFIG)


def save(config):
    return json_settings.save(CONFIG_FILE, DEFAULT_CONFIG, config)


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
