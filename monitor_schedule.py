"""Configurazione e stato del monitoraggio periodico di raggiungibilità
host (host_monitor.py), letta/scritta da un file JSON in instance/ (stesso
posto del DB, già escluso da git). Attivo di default: il monitoraggio è la
funzionalità principale della sezione Monitoraggio, deve partire da solo.
"""

import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "instance" / "monitor_schedule.json"

DEFAULT_CONFIG = {
    "enabled": True,
    "interval_minutes": 5,
    "batch_size": 60,
    "heartbeat_minutes": 60,
    "last_run_at": None,
    "last_run_summary": None,
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
    if not config.get("enabled"):
        return False
    last_run_at = config.get("last_run_at")
    if not last_run_at:
        return True
    try:
        from datetime import datetime
        last = datetime.fromisoformat(last_run_at)
    except ValueError:
        return True
    interval_minutes = config.get("interval_minutes") or 5
    elapsed_minutes = (now - last).total_seconds() / 60
    return elapsed_minutes >= interval_minutes


def mark_run(now, summary=None):
    config = load()
    config["last_run_at"] = now.isoformat(timespec="seconds")
    config["last_run_summary"] = summary
    return save(config)
