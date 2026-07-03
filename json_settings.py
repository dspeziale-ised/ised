"""Configurazione persistita come file JSON in instance/ (stesso schema in
tutto il progetto: dict di default, merge superficiale delle sole chiavi
note, tollerante a file assente/corrotto — non richiede una migrazione o un
formato di versione). Usato per le impostazioni configurabili dalla UI che
devono sopravvivere ai riavvii dell'app (schedulazioni, effort di rete), a
differenza delle credenziali (vedi secrets_store.py) o dei dati veri e
propri (nel database).

Era prima duplicato identico in monitor_schedule.py/report_schedule.py:
centralizzato qui.
"""

import json
from pathlib import Path

INSTANCE_DIR = Path(__file__).parent / "instance"


def load(filename, defaults):
    """Ritorna il config da instance/<filename>, con le sole chiavi
    presenti in `defaults` (merge superficiale sopra una copia di
    `defaults`). File assente/corrotto -> una copia di `defaults`."""
    path = INSTANCE_DIR / filename
    if not path.exists():
        return dict(defaults)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return dict(defaults)
    config = dict(defaults)
    config.update({k: v for k, v in data.items() if k in defaults})
    return config


def save(filename, defaults, config):
    """Scrive in instance/<filename> `config` mergiato sopra `defaults`
    (solo le chiavi note in `defaults`, per non scrivere campi arbitrari).
    Ritorna il dict effettivamente scritto."""
    path = INSTANCE_DIR / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    merged = dict(defaults)
    merged.update({k: v for k, v in config.items() if k in defaults})
    path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged
