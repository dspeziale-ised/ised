"""Template di scansione nmap personalizzata (Inventario -> Scansione nmap):
combinazioni salvate di target + argomenti nmap, per ripetere una scansione
tipica senza ricompilare il form da zero ogni volta.

Persistiti in instance/nmap_scan_templates.json (json_settings.py, stesso
pattern/posto delle altre configurazioni) come dict {nome: {target, args,
saved_at}} — un dict e non una lista, cosi salvare con un nome già
esistente sovrascrive il template senza doverlo cercare/rimuovere prima.
"""

from datetime import datetime, timezone

import json_settings

CONFIG_FILE = "nmap_scan_templates.json"
_DEFAULT_CONFIG = {"templates": {}}


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def list_templates():
    """Ritorna i template ordinati per nome: [{name, target, args, saved_at}, ...]."""
    data = json_settings.load(CONFIG_FILE, _DEFAULT_CONFIG)
    templates = data.get("templates") or {}
    return [
        {"name": name, "target": payload.get("target", ""), "args": payload.get("args", ""),
         "saved_at": payload.get("saved_at")}
        for name, payload in sorted(templates.items())
    ]


def save_template(name, target, args):
    name = (name or "").strip()
    if not name:
        raise ValueError("Il nome del template non può essere vuoto.")
    data = json_settings.load(CONFIG_FILE, _DEFAULT_CONFIG)
    templates = dict(data.get("templates") or {})
    templates[name] = {"target": (target or "").strip(), "args": args or "", "saved_at": _now_iso()}
    json_settings.save(CONFIG_FILE, _DEFAULT_CONFIG, {"templates": templates})


def delete_template(name):
    """Ritorna True se un template con quel nome esisteva ed è stato rimosso."""
    data = json_settings.load(CONFIG_FILE, _DEFAULT_CONFIG)
    templates = dict(data.get("templates") or {})
    if name not in templates:
        return False
    del templates[name]
    json_settings.save(CONFIG_FILE, _DEFAULT_CONFIG, {"templates": templates})
    return True
