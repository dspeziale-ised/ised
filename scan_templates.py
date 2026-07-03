"""Template di scansione nmap personalizzata (Inventario -> Scansione nmap):
lo stato COMPLETO di ogni singolo controllo del form (ogni checkbox/select/
campo, non solo il comando nmap risultante) salvato con un nome, per
ripristinare esattamente la stessa configurazione senza doverla ricostruire
opzione per opzione ogni volta.

Persistiti in instance/nmap_scan_templates.json (json_settings.py, stesso
pattern/posto delle altre configurazioni) come dict {nome: {target, args,
fields, saved_at}} — un dict e non una lista, cosi salvare con un nome già
esistente sovrascrive il template senza doverlo cercare/rimuovere prima.
`fields` è un dict opaco {id_controllo: valore} costruito e consumato lato
client (vedi templates/custom_scan.html): il backend non ne interpreta il
contenuto, si limita a persisterlo così com'è. `target`/`args` restano
salvati separatamente solo come riepilogo leggibile (mostrati nella lista
template), il ripristino effettivo del form usa `fields`.
"""

from datetime import datetime, timezone

import json_settings

CONFIG_FILE = "nmap_scan_templates.json"
_DEFAULT_CONFIG = {"templates": {}}


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def list_templates():
    """Ritorna i template ordinati per nome: [{name, target, args, fields, saved_at}, ...]."""
    data = json_settings.load(CONFIG_FILE, _DEFAULT_CONFIG)
    templates = data.get("templates") or {}
    return [
        {
            "name": name,
            "target": payload.get("target", ""),
            "args": payload.get("args", ""),
            "fields": payload.get("fields") or {},
            "saved_at": payload.get("saved_at"),
        }
        for name, payload in sorted(templates.items())
    ]


def save_template(name, target, args, fields):
    name = (name or "").strip()
    if not name:
        raise ValueError("Il nome del template non può essere vuoto.")
    data = json_settings.load(CONFIG_FILE, _DEFAULT_CONFIG)
    templates = dict(data.get("templates") or {})
    templates[name] = {
        "target": (target or "").strip(),
        "args": args or "",
        "fields": fields or {},
        "saved_at": _now_iso(),
    }
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
