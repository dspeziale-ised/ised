"""Lettura/scrittura di credenziali/token/chiavi API, con lo stesso
meccanismo in tutto il progetto: variabile d'ambiente PRIMA (permette a
Docker/.env di configurarle senza toccare file), file dedicato in keys/
SECONDA (uso nativo, scrivibile anche dalla UI di Amministrazione) — mai
committato, l'intera cartella keys/ è in .gitignore.

Questo doppio meccanismo era prima duplicato identico in ogni modulo che
legge una credenziale (groq_client.py, gemini_client.py, ollama_client.py,
nvd_client.py, notify_telegram.py, notify_gmail.py, nmap_proxy_client.py,
nmap_proxy_server.py): centralizzato qui.
"""

import os
from pathlib import Path

KEYS_DIR = Path(__file__).parent / "keys"


def load_secret(env_var, filename):
    """Valore da variabile d'ambiente `env_var` se impostata, altrimenti da
    `keys/<filename>` se esiste, altrimenti None."""
    value = os.environ.get(env_var)
    if value:
        return value.strip()
    path = KEYS_DIR / filename
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return None


def is_from_env(env_var):
    """True se il valore viene da una variabile d'ambiente (non dal file
    scrivibile da UI) — in quel caso l'env var ha sempre la priorità e un
    salvataggio da form non avrebbe effetto visibile."""
    return bool(os.environ.get(env_var))


def save_secret(filename, value):
    """Salva `value` in `keys/<filename>` se non vuoto/None: un valore
    vuoto lascia invariato quanto già salvato, così un form può essere
    sottomesso senza dover re-inserire un segreto già configurato."""
    if not value:
        return
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    (KEYS_DIR / filename).write_text(value.strip(), encoding="utf-8")
