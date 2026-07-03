"""Invio di documenti/messaggi a un bot Telegram (Bot API ufficiale), usato
per notificare il report PDF dell'inventario di rete.

Configurazione (stesso pattern delle altre chiavi API del progetto): file
dedicati nella cartella keys/ (mai committare, già in .gitignore) oppure
variabili d'ambiente equivalenti.
"""

import os
from pathlib import Path

import requests

API_BASE = "https://api.telegram.org/bot"
_KEYS_DIR = Path(__file__).parent / "keys"
_TOKEN_FILE = _KEYS_DIR / "telegram_bot_token"
_CHAT_ID_FILE = _KEYS_DIR / "telegram_chat_id"


class TelegramError(Exception):
    pass


def _load_token():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if token:
        return token.strip()
    if _TOKEN_FILE.exists():
        return _TOKEN_FILE.read_text(encoding="utf-8").strip()
    return None


def _load_chat_id():
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if chat_id:
        return chat_id.strip()
    if _CHAT_ID_FILE.exists():
        return _CHAT_ID_FILE.read_text(encoding="utf-8").strip()
    return None


def is_configured():
    return bool(_load_token() and _load_chat_id())


def has_token():
    return bool(_load_token())


def token_from_env():
    """True se il token viene da una variabile d'ambiente (non dal file
    scrivibile da UI) — in quel caso l'env var ha sempre la priorità e un
    salvataggio da form non avrebbe effetto visibile."""
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN"))


def chat_id_from_env():
    return bool(os.environ.get("TELEGRAM_CHAT_ID"))


def get_chat_id_display():
    """Chat ID da mostrare in un form (non è un segreto quanto il token)."""
    return _load_chat_id() or ""


def save_credentials(token=None, chat_id=None):
    """Salva token/chat_id nei file dedicati. Un campo vuoto/assente lascia
    invariato il valore già salvato (così il form può essere sottomesso
    senza dover re-inserire un token già configurato)."""
    _KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if token:
        _TOKEN_FILE.write_text(token.strip(), encoding="utf-8")
    if chat_id:
        _CHAT_ID_FILE.write_text(chat_id.strip(), encoding="utf-8")


def send_document(file_bytes, filename, caption=None, chat_id=None, timeout=60):
    """Invia un file (es. PDF) al bot Telegram. Ritorna la risposta JSON
    dell'API in caso di successo, solleva TelegramError altrimenti."""
    token = _load_token()
    configured_chat_id = chat_id or _load_chat_id()
    if not token or not configured_chat_id:
        raise TelegramError(
            "Bot Telegram non configurato (variabili d'ambiente TELEGRAM_BOT_TOKEN/"
            "TELEGRAM_CHAT_ID o file keys/telegram_bot_token e keys/telegram_chat_id)."
        )

    url = f"{API_BASE}{token}/sendDocument"
    data = {"chat_id": configured_chat_id}
    if caption:
        data["caption"] = caption[:1024]  # limite Telegram per le caption
    files = {"document": (filename, file_bytes, "application/pdf")}

    try:
        resp = requests.post(url, data=data, files=files, timeout=timeout)
    except requests.RequestException as e:
        raise TelegramError(f"Errore di rete verso Telegram: {e}") from e

    try:
        payload = resp.json()
    except ValueError:
        raise TelegramError(f"Risposta non valida da Telegram (HTTP {resp.status_code}).")

    if not resp.ok or not payload.get("ok"):
        raise TelegramError(payload.get("description") or f"Errore Telegram (HTTP {resp.status_code}).")

    return payload


def send_message(text, chat_id=None, timeout=20):
    """Invia un messaggio di testo semplice (es. notifica senza allegato)."""
    token = _load_token()
    configured_chat_id = chat_id or _load_chat_id()
    if not token or not configured_chat_id:
        raise TelegramError("Bot Telegram non configurato.")

    url = f"{API_BASE}{token}/sendMessage"
    try:
        resp = requests.post(
            url, data={"chat_id": configured_chat_id, "text": text[:4096]}, timeout=timeout
        )
    except requests.RequestException as e:
        raise TelegramError(f"Errore di rete verso Telegram: {e}") from e

    try:
        payload = resp.json()
    except ValueError:
        raise TelegramError(f"Risposta non valida da Telegram (HTTP {resp.status_code}).")

    if not resp.ok or not payload.get("ok"):
        raise TelegramError(payload.get("description") or f"Errore Telegram (HTTP {resp.status_code}).")

    return payload
