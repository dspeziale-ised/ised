"""Invio di documenti/messaggi a un bot Telegram (Bot API ufficiale), usato
per notificare il report PDF dell'inventario di rete.

Configurazione (stesso pattern delle altre chiavi API del progetto): file
dedicati nella root del progetto (mai committare, già in .gitignore) oppure
variabili d'ambiente equivalenti.
"""

import os
from pathlib import Path

import requests

API_BASE = "https://api.telegram.org/bot"
_TOKEN_FILE = Path(__file__).parent / ".telegram_bot_token"
_CHAT_ID_FILE = Path(__file__).parent / ".telegram_chat_id"


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


def send_document(file_bytes, filename, caption=None, chat_id=None, timeout=60):
    """Invia un file (es. PDF) al bot Telegram. Ritorna la risposta JSON
    dell'API in caso di successo, solleva TelegramError altrimenti."""
    token = _load_token()
    configured_chat_id = chat_id or _load_chat_id()
    if not token or not configured_chat_id:
        raise TelegramError(
            "Bot Telegram non configurato (variabili d'ambiente TELEGRAM_BOT_TOKEN/"
            "TELEGRAM_CHAT_ID o file .telegram_bot_token/.telegram_chat_id)."
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
