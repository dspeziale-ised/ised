"""Client minimale per l'API Gemini (Google Generative Language), usato come
provider di fallback quando Groq non è disponibile (rate limit, quota
esaurita, errore) per classificare il tipo di dispositivo.
"""

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from llm_common import (
    BROWSER_LIKE_USER_AGENT,
    SYSTEM_PROMPT,
    LLMDailyLimitError,
    LLMError,
    LLMRateLimitError,
    LLMTooLargeError,
    extract_json,
    results_by_signature,
)

PROVIDER_NAME = "gemini"
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_API_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/{{model}}:generateContent"
)
_KEY_FILE = Path(__file__).parent / "keys" / "gemini_api_key"


def is_configured():
    return bool(_load_api_key())


def _load_api_key():
    key = os.environ.get("GEMINI_API_KEY")
    if key:
        return key.strip()
    if _KEY_FILE.exists():
        return _KEY_FILE.read_text(encoding="utf-8").strip()
    return None


def _parse_retry_delay(detail):
    match = re.search(r'"retryDelay"\s*:\s*"(\d+(?:\.\d+)?)s"', detail)
    return float(match.group(1)) if match else None


def classify_signature_groups(groups, timeout=90, model=None):
    """groups: lista di dict {signature_id, os, services, evidence}.
    Ritorna dict {signature_id: {device_type, vendor, confidence, reasoning}}."""
    if not groups:
        return {}

    api_key = _load_api_key()
    if not api_key:
        raise LLMError(
            "Nessuna API key Gemini trovata (variabile d'ambiente GEMINI_API_KEY "
            "o file keys/gemini_api_key)."
        )

    url = GEMINI_API_URL.format(model=model or GEMINI_MODEL)
    payload = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [
            {"role": "user", "parts": [{"text": json.dumps({"groups": groups}, ensure_ascii=False)}]}
        ],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": BROWSER_LIKE_USER_AGENT,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        message = f"Gemini HTTP {e.code}: {detail}"
        if e.code == 429 or "RESOURCE_EXHAUSTED" in detail:
            retry_after = _parse_retry_delay(detail)
            if re.search(r"per.?day|daily|PerDay", detail, re.I):
                raise LLMDailyLimitError(message, retry_after=retry_after) from e
            raise LLMRateLimitError(message, retry_after=retry_after) from e
        if e.code == 400 and re.search(r"token|too long|exceed", detail, re.I):
            raise LLMTooLargeError(message) from e
        raise LLMError(message) from e
    except urllib.error.URLError as e:
        raise LLMError(f"Errore di rete verso Gemini: {e}") from e
    except (TimeoutError, ConnectionError, OSError) as e:
        raise LLMError(f"Timeout/errore di connessione verso Gemini: {e}") from e

    try:
        content = body["candidates"][0]["content"]["parts"][0]["text"]
        parsed = extract_json(content)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        raise LLMError(f"Risposta Gemini inattesa: {body}") from e

    return results_by_signature(parsed)
