"""Client minimale per Ollama (locale o Ollama Cloud), usato come ulteriore
provider di fallback per la classificazione del tipo di dispositivo.

Usa l'endpoint compatibile OpenAI:
- se è configurata una API key (OLLAMA_API_KEY o file .ollama_api_key),
  punta a Ollama Cloud (https://ollama.com);
- altrimenti punta a un'istanza locale (http://localhost:11434), senza
  autenticazione.
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
    parse_wait_seconds,
    results_by_signature,
)

PROVIDER_NAME = "ollama"
_KEY_FILE = Path(__file__).parent / ".ollama_api_key"

OLLAMA_CLOUD_URL = "https://ollama.com/v1/chat/completions"
OLLAMA_LOCAL_URL = os.environ.get("OLLAMA_LOCAL_URL", "http://localhost:11434/v1/chat/completions")
# Modello richiesto esplicitamente dall'utente (disponibile via Ollama Cloud,
# anche da un'istanza locale se il modello ":cloud" è configurato/loggato lì).
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "nemotron-3-super:cloud")


def is_configured():
    # Configurato sia se c'è una API key cloud, sia semplicemente perché si
    # assume una istanza locale raggiungibile su OLLAMA_LOCAL_URL.
    return True


def _load_api_key():
    key = os.environ.get("OLLAMA_API_KEY")
    if key:
        return key.strip()
    if _KEY_FILE.exists():
        return _KEY_FILE.read_text(encoding="utf-8").strip()
    return None


def classify_signature_groups(groups, timeout=90, model=None):
    """groups: lista di dict {signature_id, os, services, evidence}.
    Ritorna dict {signature_id: {device_type, vendor, confidence, reasoning}}."""
    if not groups:
        return {}

    api_key = _load_api_key()
    url = OLLAMA_CLOUD_URL if api_key else OLLAMA_LOCAL_URL
    chosen_model = model or OLLAMA_MODEL

    payload = {
        "model": chosen_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps({"groups": groups}, ensure_ascii=False)},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    headers = {"Content-Type": "application/json", "User-Agent": BROWSER_LIKE_USER_AGENT}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        message = f"Ollama HTTP {e.code}: {detail}"
        if e.code == 429:
            retry_after = parse_wait_seconds(detail)
            if re.search(r"per.?day|daily", detail, re.I):
                raise LLMDailyLimitError(message, retry_after=retry_after) from e
            raise LLMRateLimitError(message, retry_after=retry_after) from e
        if e.code == 413 or re.search(r"context length|too long|token.*(limit|exceed)", detail, re.I):
            raise LLMTooLargeError(message) from e
        raise LLMError(message) from e
    except urllib.error.URLError as e:
        raise LLMError(
            f"Errore di rete verso Ollama ({url}): {e}. "
            "Se stai usando un'istanza locale, verifica che sia in esecuzione "
            "('ollama serve') e che il modello sia stato scaricato ('ollama pull <modello>')."
        ) from e

    try:
        content = body["choices"][0]["message"]["content"]
        parsed = extract_json(content)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        raise LLMError(f"Risposta Ollama inattesa: {body}") from e

    return results_by_signature(parsed)
