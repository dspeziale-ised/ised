"""Client minimale per l'API Groq (compatibile OpenAI), usato per classificare
il tipo di dispositivo di gruppi di host con fingerprint identico.

Una sola richiesta HTTP classifica più gruppi insieme (batch), per limitare
il numero di chiamate a carico della API key.
"""

import json
import os
import urllib.error
import urllib.request

import secrets_store
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

PROVIDER_NAME = "groq"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

# Alias per compatibilità con codice/test esistenti che importano da qui.
GroqError = LLMError
GroqTooLargeError = LLMTooLargeError
GroqRateLimitError = LLMRateLimitError
GroqDailyLimitError = LLMDailyLimitError


def is_configured():
    return bool(_load_api_key())


def _load_api_key():
    return secrets_store.load_secret("GROQ_API_KEY", "groq_api_key")


def classify_signature_groups(groups, timeout=90, model=None):
    """groups: lista di dict {signature_id, os, services, evidence}.
    Ritorna dict {signature_id: {device_type, vendor, confidence, reasoning}}."""
    if not groups:
        return {}

    api_key = _load_api_key()
    if not api_key:
        raise LLMError(
            "Nessuna API key Groq trovata (variabile d'ambiente GROQ_API_KEY "
            "o file keys/groq_api_key)."
        )

    payload = {
        "model": model or GROQ_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps({"groups": groups}, ensure_ascii=False)},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    req = urllib.request.Request(
        GROQ_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            # Il User-Agent di default di urllib viene bloccato dal WAF/Cloudflare di Groq (403).
            "User-Agent": BROWSER_LIKE_USER_AGENT,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        message = f"Groq HTTP {e.code}: {detail}"
        if "rate_limit_exceeded" in detail or e.code == 429:
            retry_after = parse_wait_seconds(detail)
            if e.code == 413 or "reduce your message size" in detail:
                raise LLMTooLargeError(message) from e
            if "(TPD)" in detail or "tokens per day" in detail:
                raise LLMDailyLimitError(message, retry_after=retry_after) from e
            raise LLMRateLimitError(message, retry_after=retry_after) from e
        raise LLMError(message) from e
    except urllib.error.URLError as e:
        raise LLMError(f"Errore di rete verso Groq: {e}") from e
    except (TimeoutError, ConnectionError, OSError) as e:
        # Timeout durante la lettura della risposta (non sempre incapsulato
        # in URLError da urllib): senza questo except lo script crasha
        # invece di passare al provider successivo.
        raise LLMError(f"Timeout/errore di connessione verso Groq: {e}") from e

    try:
        content = body["choices"][0]["message"]["content"]
        parsed = extract_json(content)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        raise LLMError(f"Risposta Groq inattesa: {body}") from e

    return results_by_signature(parsed)
