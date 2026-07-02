"""Elementi condivisi tra i client dei diversi provider LLM (Groq, Gemini,
Ollama) usati per classificare il tipo di dispositivo: eccezioni comuni,
prompt di sistema, e helper di parsing/estrazione JSON.

Avere eccezioni condivise permette a classify_devices.py di gestire il
fallback tra provider in modo generico, senza sapere quale provider ha
fallito.
"""

import json
import re


class LLMError(RuntimeError):
    """Errore generico nella chiamata a un provider LLM."""


class LLMTooLargeError(LLMError):
    """La richiesta supera il limite di token del provider: va ritentata con
    un batch più piccolo (stesso provider) o passata a un altro provider."""


class LLMRateLimitError(LLMError):
    """Limite di frequenza superato: va ritentata dopo un'attesa breve,
    o passata a un altro provider se persiste."""

    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


class LLMDailyLimitError(LLMRateLimitError):
    """Limite giornaliero/di quota superato: inutile ritentare a breve,
    conviene passare subito a un altro provider."""


SYSTEM_PROMPT = (
    "Sei un analista di sicurezza di rete esperto di fingerprinting. Ti vengono forniti "
    "gruppi di host: ogni gruppo condivide lo stesso identico fingerprint (stesso OS rilevato "
    "da nmap e stessa combinazione di porte/servizi aperti), quindi rappresenta un solo tipo "
    "di dispositivo. Per ogni gruppo ricevi anche eventuali evidenze extra (banner HTTP, "
    "condivisioni SMB, banner TCP grezzi). "
    "Per OGNI gruppo determina due cose separate: \n"
    "1) device_type: la categoria AMPIA e GENERICA del dispositivo, SEMPRE tutta in minuscolo, "
    "breve (2-4 parole), es. 'server linux', 'server windows', 'nas', 'router', 'firewall', "
    "'switch di rete', 'access point', 'telecamera ip', 'stampante di rete', 'hypervisor esxi', "
    "'controller cisco aci/apic'. Non metterci dettagli di ruolo/applicazione: quelli vanno in roles. "
    "2) roles: una lista di stringhe con i ruoli/funzioni/applicazioni SPECIFICHE rilevate su quel "
    "device_type, una voce per ruolo distinto, es. ['web server/reverse proxy nginx', "
    "'con applicazioni (apache tomcat)']. Lista vuota [] se non c'è nulla di specifico da segnalare "
    "oltre al tipo generico. Non ripetere il device_type dentro roles. "
    "Non inventare marchi/modelli/applicazioni non supportati dalle evidenze. "
    "Indica anche il produttore/vendor HARDWARE del dispositivo se le evidenze lo rendono "
    "ragionevolmente identificabile (es. banner HTTP con nome prodotto, MAC vendor, stringhe "
    "SMB/servizio con marchio, CPE nell'OS match). Usa il nome del produttore vero e proprio "
    "(es. 'Ubiquiti', 'Cisco', 'Synology', 'QNAP', 'TP-Link', 'Dell', 'HPE', 'VMware'): NON usare "
    "'Linux' come vendor, è il sistema operativo non il produttore. Se non è determinabile con "
    "ragionevole certezza lascia vendor come stringa vuota, non indovinare. "
    "Rispondi SEMPRE in italiano (tranne device_type/roles che restano descrittivi ma in minuscolo) "
    "e SOLO con un oggetto JSON con questa forma esatta, senza testo fuori dal JSON:\n"
    '{"results": [{"signature_id": "...", "device_type": "...", "roles": ["..."], '
    '"vendor": "...", "confidence": 0, "reasoning": "..."}]}\n'
    "confidence è un intero 0-100. reasoning massimo 2 frasi, basato solo sulle evidenze fornite."
)

# User-Agent "browser-like": alcuni provider (es. Groq, dietro Cloudflare)
# bloccano lo User-Agent di default di urllib.
BROWSER_LIKE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) net-inventory-classifier/1.0"
)


def extract_json(text):
    """Estrae un oggetto JSON da una risposta del modello, anche se contiene
    testo extra attorno al JSON (alcuni modelli non rispettano lo strict
    JSON-mode)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            raise
        return json.loads(match.group(0))


def parse_wait_seconds(detail):
    """Estrae un'attesa suggerita in secondi da un messaggio di errore tipo
    'try again in 51m46.08s' o 'try again in 15s'."""
    match = re.search(r"try again in ([0-9hms.\s]+)", detail, re.I)
    if not match:
        return None
    total = 0.0
    for value, unit in re.findall(r"(\d+(?:\.\d+)?)\s*(h|m|s)", match.group(1)):
        value = float(value)
        total += value * (3600 if unit == "h" else 60 if unit == "m" else 1)
    return total or None


def results_by_signature(parsed):
    return {
        r["signature_id"]: r
        for r in parsed.get("results", [])
        if "signature_id" in r
    }
