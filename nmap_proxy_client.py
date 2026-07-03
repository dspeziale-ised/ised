"""Client per il proxy nmap (nmap_proxy_server.py).

Fornisce run_nmap(args, ...) come sostituto quasi drop-in di
subprocess.run(["nmap", *args], ...):

- se NMAP_PROXY_URL è impostata (modalità container: l'app gira in Docker,
  dove nmap non funziona in modo affidabile — specialmente su Docker
  Desktop/Windows, senza accesso ai raw socket/driver Npcap) inoltra la
  richiesta al proxy che gira nativamente sull'host con nmap vero
- altrimenti esegue nmap in locale esattamente come prima (NESSUN cambio di
  comportamento per l'uso nativo/non containerizzato di oggi)

Gestisce anche la traduzione dei pattern di I/O su file usati nel resto del
progetto, dato che il vero processo nmap (in modalità proxy) gira su una
macchina diversa dal chiamante:
  - '-oX <path>' (path reale, non '-'): tradotto in '-oX -' verso il proxy,
    l'XML ricevuto via stdout viene scritto qui nel path locale richiesto.
  - '-iL <path>': il file locale con la lista IP viene letto qui e i target
    passati al proxy come argomenti posizionali (IP diretti), invece di un
    path che sull'host proxy non esisterebbe.

Solleva subprocess.TimeoutExpired in caso di timeout, esattamente come
subprocess.run — così il codice chiamante esistente (che intercetta quella
eccezione) funziona invariato in entrambe le modalità.
"""

import base64
import os
import subprocess
from pathlib import Path

import requests

PROXY_URL = (os.environ.get("NMAP_PROXY_URL") or "").rstrip("/") or None
_TOKEN_FILE = Path(__file__).parent / "keys" / "nmap_proxy_token"


def _load_token():
    token = os.environ.get("NMAP_PROXY_TOKEN")
    if token:
        return token.strip()
    if _TOKEN_FILE.exists():
        return _TOKEN_FILE.read_text(encoding="utf-8").strip()
    return None


def is_proxy_mode():
    return bool(PROXY_URL)


class CompletedProcessLike:
    """Oggetto minimale compatibile con subprocess.CompletedProcess (solo i
    campi usati nel resto del progetto: returncode, stdout, stderr)."""

    def __init__(self, args, returncode, stdout, stderr):
        self.args = args
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run_nmap(args, timeout=None, capture_output=True, text=True):
    """Esegue nmap con gli argomenti indicati (senza il nome del binario).
    In assenza di NMAP_PROXY_URL, comportamento identico a
    subprocess.run(['nmap', *args], capture_output=capture_output, text=text,
    timeout=timeout). Con NMAP_PROXY_URL impostata, inoltra al proxy."""
    if not PROXY_URL:
        return subprocess.run(
            ["nmap", *args], capture_output=capture_output, text=text, timeout=timeout
        )
    return _run_via_proxy(args, timeout=timeout, text=text)


def _extract_output_file(args):
    """Se args contiene '-oX <path>' con un path reale (non '-'), lo
    rimpiazza con '-oX -' e ritorna (nuovi_args, path_locale). Altrimenti
    ritorna (args invariati, None)."""
    args = list(args)
    for i, a in enumerate(args):
        if a == "-oX" and i + 1 < len(args) and args[i + 1] != "-":
            local_path = args[i + 1]
            args[i + 1] = "-"
            return args, local_path
    return args, None


def _expand_input_file(args):
    """Se args contiene '-iL <path>', legge gli IP dal file locale e li
    aggiunge come target posizionali al posto del flag — sull'host del
    proxy quel path non esiste. Ritorna i nuovi args."""
    args = list(args)
    for i, a in enumerate(args):
        if a == "-iL" and i + 1 < len(args):
            path = args[i + 1]
            targets = [
                line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            del args[i:i + 2]
            return args + targets
    return args


def _run_via_proxy(args, timeout, text):
    proxy_args, local_output_path = _extract_output_file(args)
    proxy_args = _expand_input_file(proxy_args)

    headers = {}
    token = _load_token()
    if token:
        headers["X-Proxy-Token"] = token

    request_timeout = (timeout or 120) + 20  # margine oltre il timeout nmap lato proxy
    try:
        resp = requests.post(
            f"{PROXY_URL}/nmap", json={"args": proxy_args, "timeout": timeout},
            headers=headers, timeout=request_timeout,
        )
    except requests.Timeout as e:
        raise subprocess.TimeoutExpired(cmd=["nmap", *args], timeout=timeout) from e
    except requests.RequestException as e:
        raise RuntimeError(f"Proxy nmap non raggiungibile ({PROXY_URL}): {e}") from e

    if resp.status_code == 401:
        raise RuntimeError("Proxy nmap: token di autenticazione mancante/non valido (NMAP_PROXY_TOKEN).")
    if not resp.ok:
        raise RuntimeError(f"Proxy nmap: errore HTTP {resp.status_code}: {resp.text[:300]}")

    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"Proxy nmap: {data['error']}")

    stdout_bytes = base64.b64decode(data.get("stdout_b64") or "")
    stderr_bytes = base64.b64decode(data.get("stderr_b64") or "")

    if data.get("timed_out"):
        raise subprocess.TimeoutExpired(
            cmd=["nmap", *args], timeout=timeout, output=stdout_bytes, stderr=stderr_bytes
        )

    if local_output_path:
        Path(local_output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_output_path).write_bytes(stdout_bytes)
        stdout_result = "" if text else b""
    else:
        stdout_result = stdout_bytes.decode("utf-8", errors="replace") if text else stdout_bytes

    stderr_result = stderr_bytes.decode("utf-8", errors="replace") if text else stderr_bytes
    return CompletedProcessLike(
        args=["nmap", *args], returncode=data["returncode"], stdout=stdout_result, stderr=stderr_result
    )
