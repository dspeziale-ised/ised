#!/usr/bin/env python3
"""Proxy HTTP per nmap: gira NATIVAMENTE sull'host Windows (dove nmap/Npcap
funzionano correttamente), NON dentro Docker. L'app principale, quando gira
containerizzata, non installa nmap al suo interno (problemi noti coi driver
raw-socket/Npcap dentro Docker su Windows) e invoca invece questo proxy via
HTTP per eseguire le scansioni sull'host.

Uso:
    python nmap_proxy_server.py                  # ascolta su 0.0.0.0:8765
    python nmap_proxy_server.py --port 9000
    python nmap_proxy_server.py --host 127.0.0.1 # solo se il chiamante non è containerizzato

Sicurezza: il proxy esegue comandi nmap arbitrari passati dal chiamante.
Configura un token condiviso (file .nmap_proxy_token nella stessa cartella,
o variabile d'ambiente NMAP_PROXY_TOKEN) prima di esporlo oltre 127.0.0.1 —
è richiesto nell'header 'X-Proxy-Token' di ogni richiesta. Deve restare in
ascolto su 0.0.0.0 (non solo 127.0.0.1) perché un container Docker Desktop
lo raggiunga tramite 'host.docker.internal'.
"""

import argparse
import base64
import os
import shutil
import subprocess
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)
NMAP_BIN = shutil.which("nmap") or "nmap"
_TOKEN_FILE = Path(__file__).parent / ".nmap_proxy_token"


def _expected_token():
    token = os.environ.get("NMAP_PROXY_TOKEN")
    if token:
        return token.strip()
    if _TOKEN_FILE.exists():
        return _TOKEN_FILE.read_text(encoding="utf-8").strip()
    return None


@app.before_request
def _check_token():
    expected = _expected_token()
    if not expected:
        return  # nessun token configurato: solo per test su rete fidata, vedi warning all'avvio
    if request.headers.get("X-Proxy-Token") != expected:
        return jsonify({"error": "Token di autenticazione mancante o non valido."}), 401


@app.route("/health")
def health():
    return jsonify({"ok": True, "nmap": NMAP_BIN, "auth_required": bool(_expected_token())})


@app.route("/nmap", methods=["POST"])
def run_nmap_route():
    payload = request.get_json(force=True, silent=True) or {}
    args = payload.get("args")
    timeout = payload.get("timeout") or 120

    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return jsonify({"error": "Campo 'args' mancante o non valido (attesa una lista di stringhe)."}), 400

    cmd = [NMAP_BIN, *args]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return jsonify({
            "returncode": result.returncode,
            "stdout_b64": base64.b64encode(result.stdout).decode("ascii"),
            "stderr_b64": base64.b64encode(result.stderr).decode("ascii"),
            "timed_out": False,
        })
    except subprocess.TimeoutExpired as e:
        return jsonify({
            "returncode": None,
            "stdout_b64": base64.b64encode(e.stdout or b"").decode("ascii"),
            "stderr_b64": base64.b64encode(e.stderr or b"").decode("ascii"),
            "timed_out": True,
        })
    except FileNotFoundError:
        return jsonify({"error": f"Eseguibile nmap non trovato ('{NMAP_BIN}')."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0",
                         help="Indirizzo di ascolto (0.0.0.0 di default, necessario per host.docker.internal)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if not _expected_token():
        print(
            "[!] ATTENZIONE: nessun token configurato (.nmap_proxy_token o NMAP_PROXY_TOKEN). "
            "Chiunque raggiunga questa porta puo' eseguire comandi nmap arbitrari sull'host. "
            "Configura il token prima di esporre il proxy oltre 127.0.0.1."
        )
    print(f"Proxy nmap in ascolto su {args.host}:{args.port} (binario: {NMAP_BIN})")
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
