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
Configura un token condiviso (file keys/nmap_proxy_token,
o variabile d'ambiente NMAP_PROXY_TOKEN) prima di esporlo oltre 127.0.0.1 —
è richiesto nell'header 'X-Proxy-Token' di ogni richiesta. Deve restare in
ascolto su 0.0.0.0 (non solo 127.0.0.1) perché un container Docker Desktop
lo raggiunga tramite 'host.docker.internal'.
"""

import argparse
import base64
import shutil
import tempfile
import threading
import uuid
from pathlib import Path

from flask import Flask, jsonify, request

import nmap_conn_count
import secrets_store

app = Flask(__name__)
NMAP_BIN = shutil.which("nmap") or "nmap"

# Registro dei processi nmap in corso, indicizzati per request_id (di norma
# il nome del job — vedi nmap_proxy_client.py — dato che un solo job con
# quel nome può essere in esecuzione alla volta). Necessario perché
# interrompere il job dentro il container NON termina il vero processo
# nmap qui sull'host: sono due alberi di processi separati, collegati solo
# da questa richiesta HTTP, altrimenti "abbandonata" (nmap continuerebbe
# comunque fino al proprio timeout naturale). Lock perché Flask gestisce le
# richieste in thread diversi.
_active_processes = {}
_active_processes_lock = threading.Lock()

# Righe di stdout accumulate finora per una scansione in corso, indicizzate
# per request_id: permette a nmap_proxy_client._run_via_proxy di interrogare
# periodicamente /nmap/progress e mostrare l'avanzamento (es. le righe di
# 'nmap --stats-every N') PRIMA che l'intera richiesta HTTP completi, dato
# che altrimenti il client vedrebbe l'intero stdout solo alla fine (una
# singola risposta HTTP bloccante). Stesso ciclo di vita/lock pattern di
# _active_processes.
_progress_lines = {}
_progress_lines_lock = threading.Lock()


def _relocate_stdout_xml(args):
    """Se args contiene '-oX -' (il client chiede l'XML su stdout, per poi
    scriverlo nel path locale reale), lo rimpiazza con '-oX <tempfile>' su
    QUESTO host: nmap con '-oX -' sostituisce interamente lo stdout con
    l'XML, sopprimendo il riepilogo testuale (incluso 'Raw packets sent...',
    stampato da nmap solo con -v) che serve per il traffico in dashboard.
    Scrivendo l'XML su un file reale invece, stdout resta libero per quel
    testo. Ritorna (nuovi_args, path_tempfile_o_None) — il chiamante legge
    il file dopo l'esecuzione e lo cancella."""
    args = list(args)
    for i, a in enumerate(args):
        if a == "-oX" and i + 1 < len(args) and args[i + 1] == "-":
            tmp_path = Path(tempfile.gettempdir()) / f"nmap_proxy_{uuid.uuid4().hex}.xml"
            args[i + 1] = str(tmp_path)
            return args, tmp_path
    return args, None


def _expected_token():
    return secrets_store.load_secret("NMAP_PROXY_TOKEN", "nmap_proxy_token")


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


@app.route("/nmap/cancel", methods=["POST"])
def cancel_nmap_route():
    """Termina (se ancora in esecuzione) il processo nmap associato a
    request_id, registrato da run_nmap_route mentre gira. Chiamato da
    app.py quando l'utente ferma un job dalla UI, per propagare
    l'interruzione al vero processo nmap sull'host (altrimenti
    continuerebbe fino al proprio timeout naturale, vedi il commento su
    _active_processes)."""
    payload = request.get_json(force=True, silent=True) or {}
    request_id = payload.get("request_id")
    if not request_id:
        return jsonify({"error": "Campo 'request_id' mancante."}), 400

    with _active_processes_lock:
        proc = _active_processes.get(request_id)

    if proc is None or proc.poll() is not None:
        return jsonify({"cancelled": False, "reason": "Nessun processo nmap attivo per questo request_id."})

    try:
        proc.kill()
        proc.wait(timeout=5)
    except Exception as e:
        return jsonify({"cancelled": False, "reason": str(e)}), 500
    return jsonify({"cancelled": True})


@app.route("/nmap/progress")
def nmap_progress_route():
    """Righe di stdout accumulate finora per una scansione in corso (vedi
    _progress_lines), a partire dall'indice 'since': usato dal client per
    il polling periodico durante l'attesa (vedi
    nmap_proxy_client._run_via_proxy). Ritorna sempre 200 con lista vuota se
    request_id non è (più) noto — es. la scansione non è ancora iniziata,
    o è già terminata e la voce è stata rimossa — non è un errore."""
    request_id = request.args.get("request_id")
    since = request.args.get("since", type=int) or 0
    if not request_id:
        return jsonify({"lines": [], "next_since": since})
    with _progress_lines_lock:
        lines = _progress_lines.get(request_id, [])
        new_lines = lines[since:]
        next_since = len(lines)
    return jsonify({"lines": new_lines, "next_since": next_since})


@app.route("/nmap", methods=["POST"])
def run_nmap_route():
    payload = request.get_json(force=True, silent=True) or {}
    args = payload.get("args")
    timeout = payload.get("timeout") or 120
    request_id = payload.get("request_id")

    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return jsonify({"error": "Campo 'args' mancante o non valido (attesa una lista di stringhe)."}), 400

    # Rilocare '-oX -' su un file temporaneo SOLO se il client lo chiede
    # esplicitamente (relocate_xml: true): è il caso in cui il client aveva
    # un path reale e lo ha convertito in '-oX -' solo per trasportarlo via
    # HTTP (vedi nmap_proxy_client._run_via_proxy). Se invece è il chiamante
    # originale a voler l'XML grezzo direttamente su stdout (es.
    # host_monitor.py, vuln_scan.py), 'relocate_xml' è assente/false e il
    # comportamento resta quello storico (stdout_b64 = XML) — altrimenti
    # quei chiamanti riceverebbero il riepilogo testuale al posto dell'XML
    # che si aspettano di parsare.
    if payload.get("relocate_xml"):
        run_args, xml_tmp_path = _relocate_stdout_xml(args)
    else:
        run_args, xml_tmp_path = args, None
    cmd = [NMAP_BIN, *run_args]

    def _read_and_cleanup_xml():
        """Legge l'XML dal file temporaneo (se prodotto) e lo cancella. Un
        file assente/vuoto è normale se nmap è fallito prima di scrivere
        nulla (es. timeout immediato) — ritorna None in quel caso, il
        client tratta l'assenza di xml_b64 come prima (nessun cambiamento
        al path locale richiesto)."""
        if not xml_tmp_path:
            return None
        try:
            data = xml_tmp_path.read_bytes() if xml_tmp_path.exists() else None
        finally:
            xml_tmp_path.unlink(missing_ok=True)
        return data

    def _register(proc):
        if request_id:
            with _active_processes_lock:
                _active_processes[request_id] = proc
            with _progress_lines_lock:
                _progress_lines[request_id] = []

    def _unregister():
        if request_id:
            with _active_processes_lock:
                _active_processes.pop(request_id, None)
            with _progress_lines_lock:
                _progress_lines.pop(request_id, None)

    def _on_output_line(line):
        if request_id:
            with _progress_lines_lock:
                _progress_lines.setdefault(request_id, []).append(line)

    try:
        returncode, stdout, stderr, timed_out, conns_out, conns_in = \
            nmap_conn_count.run_and_count_connections(
                cmd, timeout=timeout, on_start=_register, on_output_line=_on_output_line,
            )
        xml_bytes = _read_and_cleanup_xml()
        response = {
            "returncode": returncode,
            "stdout_b64": base64.b64encode(stdout or b"").decode("ascii"),
            "stderr_b64": base64.b64encode(stderr or b"").decode("ascii"),
            "timed_out": timed_out,
            "connections_out": conns_out,
            "connections_in": conns_in,
        }
        if xml_bytes is not None:
            response["xml_b64"] = base64.b64encode(xml_bytes).decode("ascii")
        return jsonify(response)
    except FileNotFoundError:
        return jsonify({"error": f"Eseguibile nmap non trovato ('{NMAP_BIN}')."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        _unregister()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0",
                         help="Indirizzo di ascolto (0.0.0.0 di default, necessario per host.docker.internal)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if not _expected_token():
        print(
            "[!] ATTENZIONE: nessun token configurato (keys/nmap_proxy_token o NMAP_PROXY_TOKEN). "
            "Chiunque raggiunga questa porta puo' eseguire comandi nmap arbitrari sull'host. "
            "Configura il token prima di esporre il proxy oltre 127.0.0.1."
        )
    print(f"Proxy nmap in ascolto su {args.host}:{args.port} (binario: {NMAP_BIN})")
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
