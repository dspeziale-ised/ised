"""Pipeline comune a tutti gli script che eseguono nmap e salvano gli host
risultanti nel database: esegue il comando (via nmap_proxy_client, quindi
trasparente a modalità nativa/proxy), parsa l'XML prodotto, classifica e
upserta ogni host 'up', registra il batch in scans.

Era prima duplicata quasi identica in scan_and_store.py (run_batch) e
custom_scan.py (run_scan): centralizzata qui. Ogni chiamante resta
responsabile di costruire il comando/percorso XML e di stampare il proprio
riepilogo a partire dal dict ritornato — questa funzione non stampa nulla.
"""

import subprocess
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from classify import classify_device
from nmap_parser import parse_nmap_xml
import nmap_proxy_client
import scanner_db


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_and_store(cmd, xml_out, conn, target_count=None, timeout=None):
    """Esegue `nmap <cmd>` (args senza il nome del binario, con `-oX
    <xml_out>` già incluso), parsa l'XML prodotto e salva/aggiorna gli host
    con stato 'up' nel database, registrando il batch in `scans`.

    `target_count` è solo metadato per il log (`scans.target_count`): se il
    chiamante non conosce in anticipo quanti target ha richiesto (es.
    custom_scan.py, dove il target può essere un CIDR mai espanso
    esplicitamente), lasciarlo a None usa il numero di host effettivamente
    trovati nell'XML.

    Non solleva per timeout o altri errori nmap: li registra come stato del
    batch ('timeout'/'error', vedi scanner_db.log_scan) e prosegue
    comunque con l'XML parziale eventualmente già scritto, così un singolo
    batch/scansione fallita non compromette il resto di un run più ampio.

    Ritorna {'status', 'hosts_found', 'hosts_up': [host, ...], 'error_detail'}
    — hosts_up contiene i dict host così come upsertati (device_type
    incluso), utile ai chiamanti che vogliono stampare un riepilogo per
    host; error_detail è il messaggio dell'eccezione se status == 'error'
    (None altrimenti), utile ai chiamanti che vogliono loggarlo."""
    started = now_iso()
    status = "ok"
    error_detail = None
    try:
        nmap_proxy_client.run_nmap(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        status = "timeout"
    except Exception as e:
        # Es. RuntimeError del proxy nmap (non raggiungibile, token non
        # valido, ...): senza questo except un singolo batch/target
        # irraggiungibile farebbe crashare l'intero run invece di essere
        # registrato come batch fallito e proseguire con gli altri.
        status = "error"
        error_detail = str(e)
    finished = now_iso()

    hosts = []
    if xml_out.exists():
        try:
            hosts = parse_nmap_xml(xml_out)
        except ET.ParseError as e:
            # XML troncato/incompleto (es. batch interrotto a metà scrittura
            # da un timeout): tratta come nessun host trovato invece di
            # propagare, così un singolo batch/scansione con output
            # corrotto non fa crashare il resto del run.
            if status == "ok":
                status = "error"
            error_detail = error_detail or f"XML non valido/incompleto: {e}"

    hosts_up = []
    for host in hosts:
        if host["state"] != "up":
            continue
        device_type, device_vendor = classify_device(
            host["os_matches"], host["services"], ip=host["ip"], ttl=host.get("ttl")
        )
        host["device_type"] = device_type
        host["device_vendor"] = device_vendor
        host["last_scanned"] = finished
        host["raw_xml_path"] = str(xml_out)
        scanner_db.upsert_host(conn, host)
        hosts_up.append(host)

    if target_count is None:
        target_count = len(hosts) or 1
    scanner_db.log_scan(conn, started, finished, target_count, str(xml_out), "nmap " + " ".join(cmd), status)
    conn.commit()

    return {"status": status, "hosts_found": len(hosts), "hosts_up": hosts_up, "error_detail": error_detail}
