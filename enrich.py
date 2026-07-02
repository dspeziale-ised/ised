"""Funzioni di arricchimento: raccolgono evidenze extra su un host (banner
HTTP, condivisioni SMB, banner TCP grezzi) da usare come contesto per la
classificazione del tipo di dispositivo (manuale o via AI).

Pensate per essere chiamate una volta per gruppo di host con fingerprint
identico (stesso OS + stesse porte/servizi), non per ogni singolo host,
per restare leggere e non intrusive.
"""

import re
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from xml.etree import ElementTree as ET

NMAP_BIN = shutil.which("nmap") or "nmap"
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 10000, 10001, 5000, 5001}


def grab_http_banner(ip, port, timeout=5, use_https=None):
    """GET la radice del servizio web e ritorna status/header/title/snippet."""
    if use_https is None:
        use_https = port in (443, 8443)
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}/"
    ctx = None
    if use_https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "net-inventory-enrich/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            return {
                "status": resp.status,
                "server_header": resp.headers.get("Server", ""),
                "title": title_match.group(1).strip() if title_match else "",
                "body_snippet": body[:300],
            }
    except urllib.error.HTTPError as e:
        # Anche un 401/403/404 rivela spesso il prodotto via header/pagina di errore.
        body = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        return {
            "status": e.code,
            "server_header": e.headers.get("Server", "") if e.headers else "",
            "title": title_match.group(1).strip() if title_match else "",
            "body_snippet": body[:300],
        }
    except Exception as e:
        return {"error": str(e)}


def grab_tcp_banner(ip, port, timeout=3, probe=b""):
    """Connessione TCP grezza: utile per porte 'tcpwrapped' non identificate da nmap."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            if probe:
                s.sendall(probe)
            s.settimeout(timeout)
            data = s.recv(1024)
            return {"banner": data.decode("utf-8", errors="replace").strip()}
    except socket.timeout:
        return {"banner": "", "note": "connesso ma nessun dato ricevuto (timeout)"}
    except Exception as e:
        return {"error": str(e)}


def enum_smb_shares(ip, timeout=30):
    """Usa gli script NSE di nmap per enumerare condivisioni SMB e info SMB/OS."""
    try:
        result = subprocess.run(
            [
                NMAP_BIN, "-Pn", "-p", "139,445",
                "--script", "smb-enum-shares,smb-os-discovery",
                "-oX", "-", ip,
            ],
            capture_output=True, text=True, timeout=timeout,
        )
        root = ET.fromstring(result.stdout)
        scripts = {}
        for script in root.iter("script"):
            output = (script.get("output") or "").strip()
            if output:
                scripts[script.get("id")] = output
        return scripts if scripts else {"note": "nessun output dagli script SMB"}
    except subprocess.TimeoutExpired:
        return {"error": "timeout durante l'enumerazione SMB"}
    except ET.ParseError:
        return {"error": "output nmap non valido"}
    except Exception as e:
        return {"error": str(e)}


def enrich_host(ip, services):
    """Raccoglie le evidenze extra pertinenti in base alle porte/servizi noti.

    `services` è una lista di dict/Row con almeno: port, protocol, state,
    service_name. Ritorna un dict {chiave: evidenza} pronto per essere
    serializzato nel prompt di classificazione.
    """
    evidence = {}
    smb_done = False

    for s in services:
        if s["state"] != "open":
            continue
        port = s["port"]
        name = (s["service_name"] or "").lower()

        if name in ("http", "https") or port in HTTP_PORTS:
            evidence[f"http_{port}"] = grab_http_banner(ip, port)
        elif port in (139, 445) or name == "netbios-ssn":
            if not smb_done:
                evidence["smb"] = enum_smb_shares(ip)
                smb_done = True
        elif name in ("tcpwrapped", "unknown", ""):
            evidence[f"tcp_{port}"] = grab_tcp_banner(ip, port)

    return evidence
