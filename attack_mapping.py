"""Regole euristiche per mappare servizi/vulnerabilità/tipo dispositivo di un
host sulle tecniche MITRE ATT&CK Enterprise applicabili.

Non è un'analisi di exploit reali: segnala esposizione POTENZIALE in base a
cosa un host espone sulla rete (porte/servizi aperti, CVE note, tipo
dispositivo). Tutti gli ID tecnica usati qui sono stati verificati contro il
dataset ufficiale MITRE ATT&CK (vedi attack_data.py) prima di essere inseriti.
"""

CRITICAL_CVSS_THRESHOLD = 9.0
HIGH_CVSS_THRESHOLD = 7.0

# porta -> [(technique_id, motivo)]
PORT_TECHNIQUES = {
    22: [("T1021.004", "porta SSH (22) esposta"), ("T1110", "servizio SSH esposto: possibile bersaglio brute force")],
    23: [("T1552", "porta Telnet (23) esposta: credenziali trasmesse in chiaro"), ("T1040", "Telnet non cifrato: intercettabile via sniffing di rete")],
    21: [("T1552", "porta FTP (21) esposta: spesso credenziali/anonymous in chiaro"), ("T1110", "servizio FTP esposto: possibile bersaglio brute force")],
    445: [("T1021.002", "porta SMB (445) esposta"), ("T1552", "SMB esposto: possibili condivisioni con credenziali deboli"), ("T1039", "SMB esposto: possibile accesso a condivisioni di rete")],
    139: [("T1021.002", "porta NetBIOS/SMB (139) esposta")],
    3389: [("T1021.001", "porta RDP (3389) esposta"), ("T1110", "servizio RDP esposto: possibile bersaglio brute force")],
    5900: [("T1021.005", "porta VNC (5900) esposta"), ("T1110", "servizio VNC esposto: possibile bersaglio brute force")],
    161: [("T1602.002", "porta SNMP (161) esposta: possibile dump configurazione dispositivo di rete")],
    2049: [("T1039", "porta NFS (2049) esposta: possibile accesso a condivisioni di rete")],
    111: [("T1039", "portmapper/RPC (111) esposto: spesso associato a NFS")],
    3306: [("T1210", "database MySQL esposto in rete"), ("T1552", "database esposto: rischio credenziali deboli/di default")],
    5432: [("T1210", "database PostgreSQL esposto in rete"), ("T1552", "database esposto: rischio credenziali deboli/di default")],
    1433: [("T1210", "database MSSQL esposto in rete"), ("T1552", "database esposto: rischio credenziali deboli/di default")],
    1521: [("T1210", "database Oracle esposto in rete"), ("T1552", "database esposto: rischio credenziali deboli/di default")],
    27017: [("T1210", "database MongoDB esposto in rete"), ("T1552", "database esposto: rischio credenziali deboli/di default")],
}

# keyword (in service_name/product, minuscolo) -> [(technique_id, motivo)]
SERVICE_NAME_TECHNIQUES = {
    "vnc": [("T1021.005", "servizio VNC rilevato")],
    "ms-wbt-server": [("T1021.001", "servizio RDP rilevato")],
    "rdp": [("T1021.001", "servizio RDP rilevato")],
    "microsoft-ds": [("T1021.002", "servizio SMB rilevato")],
    "netbios-ssn": [("T1021.002", "servizio NetBIOS/SMB rilevato")],
    "snmp": [("T1602.002", "servizio SNMP rilevato: possibile dump configurazione")],
    "nfs": [("T1039", "servizio NFS rilevato: possibile accesso a condivisioni di rete")],
    "telnet": [("T1552", "servizio Telnet rilevato: credenziali in chiaro")],
    "ftp": [("T1552", "servizio FTP rilevato")],
}

# servizi web: qualsiasi match parziale in service_name -> Exploit Public-Facing Application
WEB_SERVICE_NAMES = {"http", "https", "ssl/http", "http-proxy", "http-alt"}
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9090}

# substring nel device_type (minuscolo) -> [(technique_id, motivo)]
DEVICE_TYPE_TECHNIQUES = {
    "router": [("T1599", "dispositivo di rete (router): possibile bridging tra segmenti"), ("T1016", "dispositivo di rete: discovery configurazione di rete")],
    "switch": [("T1599", "dispositivo di rete (switch): possibile bridging tra segmenti")],
    "firewall": [("T1599", "dispositivo di rete (firewall): possibile bridging/bypass tra segmenti")],
    "access point": [("T1599", "access point wireless: possibile punto di bridging verso la rete cablata")],
}


def _add(bucket, technique_id, reason):
    if technique_id not in bucket:
        bucket[technique_id] = set()
    bucket[technique_id].add(reason)


def map_host_techniques(host, services, vulnerabilities):
    """host: dict con almeno 'device_type'.
    services: lista di dict con 'port', 'service_name', 'product' (solo stato open).
    vulnerabilities: lista di dict con 'cvss'.
    Ritorna lista di {'technique_id': ..., 'reason': ...} deduplicata."""
    bucket = {}
    has_remote_access = False

    for svc in services or []:
        port = svc.get("port")
        service_name = (svc.get("service_name") or "").lower()
        product = (svc.get("product") or "").lower()

        for technique_id, reason in PORT_TECHNIQUES.get(port, []):
            _add(bucket, technique_id, reason)
            if technique_id.startswith("T1021"):
                has_remote_access = True

        for keyword, rules in SERVICE_NAME_TECHNIQUES.items():
            if keyword in service_name or keyword in product:
                for technique_id, reason in rules:
                    _add(bucket, technique_id, reason)
                    if technique_id.startswith("T1021"):
                        has_remote_access = True

        if port in WEB_PORTS or any(w in service_name for w in WEB_SERVICE_NAMES):
            _add(bucket, "T1190", f"servizio web esposto sulla porta {port}")

    if has_remote_access:
        _add(bucket, "T1078", "servizi di accesso remoto esposti: vettore comune è l'uso di credenziali valide")

    device_type = (host.get("device_type") or "").lower()
    for keyword, rules in DEVICE_TYPE_TECHNIQUES.items():
        if keyword in device_type:
            for technique_id, reason in rules:
                _add(bucket, technique_id, reason)

    max_cvss = 0.0
    for vuln in vulnerabilities or []:
        cvss = vuln.get("cvss") or 0
        if cvss > max_cvss:
            max_cvss = cvss
    if max_cvss >= CRITICAL_CVSS_THRESHOLD:
        _add(bucket, "T1210", f"CVE critica nota su un servizio esposto (CVSS {max_cvss})")
    elif max_cvss >= HIGH_CVSS_THRESHOLD:
        _add(bucket, "T1210", f"CVE ad alta severità nota su un servizio esposto (CVSS {max_cvss})")

    return [
        {"technique_id": tid, "reason": "; ".join(sorted(reasons))}
        for tid, reasons in bucket.items()
    ]
