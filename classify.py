"""Classificazione del tipo di dispositivo a partire da OS fingerprint e servizi."""

# Porte/servizi noti per dedurre il tipo dispositivo quando nmap non ha un OS match.
_PRINTER_PORTS = {515, 631, 9100}
_CAMERA_PORTS = {554, 8554}
_ROUTER_KEYWORDS = ("router", "ios", "junos", "routeros", "cisco", "mikrotik")
_SWITCH_KEYWORDS = ("switch",)
_NAS_KEYWORDS = ("nas", "synology", "qnap", "freenas", "truenas")
_HYPERVISOR_KEYWORDS = ("esxi", "vmware", "hyper-v", "proxmox", "xen")
_WINDOWS_PORTS = {135, 139, 445, 3389}

# TTL di partenza tipici: da qui si stima quanti hop sono stati attraversati
# (baseline - ttl_osservato). Un TTL di partenza a 255 è tipico di apparati
# di rete (router/switch/firewall), utile quando non ci sono porte aperte
# o OS match a disposizione (es. un host che risponde solo al ping ICMP).
_TTL_BASELINES = (64, 128, 255)


def guess_ttl_baseline(ttl):
    """Stima il TTL di partenza (64/128/255) e gli hop attraversati da un
    TTL osservato in una risposta (es. reason_ttl di un echo-reply ICMP).
    Ritorna (baseline, hops), oppure (None, None) se ttl è assente/invalido."""
    if not ttl:
        return None, None
    for baseline in _TTL_BASELINES:
        if ttl <= baseline:
            return baseline, baseline - ttl
    return None, None


def is_likely_gateway_ip(ip):
    """True se l'ultimo ottetto è .1, convenzione tipica per gateway/router
    di una sottorete (non una prova, solo un indizio supplementare)."""
    return bool(ip) and ip.rsplit(".", 1)[-1] == "1"


def classify_device(os_matches, services, ip=None, ttl=None):
    """Ritorna (device_type, device_vendor) migliore stima disponibile.
    device_type è sempre in minuscolo. ip/ttl sono opzionali: usati solo
    come euristica di riserva (TTL della risposta ping + convenzione .1 per
    i gateway) quando OS match e porte/servizi non danno un segnale forte —
    tipico di un host visto solo in un ping-sweep (-sn), senza scansione
    porte/OS completa."""
    if os_matches:
        best = os_matches[0]
        if best.get("os_type"):
            return best["os_type"].lower(), best.get("vendor")

    products = " ".join(
        (s.get("product") or "") + " " + (s.get("extrainfo") or "")
        for s in services
    ).lower()
    open_ports = {s["port"] for s in services if s.get("state") == "open"}

    if open_ports & _PRINTER_PORTS:
        return "printer", None
    if open_ports & _CAMERA_PORTS:
        return "camera/dvr", None
    if any(k in products for k in _ROUTER_KEYWORDS):
        return "router", None
    if any(k in products for k in _SWITCH_KEYWORDS):
        return "switch", None
    if any(k in products for k in _NAS_KEYWORDS):
        return "storage-misc", None
    if any(k in products for k in _HYPERVISOR_KEYWORDS):
        return "hypervisor", None
    if open_ports & _WINDOWS_PORTS:
        return "general purpose (windows-like)", None

    baseline, _hops = guess_ttl_baseline(ttl)
    if baseline == 255:
        return ("router" if is_likely_gateway_ip(ip) else "network device"), None

    if not services:
        return "unknown", None

    return "general purpose", None
