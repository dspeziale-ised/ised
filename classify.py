"""Classificazione del tipo di dispositivo a partire da OS fingerprint e servizi."""

# Porte/servizi noti per dedurre il tipo dispositivo quando nmap non ha un OS match.
_PRINTER_PORTS = {515, 631, 9100}
_CAMERA_PORTS = {554, 8554}
_ROUTER_KEYWORDS = ("router", "ios", "junos", "routeros", "cisco", "mikrotik")
_SWITCH_KEYWORDS = ("switch",)
_NAS_KEYWORDS = ("nas", "synology", "qnap", "freenas", "truenas")
_HYPERVISOR_KEYWORDS = ("esxi", "vmware", "hyper-v", "proxmox", "xen")
_WINDOWS_PORTS = {135, 139, 445, 3389}


def classify_device(os_matches, services):
    """Ritorna (device_type, device_vendor) migliore stima disponibile.
    device_type è sempre in minuscolo."""
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
    if not services:
        return "unknown", None

    return "general purpose", None
