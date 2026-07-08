"""Parser incrementale per output XML di nmap (-sV -O), robusto a file troncati."""

from xml.etree.ElementTree import iterparse, ParseError


def _text_or_none(value):
    return value if value else None


def parse_host_element(elem):
    """Converte un elemento <host> dell'XML di nmap in un dict pronto per il DB."""
    status = elem.find("status")
    state = status.get("state") if status is not None else None
    # reason ('echo-reply' = ha risposto a un ping ICMP, 'syn-ack' = porta TCP
    # aperta, ecc.) e reason_ttl (TTL con cui è arrivata la risposta): usati
    # come euristica di riserva in classify.py quando OS match/porte non
    # bastano — un TTL di partenza stimato a 255 è tipico di apparati di rete.
    status_reason = status.get("reason") if status is not None else None
    reason_ttl_raw = status.get("reason_ttl") if status is not None else None
    ttl = int(reason_ttl_raw) if reason_ttl_raw not in (None, "", "0") else None

    ip = None
    mac_address = None
    mac_vendor = None
    for address in elem.findall("address"):
        addrtype = address.get("addrtype")
        if addrtype == "ipv4":
            ip = address.get("addr")
        elif addrtype == "mac":
            mac_address = address.get("addr")
            mac_vendor = address.get("vendor")

    if ip is None:
        return None

    hostname = None
    hostnames_el = elem.find("hostnames")
    if hostnames_el is not None:
        hn = hostnames_el.find("hostname")
        if hn is not None:
            hostname = hn.get("name")

    services = []
    ports_el = elem.find("ports")
    if ports_el is not None:
        for port in ports_el.findall("port"):
            port_state = port.find("state")
            service = port.find("service")
            cpe = None
            if service is not None:
                cpe_el = service.find("cpe")
                if cpe_el is not None:
                    cpe = _text_or_none(cpe_el.text)
            scripts = [
                {"id": script.get("id"), "output": script.get("output")}
                for script in port.findall("script")
            ]
            services.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": port_state.get("state") if port_state is not None else None,
                "service_name": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
                "extrainfo": service.get("extrainfo") if service is not None else None,
                "tunnel": service.get("tunnel") if service is not None else None,
                "cpe": cpe,
                "scripts": scripts,
            })

    os_matches = []
    os_el = elem.find("os")
    if os_el is not None:
        for osmatch in os_el.findall("osmatch"):
            osclass = osmatch.find("osclass")
            os_matches.append({
                "name": osmatch.get("name"),
                "accuracy": int(osmatch.get("accuracy", 0)),
                "os_family": osclass.get("osfamily") if osclass is not None else None,
                "os_gen": osclass.get("osgen") if osclass is not None else None,
                "os_type": osclass.get("type") if osclass is not None else None,
                "vendor": osclass.get("vendor") if osclass is not None else None,
            })

    distance_el = elem.find("distance")
    distance = int(distance_el.get("value")) if distance_el is not None else None

    best_os = os_matches[0] if os_matches else {}

    # Script a livello HOST (<hostscript>), distinti da quelli a livello
    # porta dentro <ports><port> sopra: nbstat/smb-os-discovery/smb-enum-*
    # non sono legati a una porta specifica (nmap li mette qui anche se
    # innescati dalla presenza di 445/tcp o 137/udp), quindi vanno raccolti
    # separatamente — un parser che guardasse solo dentro <port> li perderebbe
    # silenziosamente (bug verificato: erano visibili nell'output testuale di
    # nmap ma non finivano mai nel DB).
    host_scripts = []
    hostscript_el = elem.find("hostscript")
    if hostscript_el is not None:
        for script in hostscript_el.findall("script"):
            host_scripts.append({"id": script.get("id"), "output": script.get("output")})

    return {
        "ip": ip,
        "hostname": _text_or_none(hostname),
        "mac_address": mac_address,
        "mac_vendor": mac_vendor,
        "host_scripts": host_scripts,
        "state": state,
        "status_reason": status_reason,
        "ttl": ttl,
        "timed_out": elem.get("timedout") == "true",
        "distance": distance,
        "os_name": best_os.get("name"),
        "os_accuracy": best_os.get("accuracy"),
        "os_family": best_os.get("os_family"),
        "os_gen": best_os.get("os_gen"),
        "os_matches": os_matches,
        "services": services,
    }


def parse_nmap_xml(xml_path):
    """Estrae gli host da un file XML di nmap (anche se troncato/in scrittura)."""
    hosts = []
    with open(xml_path, "rb") as f:
        parser = iterparse(f, events=("end",))
        try:
            for _, elem in parser:
                if elem.tag != "host":
                    continue
                host = parse_host_element(elem)
                if host is not None:
                    hosts.append(host)
                elem.clear()
        except ParseError:
            pass
    return hosts
