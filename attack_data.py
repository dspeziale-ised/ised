"""Download e caricamento della matrice MITRE ATT&CK Enterprise (STIX 2.1).

Fonte ufficiale: https://github.com/mitre/cti (enterprise-attack.json).
Il file viene cachato in instance/attack_enterprise.json per non riscaricare
~47MB ad ogni avvio; ensure_loaded() lo scarica solo se manca o su force=True,
e ripopola le tabelle attack_tactics/attack_techniques/attack_technique_tactics.
"""
import json
import urllib.request
from pathlib import Path

import scanner_db

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_PATH = Path(__file__).resolve().parent / "instance" / "attack_enterprise.json"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def download_raw(force=False, timeout=120):
    """Scarica il dataset ufficiale MITRE ATT&CK e lo salva in cache locale."""
    if CACHE_PATH.exists() and not force:
        return CACHE_PATH.read_bytes()

    req = urllib.request.Request(ATTACK_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()

    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_bytes(raw)
    return raw


def _external_id_and_url(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def parse_and_load(conn, raw_bytes):
    """Estrae tattiche/tecniche dal STIX bundle e popola le tabelle attack_*."""
    bundle = json.loads(raw_bytes)
    objects = bundle.get("objects", [])

    tactics_by_stix_id = {}
    tactic_rows = []
    technique_rows = []
    technique_tactic_pairs = []

    matrix_tactic_order = None
    for obj in objects:
        if obj.get("type") == "x-mitre-matrix":
            matrix_tactic_order = obj.get("tactic_refs", [])
            break

    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        shortname = obj.get("x_mitre_shortname")
        if not shortname:
            continue
        tactics_by_stix_id[obj["id"]] = shortname
        _, url = _external_id_and_url(obj)
        tactic_rows.append({
            "shortname": shortname,
            "name": obj.get("name", shortname),
            "description": obj.get("description", ""),
            "url": url or "",
        })

    order_index = {stix_id: i for i, stix_id in enumerate(matrix_tactic_order or [])}
    tactic_rows.sort(key=lambda t: order_index.get(
        next((sid for sid, sn in tactics_by_stix_id.items() if sn == t["shortname"]), None),
        999,
    ))
    for i, row in enumerate(tactic_rows):
        row["sort_order"] = i

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id, url = _external_id_and_url(obj)
        if not technique_id:
            continue
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        parent_id = technique_id.split(".")[0] if is_sub and "." in technique_id else None
        platforms = ",".join(obj.get("x_mitre_platforms", []) or [])
        technique_rows.append({
            "technique_id": technique_id,
            "name": obj.get("name", technique_id),
            "description": obj.get("description", ""),
            "url": url or "",
            "is_subtechnique": 1 if is_sub else 0,
            "parent_technique_id": parent_id,
            "platforms": platforms,
        })
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            technique_tactic_pairs.append((technique_id, phase.get("phase_name")))

    cur = conn.cursor()
    cur.execute("DELETE FROM attack_technique_tactics")
    cur.execute("DELETE FROM attack_techniques")
    cur.execute("DELETE FROM attack_tactics")

    cur.executemany(
        "INSERT INTO attack_tactics (shortname, name, description, url, sort_order) "
        "VALUES (?, ?, ?, ?, ?)",
        [(r["shortname"], r["name"], r["description"], r["url"], r["sort_order"]) for r in tactic_rows],
    )
    cur.executemany(
        "INSERT INTO attack_techniques "
        "(technique_id, name, description, url, is_subtechnique, parent_technique_id, platforms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(r["technique_id"], r["name"], r["description"], r["url"], r["is_subtechnique"],
          r["parent_technique_id"], r["platforms"]) for r in technique_rows],
    )
    cur.executemany(
        "INSERT INTO attack_technique_tactics (technique_id, tactic_shortname) VALUES (?, ?) "
        "ON CONFLICT DO NOTHING",
        technique_tactic_pairs,
    )
    conn.commit()
    return {"tactics": len(tactic_rows), "techniques": len(technique_rows)}


def is_loaded(conn):
    row = conn.execute("SELECT COUNT(*) c FROM attack_techniques").fetchone()
    return row["c"] > 0


def ensure_loaded(conn, force=False):
    """Scarica (se necessario) e carica la matrice ATT&CK nel DB. Idempotente."""
    scanner_db.ensure_attack_tables(conn)
    if is_loaded(conn) and not force:
        return {"skipped": True}
    raw = download_raw(force=force)
    return parse_and_load(conn, raw)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scarica e carica la matrice MITRE ATT&CK")
    parser.add_argument("--db", default=scanner_db.resolve_db_target(Path(__file__).parent / "instance" / "inventory.db"))
    parser.add_argument("--force", action="store_true", help="Riscarica e ricarica anche se già presente")
    args = parser.parse_args()

    conn = scanner_db.connect(args.db)
    result = ensure_loaded(conn, force=args.force)
    print(result)
