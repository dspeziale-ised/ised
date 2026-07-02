"""Schema e funzioni di accesso al database SQLite dell'inventario host."""

import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT UNIQUE NOT NULL,
    hostname      TEXT,
    mac_address   TEXT,
    mac_vendor    TEXT,
    state         TEXT,
    timed_out     INTEGER DEFAULT 0,
    distance      INTEGER,
    os_name       TEXT,
    os_accuracy   INTEGER,
    os_family     TEXT,
    os_gen        TEXT,
    device_type   TEXT,
    device_vendor TEXT,
    last_scanned  TEXT,
    scan_duration REAL,
    raw_xml_path  TEXT
);

CREATE TABLE IF NOT EXISTS os_matches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name        TEXT,
    accuracy    INTEGER,
    os_family   TEXT,
    os_gen      TEXT,
    os_type     TEXT,
    vendor      TEXT
);

CREATE TABLE IF NOT EXISTS services (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port         INTEGER,
    protocol     TEXT,
    state        TEXT,
    service_name TEXT,
    product      TEXT,
    version      TEXT,
    extrainfo    TEXT,
    tunnel       TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT,
    finished_at  TEXT,
    target_count INTEGER,
    xml_path     TEXT,
    command      TEXT,
    status       TEXT
);

-- Sotto-tipi/ruoli del dispositivo (es. "web server/reverse proxy nginx",
-- "con applicazioni (apache tomcat)"), distinti dal device_type principale
-- ("server linux") per poter avere più ruoli specifici per host.
CREATE TABLE IF NOT EXISTS host_roles (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    source     TEXT,
    created_at TEXT
);

-- Output grezzo degli script NSE eseguiti su una porta/servizio (script
-- default, vuln, vulners, ecc.), per non perdere il dettaglio raccolto.
CREATE TABLE IF NOT EXISTS service_scripts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id   INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    script_id    TEXT,
    output       TEXT,
    collected_at TEXT
);

-- Cache dei CVE trovati per una data CPE (es. cpe:/a:openbsd:openssh:8.2),
-- per evitare di rilanciare la ricerca (nmap --script vulners) sulla stessa
-- combinazione prodotto/versione più volte.
CREATE TABLE IF NOT EXISTS cve_cache (
    cpe        TEXT PRIMARY KEY,
    cve_json   TEXT NOT NULL,
    fetched_at TEXT
);

-- Vulnerabilità (CVE) rilevate su un host/porta, risolte dal vivo o riusate
-- dalla cache cve_cache quando la CPE è già nota.
CREATE TABLE IF NOT EXISTS host_vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER,
    cpe         TEXT,
    cve_id      TEXT NOT NULL,
    cvss        REAL,
    url         TEXT,
    source      TEXT,
    detected_at TEXT
);

-- Matrice MITRE ATT&CK Enterprise (tattiche + tecniche), scaricata dalla
-- fonte ufficiale (https://github.com/mitre/cti) e cachata localmente.
CREATE TABLE IF NOT EXISTS attack_tactics (
    shortname   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    sort_order  INTEGER
);

CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id        TEXT PRIMARY KEY,   -- es. 'T1021.001'
    name                TEXT NOT NULL,
    description         TEXT,
    url                 TEXT,
    is_subtechnique     INTEGER DEFAULT 0,
    parent_technique_id TEXT,
    platforms           TEXT
);

CREATE TABLE IF NOT EXISTS attack_technique_tactics (
    technique_id     TEXT NOT NULL REFERENCES attack_techniques(technique_id) ON DELETE CASCADE,
    tactic_shortname TEXT NOT NULL REFERENCES attack_tactics(shortname) ON DELETE CASCADE,
    PRIMARY KEY (technique_id, tactic_shortname)
);

-- Tecniche ATT&CK potenzialmente applicabili a un host, secondo la
-- mappatura euristica basata su servizi/vulnerabilità/tipo dispositivo
-- (non un'analisi di exploit reali: segnala esposizione potenziale).
CREATE TABLE IF NOT EXISTS host_attack_techniques (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL,
    reason       TEXT,
    source       TEXT,
    detected_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_os_matches_host ON os_matches(host_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_hosts_device_type ON hosts(device_type);
CREATE INDEX IF NOT EXISTS idx_host_roles_host ON host_roles(host_id);
CREATE INDEX IF NOT EXISTS idx_service_scripts_service ON service_scripts(service_id);
CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_host ON host_vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_attack_technique_tactics_tactic ON attack_technique_tactics(tactic_shortname);
CREATE INDEX IF NOT EXISTS idx_host_attack_techniques_host ON host_attack_techniques(host_id);
CREATE INDEX IF NOT EXISTS idx_host_attack_techniques_technique ON host_attack_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_cve ON host_vulnerabilities(cve_id);
"""


def connect(db_path):
    """Apre (creando se serve) il DB SQLite in db_path. Crea anche la
    cartella contenente il file (es. instance/) se non esiste già."""
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn):
    conn.executescript(SCHEMA)
    conn.commit()
    ensure_ai_columns(conn)
    ensure_service_columns(conn)


AI_COLUMNS = {
    "fingerprint_signature": "TEXT",
    "ai_device_type": "TEXT",
    "ai_confidence": "INTEGER",
    "ai_reasoning": "TEXT",
    "ai_classified_at": "TEXT",
    "ai_provider": "TEXT",
    "device_type_manual": "INTEGER DEFAULT 0",
}

SERVICE_COLUMNS = {
    "cpe": "TEXT",
}


def ensure_service_columns(conn):
    """Aggiunge le colonne extra su services (es. cpe) se non esistono già."""
    conn.executescript(SCHEMA)  # crea le tabelle nuove (host_roles, cve_cache, ecc.) se il DB è preesistente
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(services)")}
    added = False
    for col, col_type in SERVICE_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE services ADD COLUMN {col} {col_type}")
            added = True
    conn.commit()
    return added


def ensure_ai_columns(conn):
    """Aggiunge le colonne per la classificazione AI (Groq) se non esistono già.
    Migrazione additiva e idempotente, sicura da chiamare su un DB già popolato."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(hosts)")}
    added = False
    for col, col_type in AI_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE hosts ADD COLUMN {col} {col_type}")
            added = True
    if added:
        conn.commit()


def normalize_device_types(conn):
    """Forza device_type/ai_device_type sempre in minuscolo (idempotente)."""
    conn.execute(
        "UPDATE hosts SET device_type = LOWER(device_type) "
        "WHERE device_type IS NOT NULL AND device_type != LOWER(device_type)"
    )
    conn.execute(
        "UPDATE hosts SET ai_device_type = LOWER(ai_device_type) "
        "WHERE ai_device_type IS NOT NULL AND ai_device_type != LOWER(ai_device_type)"
    )
    conn.commit()


def get_scanned_ips(conn):
    return {row["ip"] for row in conn.execute("SELECT ip FROM hosts")}


def set_host_roles(conn, host_id, roles, source="ai"):
    """Sostituisce i sotto-tipi/ruoli di un host per una data fonte (es. 'ai')."""
    conn.execute("DELETE FROM host_roles WHERE host_id = ? AND source = ?", (host_id, source))
    for role in roles or []:
        role = (role or "").strip()
        if not role:
            continue
        conn.execute(
            "INSERT INTO host_roles (host_id, role, source, created_at) VALUES (?, ?, ?, datetime('now'))",
            (host_id, role, source),
        )
    conn.commit()


def get_host_roles(conn, host_id):
    return [row["role"] for row in conn.execute(
        "SELECT role FROM host_roles WHERE host_id = ? ORDER BY id", (host_id,)
    )]


def get_cached_cve(conn, cpe):
    """Ritorna (lista_cve, fetched_at) dalla cache per una CPE, o None se assente."""
    row = conn.execute(
        "SELECT cve_json, fetched_at FROM cve_cache WHERE cpe = ?", (cpe,)
    ).fetchone()
    if not row:
        return None
    return json.loads(row["cve_json"]), row["fetched_at"]


def set_cached_cve(conn, cpe, cve_list):
    conn.execute(
        """INSERT INTO cve_cache (cpe, cve_json, fetched_at) VALUES (?, ?, datetime('now'))
           ON CONFLICT(cpe) DO UPDATE SET cve_json = excluded.cve_json, fetched_at = excluded.fetched_at""",
        (cpe, json.dumps(cve_list)),
    )
    conn.commit()


def merge_cached_cve(conn, cpe, new_cve_list):
    """Aggiunge/aggiorna le CVE di una CPE nella cache SENZA perdere quelle
    già presenti (a differenza di set_cached_cve, che sovrascrive) — usato
    per import cumulativi da file esterni. Ritorna il numero di CVE totali
    in cache per quella CPE dopo il merge."""
    cached = get_cached_cve(conn, cpe)
    existing = cached[0] if cached else []
    by_id = {c["id"]: c for c in existing if c.get("id")}
    for c in new_cve_list:
        cid = c.get("id")
        if not cid:
            continue
        if cid not in by_id or (c.get("cvss") or 0) > (by_id[cid].get("cvss") or 0):
            by_id[cid] = c
    merged = sorted(by_id.values(), key=lambda c: c.get("cvss") or 0, reverse=True)
    set_cached_cve(conn, cpe, merged)
    return len(merged)


def cve_cache_stats(conn):
    """Ritorna {'cpes': N, 'cves': M} sulla cache CVE attuale."""
    cpes = conn.execute("SELECT COUNT(*) c FROM cve_cache").fetchone()["c"]
    total_cves = 0
    for row in conn.execute("SELECT cve_json FROM cve_cache"):
        total_cves += len(json.loads(row["cve_json"]))
    return {"cpes": cpes, "cves": total_cves}


def set_host_vulnerabilities(conn, host_id, port, cpe, cve_list, source):
    """Sostituisce le vulnerabilità note per un host/porta/cpe."""
    conn.execute(
        "DELETE FROM host_vulnerabilities WHERE host_id = ? AND port = ? AND cpe = ?",
        (host_id, port, cpe),
    )
    for cve in cve_list:
        conn.execute(
            """INSERT INTO host_vulnerabilities (host_id, port, cpe, cve_id, cvss, url, source, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (host_id, port, cpe, cve.get("id"), cve.get("cvss"), cve.get("url"), source),
        )
    conn.commit()


def ensure_attack_tables(conn):
    """Crea le tabelle attack_* se mancanti (DB preesistente). Idempotente."""
    conn.executescript(SCHEMA)
    conn.commit()


def set_host_attack_techniques(conn, host_id, techniques, source="heuristic"):
    """Sostituisce le tecniche ATT&CK associate a un host per una data fonte.
    techniques: lista di dict {'technique_id': ..., 'reason': ...}."""
    conn.execute(
        "DELETE FROM host_attack_techniques WHERE host_id = ? AND source = ?", (host_id, source)
    )
    for t in techniques or []:
        technique_id = (t.get("technique_id") or "").strip()
        if not technique_id:
            continue
        conn.execute(
            """INSERT INTO host_attack_techniques (host_id, technique_id, reason, source, detected_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            (host_id, technique_id, t.get("reason", ""), source),
        )
    conn.commit()


def get_host_attack_techniques(conn, host_id):
    """Ritorna le tecniche ATT&CK rilevate per un host, con nome/tattiche/url."""
    rows = conn.execute(
        """SELECT hat.technique_id, hat.reason, hat.detected_at,
                  at.name, at.url, at.is_subtechnique, at.parent_technique_id
           FROM host_attack_techniques hat
           JOIN attack_techniques at ON at.technique_id = hat.technique_id
           WHERE hat.host_id = ?
           ORDER BY hat.technique_id""",
        (host_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def attack_matrix_data(conn, only_exposed=False):
    """Ritorna {tactics: [...], techniques_by_tactic: {shortname: [...]}} con il
    conteggio di host esposti per tecnica, per costruire la vista a matrice.
    Se only_exposed=True, restituisce solo le tecniche con almeno un host esposto."""
    tactics = [dict(r) for r in conn.execute(
        "SELECT shortname, name, description, url, sort_order FROM attack_tactics ORDER BY sort_order"
    )]

    exposure = {}
    for row in conn.execute(
        """SELECT technique_id, COUNT(DISTINCT host_id) c
           FROM host_attack_techniques GROUP BY technique_id"""
    ):
        exposure[row["technique_id"]] = row["c"]

    techniques_by_tactic = {t["shortname"]: [] for t in tactics}
    for row in conn.execute(
        """SELECT tt.tactic_shortname, t.technique_id, t.name, t.url,
                  t.is_subtechnique, t.parent_technique_id
           FROM attack_technique_tactics tt
           JOIN attack_techniques t ON t.technique_id = tt.technique_id
           ORDER BY t.technique_id"""
    ):
        shortname = row["tactic_shortname"]
        if shortname not in techniques_by_tactic:
            continue
        host_count = exposure.get(row["technique_id"], 0)
        if only_exposed and host_count == 0:
            continue
        techniques_by_tactic[shortname].append({
            "technique_id": row["technique_id"],
            "name": row["name"],
            "url": row["url"],
            "is_subtechnique": bool(row["is_subtechnique"]),
            "parent_technique_id": row["parent_technique_id"],
            "host_count": host_count,
        })

    return {"tactics": tactics, "techniques_by_tactic": techniques_by_tactic}


def hosts_for_technique(conn, technique_id):
    rows = conn.execute(
        """SELECT DISTINCT h.ip, h.device_type, hat.reason
           FROM host_attack_techniques hat
           JOIN hosts h ON h.id = hat.host_id
           WHERE hat.technique_id = ?
           ORDER BY h.ip""",
        (technique_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def upsert_host(conn, host):
    """Inserisce/aggiorna un host e sostituisce le sue righe os_matches/services."""
    cur = conn.execute("SELECT id FROM hosts WHERE ip = ?", (host["ip"],))
    row = cur.fetchone()

    fields = (
        host["ip"], host.get("hostname"), host.get("mac_address"),
        host.get("mac_vendor"), host.get("state"), int(host.get("timed_out", False)),
        host.get("distance"), host.get("os_name"), host.get("os_accuracy"),
        host.get("os_family"), host.get("os_gen"), host.get("device_type"),
        host.get("device_vendor"), host.get("last_scanned"), host.get("scan_duration"),
        host.get("raw_xml_path"),
    )

    if row:
        host_id = row["id"]
        # device_type/device_vendor non vengono toccati se l'utente li ha
        # impostati manualmente dal dettaglio host (device_type_manual = 1).
        conn.execute(
            """UPDATE hosts SET hostname=?, mac_address=?, mac_vendor=?, state=?,
                   timed_out=?, distance=?, os_name=?, os_accuracy=?, os_family=?,
                   os_gen=?,
                   device_type = CASE WHEN device_type_manual = 1 THEN device_type ELSE ? END,
                   device_vendor = CASE WHEN device_type_manual = 1 THEN device_vendor ELSE ? END,
                   last_scanned=?, scan_duration=?, raw_xml_path=?
               WHERE id=?""",
            fields[1:] + (host_id,),
        )
        conn.execute("DELETE FROM os_matches WHERE host_id = ?", (host_id,))
        conn.execute("DELETE FROM services WHERE host_id = ?", (host_id,))
    else:
        cur = conn.execute(
            """INSERT INTO hosts (ip, hostname, mac_address, mac_vendor, state,
                   timed_out, distance, os_name, os_accuracy, os_family, os_gen,
                   device_type, device_vendor, last_scanned, scan_duration, raw_xml_path)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            fields,
        )
        host_id = cur.lastrowid

    for m in host.get("os_matches", []):
        conn.execute(
            """INSERT INTO os_matches (host_id, name, accuracy, os_family, os_gen, os_type, vendor)
               VALUES (?,?,?,?,?,?,?)""",
            (host_id, m.get("name"), m.get("accuracy"), m.get("os_family"),
             m.get("os_gen"), m.get("os_type"), m.get("vendor")),
        )

    for s in host.get("services", []):
        cur = conn.execute(
            """INSERT INTO services (host_id, port, protocol, state, service_name,
                   product, version, extrainfo, tunnel, cpe)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (host_id, s.get("port"), s.get("protocol"), s.get("state"),
             s.get("service_name"), s.get("product"), s.get("version"),
             s.get("extrainfo"), s.get("tunnel"), s.get("cpe")),
        )
        service_id = cur.lastrowid
        for script in s.get("scripts", []):
            conn.execute(
                """INSERT INTO service_scripts (service_id, script_id, output, collected_at)
                   VALUES (?, ?, ?, datetime('now'))""",
                (service_id, script.get("id"), script.get("output")),
            )

    return host_id


def log_scan(conn, started_at, finished_at, target_count, xml_path, command, status):
    conn.execute(
        """INSERT INTO scans (started_at, finished_at, target_count, xml_path, command, status)
           VALUES (?,?,?,?,?,?)""",
        (started_at, finished_at, target_count, xml_path, command, status),
    )
