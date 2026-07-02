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

CREATE INDEX IF NOT EXISTS idx_os_matches_host ON os_matches(host_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_hosts_device_type ON hosts(device_type);
CREATE INDEX IF NOT EXISTS idx_host_roles_host ON host_roles(host_id);
CREATE INDEX IF NOT EXISTS idx_service_scripts_service ON service_scripts(service_id);
CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_host ON host_vulnerabilities(host_id);
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
