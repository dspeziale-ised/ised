"""Schema e funzioni di accesso al database dell'inventario host.

Supporta due backend:
- SQLite (default, uso nativo/non containerizzato): db_path è un percorso
  file, comportamento identico a sempre.
- PostgreSQL (uso nel container Docker): db_path è una URL
  'postgresql://user:pass@host:port/dbname'. connect() ritorna in quel caso
  un oggetto PgConnection che espone la stessa interfaccia "di comodo" usata
  in tutto il progetto (conn.execute(sql, params) con placeholder '?',
  righe leggibili come dict, .lastrowid, .executescript()), così il resto
  del codice non deve sapere quale backend è in uso.
"""

import json
import os
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None


def _now():
    """Timestamp corrente in ISO 8601, usato al posto di datetime('now') /
    NOW() lato SQL — evita differenze di dialetto e funziona identico su
    colonne TEXT sia in SQLite che in PostgreSQL."""
    return datetime.now().isoformat(timespec="seconds")


def is_postgres_url(db_path):
    return isinstance(db_path, str) and db_path.startswith(("postgres://", "postgresql://"))


def resolve_db_target(default_sqlite_path):
    """Target DB da usare in uno script CLI: la variabile d'ambiente
    DATABASE_URL (postgresql://...) se impostata — così è che il container
    Docker punta al servizio Postgres, senza dover passare un --db esplicito
    ad ogni script — altrimenti il percorso file SQLite indicato di default
    (comportamento nativo di sempre)."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if url and is_postgres_url(url):
        return url
    return str(default_sqlite_path)


_INSERT_TABLE_RE = re.compile(r"^\s*INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE)
# Tabelle con colonna 'id' SERIAL: su queste, un INSERT senza già una
# RETURNING esplicita si vede aggiungere automaticamente "RETURNING id" per
# poter emulare cursor.lastrowid di sqlite3 (che Postgres non ha).
_TABLES_WITH_ID = {
    "hosts", "os_matches", "services", "scans", "host_roles",
    "service_scripts", "host_vulnerabilities", "host_attack_techniques",
    "host_status_checks",
}


def _adapt_schema_for_postgres(sql):
    return re.sub(r"\bINTEGER PRIMARY KEY AUTOINCREMENT\b", "SERIAL PRIMARY KEY", sql)


class _PgCursor:
    """Cursore compatibile con l'uso di sqlite3.Cursor in questo progetto:
    placeholder '?' tradotti in '%s', righe come dict, .lastrowid emulato
    via RETURNING id automatico sugli INSERT nelle tabelle con quella
    colonna."""

    def __init__(self, raw_cursor):
        self._cursor = raw_cursor
        self.lastrowid = None

    @staticmethod
    def _translate(sql):
        return sql.replace("?", "%s")

    def execute(self, sql, params=()):
        pg_sql = self._translate(sql)
        stripped = pg_sql.strip()
        match = _INSERT_TABLE_RE.match(stripped)
        auto_returning = False
        if match and match.group(1).lower() in _TABLES_WITH_ID and "RETURNING" not in stripped.upper():
            pg_sql = stripped.rstrip(";") + " RETURNING id"
            auto_returning = True
        self._cursor.execute(pg_sql, params)
        if auto_returning:
            row = self._cursor.fetchone()
            self.lastrowid = row["id"] if row else None
        return self

    def executemany(self, sql, seq_of_params):
        self._cursor.executemany(self._translate(sql), seq_of_params)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(r) for r in self._cursor.fetchall()]

    def __iter__(self):
        return (dict(r) for r in self._cursor)

    @property
    def rowcount(self):
        return self._cursor.rowcount


class PgConnection:
    """Wrapper minimale su una connessione psycopg2 per esporre la stessa
    interfaccia "di comodo" usata ovunque nel progetto su sqlite3.Connection
    (conn.execute(...) diretto, righe come dict, .executescript, ecc.)."""

    def __init__(self, raw_conn):
        self._conn = raw_conn

    def cursor(self):
        raw_cursor = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return _PgCursor(raw_cursor)

    def execute(self, sql, params=()):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def executescript(self, sql):
        with self._conn.cursor() as cur:
            cur.execute(_adapt_schema_for_postgres(sql))
        self._conn.commit()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


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

-- Storico raggiungibilità host: un check periodico (nmap -sn via
-- host_monitor.py) registra una riga solo al CAMBIO di stato o dopo un
-- "battito" periodico (default ogni ora anche senza cambi), per limitare
-- la crescita della tabella pur mantenendo uno storico utile.
CREATE TABLE IF NOT EXISTS host_status_checks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status     TEXT NOT NULL,   -- 'up' oppure 'down'
    checked_at TEXT NOT NULL
);

-- Template di scansione nmap personalizzata (Inventario -> Scansione nmap):
-- stato COMPLETO di ogni campo del form (fields_json), salvato con un nome,
-- per ripristinare esattamente la stessa configurazione senza doverla
-- ricostruire opzione per opzione ogni volta. target/args sono solo un
-- riepilogo leggibile (mostrato nella lista template), il ripristino del
-- form lato client usa fields_json. Nel database (non in un file JSON in
-- instance/) perché sopravviva ai rebuild del container Docker, che non
-- hanno un volume su instance/ a differenza del database Postgres.
CREATE TABLE IF NOT EXISTS nmap_scan_templates (
    name        TEXT PRIMARY KEY,
    target      TEXT,
    args        TEXT,
    fields_json TEXT NOT NULL,
    saved_at    TEXT
);

-- Traffico (pacchetti/byte inviati e ricevuti) generato dalle scansioni
-- nmap dell'app, una riga per invocazione nmap completata con successo
-- (parsing di "Raw packets sent: N (xKB) | Rcvd: M (yKB)", stampato da nmap
-- solo con -v). 'source' indica lo script che l'ha generato (scan_pipeline/
-- discovery/monitor), utile per un'eventuale ripartizione futura. Righe
-- individuali (non un unico contatore cumulativo) per poter mostrare un
-- grafico dell'andamento nel tempo, non solo un totale. 'duration_seconds'
-- (tempo reale della chiamata nmap, misurato dal chiamante) è necessario
-- per il grafico "al secondo": senza saperla, l'intero traffico di una
-- scansione lenta (T0-T2/--max-rate basso, che può durare minuti/ore)
-- finirebbe attribuito all'istante in cui la scansione termina, mostrando
-- un picco istantaneo invece del tasso basso e diffuso che rappresenta
-- davvero (vedi traffic_summary). 'connections_out'/'connections_in'
-- (vedi nmap_conn_count.py) sono un conteggio APPROSSIMATO PER DIFETTO
-- delle connessioni TCP/UDP distinte osservate via polling psutil sul
-- processo nmap mentre gira: un poll ogni ~100ms non cattura connessioni
-- più brevi dell'intervallo, tipico delle scansioni SYN.
CREATE TABLE IF NOT EXISTS traffic_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at      TEXT NOT NULL,
    source           TEXT,
    packets_sent     INTEGER DEFAULT 0,
    bytes_sent       INTEGER DEFAULT 0,
    packets_rcvd     INTEGER DEFAULT 0,
    bytes_rcvd       INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0,
    connections_out  INTEGER DEFAULT 0,
    connections_in   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_traffic_log_recorded_at ON traffic_log(recorded_at);

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
CREATE INDEX IF NOT EXISTS idx_host_status_checks_host ON host_status_checks(host_id, checked_at);
"""


def connect(db_path):
    """Apre una connessione al DB. Se db_path è una URL 'postgresql://...'
    si connette a PostgreSQL (uso nel container Docker); altrimenti è
    trattato come percorso file SQLite (uso nativo, come sempre) — crea
    anche la cartella contenente il file (es. instance/) se non esiste."""
    if is_postgres_url(db_path):
        if psycopg2 is None:
            raise RuntimeError(
                "psycopg2 non installato: necessario per usare un DATABASE_URL postgresql://... "
                "('pip install psycopg2-binary')."
            )
        raw_conn = psycopg2.connect(db_path)
        return PgConnection(raw_conn)

    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _get_columns(conn, table):
    """Nomi delle colonne di una tabella, indipendentemente dal backend."""
    if isinstance(conn, PgConnection):
        rows = conn.execute(
            "SELECT column_name AS name FROM information_schema.columns WHERE table_name = ?",
            (table,),
        ).fetchall()
    else:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row["name"] for row in rows}


def init_db(conn):
    conn.executescript(SCHEMA)
    conn.commit()
    ensure_ai_columns(conn)
    ensure_service_columns(conn)
    ensure_fingerprint_columns(conn)
    ensure_traffic_columns(conn)


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

# reason ('echo-reply'/'syn-ack'/...) e ttl della risposta di stato nmap:
# usati come euristica di riserva in classify.py (vedi guess_ttl_baseline)
# quando OS match/porte non bastano a determinare il tipo dispositivo.
FINGERPRINT_COLUMNS = {
    "status_reason": "TEXT",
    "ttl": "INTEGER",
}


TRAFFIC_COLUMNS = {
    "duration_seconds": "REAL DEFAULT 0",
    "connections_out": "INTEGER DEFAULT 0",
    "connections_in": "INTEGER DEFAULT 0",
}


def ensure_traffic_columns(conn):
    """Aggiunge le colonne di TRAFFIC_COLUMNS su traffic_log se non esistono
    già (migrazione additiva e idempotente, sicura su un DB già popolato)."""
    existing = _get_columns(conn, "traffic_log")
    added = False
    for col, col_type in TRAFFIC_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE traffic_log ADD COLUMN {col} {col_type}")
            added = True
    if added:
        conn.commit()


def ensure_service_columns(conn):
    """Aggiunge le colonne extra su services (es. cpe) se non esistono già."""
    conn.executescript(SCHEMA)  # crea le tabelle nuove (host_roles, cve_cache, ecc.) se il DB è preesistente
    existing = _get_columns(conn, "services")
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
    existing = _get_columns(conn, "hosts")
    added = False
    for col, col_type in AI_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE hosts ADD COLUMN {col} {col_type}")
            added = True
    if added:
        conn.commit()


def ensure_fingerprint_columns(conn):
    """Aggiunge status_reason/ttl su hosts se non esistono già (migrazione
    additiva e idempotente, sicura su un DB già popolato)."""
    existing = _get_columns(conn, "hosts")
    added = False
    for col, col_type in FINGERPRINT_COLUMNS.items():
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
            "INSERT INTO host_roles (host_id, role, source, created_at) VALUES (?, ?, ?, ?)",
            (host_id, role, source, _now()),
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
        """INSERT INTO cve_cache (cpe, cve_json, fetched_at) VALUES (?, ?, ?)
           ON CONFLICT(cpe) DO UPDATE SET cve_json = excluded.cve_json, fetched_at = excluded.fetched_at""",
        (cpe, json.dumps(cve_list), _now()),
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
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, port, cpe, cve.get("id"), cve.get("cvss"), cve.get("url"), source, _now()),
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
               VALUES (?, ?, ?, ?, ?)""",
            (host_id, technique_id, t.get("reason", ""), source, _now()),
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


def ensure_monitor_tables(conn):
    """Crea la tabella host_status_checks se mancante (DB preesistente)."""
    conn.executescript(SCHEMA)
    conn.commit()


def get_latest_status_check(conn, host_id):
    row = conn.execute(
        "SELECT status, checked_at FROM host_status_checks WHERE host_id = ? ORDER BY id DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    return dict(row) if row else None


def record_host_status_if_needed(conn, host_id, status, checked_at, heartbeat_minutes=60):
    """Inserisce una riga di storico solo al CAMBIO di stato rispetto
    all'ultimo check noto, oppure se è passato più di heartbeat_minutes
    dall'ultimo check (un "battito" periodico anche senza cambi, per poter
    calcolare l'uptime% anche su host sempre nello stesso stato). Limita la
    crescita della tabella pur mantenendo uno storico utile. Ritorna True se
    ha scritto una nuova riga."""
    last = get_latest_status_check(conn, host_id)
    if last and last["status"] == status:
        try:
            last_dt = datetime.fromisoformat(last["checked_at"])
            now_dt = datetime.fromisoformat(checked_at)
            elapsed_minutes = (now_dt - last_dt).total_seconds() / 60
        except ValueError:
            elapsed_minutes = heartbeat_minutes + 1
        if elapsed_minutes < heartbeat_minutes:
            return False

    conn.execute(
        "INSERT INTO host_status_checks (host_id, status, checked_at) VALUES (?, ?, ?)",
        (host_id, status, checked_at),
    )
    conn.commit()
    return True


def get_host_status_history(conn, host_id, limit=200):
    rows = conn.execute(
        "SELECT status, checked_at FROM host_status_checks WHERE host_id = ? ORDER BY id DESC LIMIT ?",
        (host_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def host_uptime_percent(conn, host_id, since_hours=24):
    """Percentuale di tempo 'up' nella finestra [ora - since_hours, ora],
    ricostruita dagli intervalli fra check consecutivi (dato che si registra
    solo al cambio di stato + battito periodico, non ogni singolo check).
    Ritorna None se non c'è storico sufficiente per stimarla."""
    since_dt = datetime.now() - timedelta(hours=since_hours)
    now_dt = datetime.now()
    rows = conn.execute(
        "SELECT status, checked_at FROM host_status_checks WHERE host_id = ? ORDER BY id ASC",
        (host_id,),
    ).fetchall()
    if not rows:
        return None

    total_seconds = 0.0
    up_seconds = 0.0
    for i, row in enumerate(rows):
        try:
            start = datetime.fromisoformat(row["checked_at"])
        except ValueError:
            continue
        end = None
        if i + 1 < len(rows):
            try:
                end = datetime.fromisoformat(rows[i + 1]["checked_at"])
            except ValueError:
                end = None
        end = end or now_dt
        start = max(start, since_dt)
        end = min(end, now_dt)
        if end <= start:
            continue
        duration = (end - start).total_seconds()
        total_seconds += duration
        if row["status"] == "up":
            up_seconds += duration

    if total_seconds <= 0:
        return None
    return round(up_seconds / total_seconds * 100, 1)


def monitor_summary(conn):
    """Stato corrente aggregato su tutti gli host (ultimo check noto per
    ciascuno): {'total_hosts', 'up', 'down', 'never_checked'}."""
    rows = conn.execute(
        """SELECT hsc.status
           FROM host_status_checks hsc
           JOIN (SELECT host_id, MAX(id) max_id FROM host_status_checks GROUP BY host_id) latest
             ON latest.host_id = hsc.host_id AND latest.max_id = hsc.id"""
    ).fetchall()
    total_hosts = conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
    up = sum(1 for r in rows if r["status"] == "up")
    down = sum(1 for r in rows if r["status"] == "down")
    return {
        "total_hosts": total_hosts,
        "up": up,
        "down": down,
        "never_checked": total_hosts - len(rows),
    }


def hosts_hourly_status(conn, date_str):
    """Stato di ogni host ora per ora per il giorno 'date_str' (YYYY-MM-DD):
    per ciascuna delle 24 ore, l'ultimo check noto con checked_at entro la
    fine di quell'ora (stato "riportato avanti" dall'ultimo cambio noto,
    dato che lo storico registra solo su cambio + battito periodico). None
    se non c'è ancora nessun check noto a quel punto. Ritorna
    {host_id: [stato_o_None x24]}."""
    day_start = datetime.fromisoformat(date_str)
    day_end = day_start + timedelta(days=1)

    rows = conn.execute(
        "SELECT host_id, status, checked_at FROM host_status_checks "
        "WHERE checked_at < ? ORDER BY host_id, checked_at",
        (day_end.isoformat(),),
    ).fetchall()

    by_host = {}
    for r in rows:
        by_host.setdefault(r["host_id"], []).append((r["checked_at"], r["status"]))

    result = {}
    for host_id, checks in by_host.items():
        hourly = []
        idx = 0
        current_status = None
        total = len(checks)
        for hour in range(24):
            hour_end_iso = (day_start + timedelta(hours=hour + 1)).isoformat()
            while idx < total and checks[idx][0] < hour_end_iso:
                current_status = checks[idx][1]
                idx += 1
            hourly.append(current_status)
        result[host_id] = hourly

    return result


def upsert_host(conn, host):
    """Inserisce/aggiorna un host e sostituisce le sue righe os_matches/services."""
    cur = conn.execute("SELECT id FROM hosts WHERE ip = ?", (host["ip"],))
    row = cur.fetchone()

    fields = (
        host["ip"], host.get("hostname"), host.get("mac_address"),
        host.get("mac_vendor"), host.get("state"), host.get("status_reason"), host.get("ttl"),
        int(host.get("timed_out", False)),
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
                   status_reason=?, ttl=?,
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
                   status_reason, ttl,
                   timed_out, distance, os_name, os_accuracy, os_family, os_gen,
                   device_type, device_vendor, last_scanned, scan_duration, raw_xml_path)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                   VALUES (?, ?, ?, ?)""",
                (service_id, script.get("id"), script.get("output"), _now()),
            )

    return host_id


def log_scan(conn, started_at, finished_at, target_count, xml_path, command, status):
    conn.execute(
        """INSERT INTO scans (started_at, finished_at, target_count, xml_path, command, status)
           VALUES (?,?,?,?,?,?)""",
        (started_at, finished_at, target_count, xml_path, command, status),
    )


def list_scan_templates(conn):
    """Ritorna i template di scansione nmap salvati, ordinati per nome:
    [{name, target, args, fields, saved_at}, ...]."""
    rows = conn.execute(
        "SELECT name, target, args, fields_json, saved_at FROM nmap_scan_templates ORDER BY name"
    ).fetchall()
    return [
        {
            "name": r["name"],
            "target": r["target"] or "",
            "args": r["args"] or "",
            "fields": json.loads(r["fields_json"]) if r["fields_json"] else {},
            "saved_at": r["saved_at"],
        }
        for r in rows
    ]


def save_scan_template(conn, name, target, args, fields):
    """Salva (o sovrascrive, se esiste già un template con lo stesso nome)
    un template di scansione nmap personalizzata."""
    conn.execute(
        """INSERT INTO nmap_scan_templates (name, target, args, fields_json, saved_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET
               target = excluded.target, args = excluded.args,
               fields_json = excluded.fields_json, saved_at = excluded.saved_at""",
        (name, (target or "").strip(), args or "", json.dumps(fields or {}), _now()),
    )
    conn.commit()


def delete_scan_template(conn, name):
    """Ritorna True se un template con quel nome esisteva ed è stato rimosso."""
    cur = conn.execute("DELETE FROM nmap_scan_templates WHERE name = ?", (name,))
    conn.commit()
    return (cur.rowcount or 0) > 0


def log_traffic(conn, source, packets_sent, bytes_sent, packets_rcvd, bytes_rcvd, duration_seconds=0,
                 connections_out=0, connections_in=0):
    """Registra il traffico (pacchetti/byte/connessioni) di UNA invocazione
    nmap completata. Una riga per invocazione (non un contatore cumulativo
    unico) per poter ricostruire un andamento nel tempo, vedi
    traffic_summary(). 'duration_seconds' (tempo reale della chiamata,
    misurato dal chiamante) è essenziale per un grafico "al secondo"
    corretto: senza di essa l'intero traffico risulterebbe concentrato
    nell'istante in cui la scansione termina invece che diffuso sulla sua
    reale durata. 'connections_out'/'connections_in' (vedi
    nmap_conn_count.py) sono un conteggio approssimato per difetto via
    polling psutil, non un valore esatto."""
    conn.execute(
        """INSERT INTO traffic_log
               (recorded_at, source, packets_sent, bytes_sent, packets_rcvd, bytes_rcvd,
                duration_seconds, connections_out, connections_in)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (_now(), source, packets_sent, bytes_sent, packets_rcvd, bytes_rcvd,
         duration_seconds, connections_out, connections_in),
    )
    conn.commit()


def traffic_summary(conn, since_minutes=60, bucket_minutes=2):
    """Ritorna {'total': {...}, 'series': [{'t', 'packets_sent', 'bytes_sent',
    'packets_rcvd', 'bytes_rcvd'}, ...], 'bucket_minutes'}: 'total' è il
    cumulativo su tutto lo storico (per il badge riepilogativo); 'series'
    copre gli ultimi since_minutes minuti in bucket continui da
    bucket_minutes minuti (bucket senza traffico inclusi, a zero — il
    grafico deve mostrare una linea temporale continua, non solo i punti
    con dati).

    Il traffico di OGNI riga viene distribuito PROPORZIONALMENTE su tutti i
    bucket che il suo intervallo [recorded_at - duration_seconds,
    recorded_at] attraversa, pesato per quanti secondi di sovrapposizione
    ricadono in ciascun bucket — non accumulato per intero nel bucket
    dell'istante finale. Senza questo, una scansione lenta/a basso effort
    (T0-T2, --max-rate basso: può durare minuti o ore) apparirebbe come un
    picco istantaneo invece del tasso basso e diffuso che rappresenta
    davvero, il difetto opposto di quello che l'effort di rete dovrebbe
    comunicare.

    Il binning è fatto in Python (non con funzioni SQL di troncamento data,
    diverse fra SQLite e Postgres), coerente con come il resto del progetto
    evita differenze di dialetto sulle date."""
    total_row = conn.execute(
        "SELECT COALESCE(SUM(packets_sent),0) ps, COALESCE(SUM(bytes_sent),0) bs, "
        "COALESCE(SUM(packets_rcvd),0) pr, COALESCE(SUM(bytes_rcvd),0) br, "
        "COALESCE(SUM(connections_out),0) co, COALESCE(SUM(connections_in),0) ci FROM traffic_log"
    ).fetchone()
    total = {
        "packets_sent": total_row["ps"], "bytes_sent": total_row["bs"],
        "packets_rcvd": total_row["pr"], "bytes_rcvd": total_row["br"],
        "connections_out": total_row["co"], "connections_in": total_row["ci"],
    }

    now = datetime.now()
    window_start = now - timedelta(minutes=since_minutes)
    floored_minute = window_start.minute - (window_start.minute % bucket_minutes)
    first_bucket_start = window_start.replace(minute=floored_minute, second=0, microsecond=0)

    # Bucket pre-generati (a zero) per l'intera finestra, cosi il grafico ha
    # una linea temporale continua invece di "buchi" nei periodi senza
    # traffico registrato.
    buckets = {}
    cursor = first_bucket_start
    while cursor <= now:
        key = cursor.isoformat(timespec="minutes")
        buckets[key] = {
            "t": key, "packets_sent": 0.0, "bytes_sent": 0.0, "packets_rcvd": 0.0, "bytes_rcvd": 0.0,
            "connections_out": 0.0, "connections_in": 0.0,
        }
        cursor += timedelta(minutes=bucket_minutes)

    # Include anche righe iniziate PRIMA della finestra ma la cui durata si
    # protrae al suo interno: un margine di 6 ore copre ampiamente anche le
    # scansioni T0/T1 più lente viste in pratica in questo progetto.
    fetch_since = (window_start - timedelta(hours=6)).isoformat(timespec="seconds")
    rows = conn.execute(
        "SELECT recorded_at, packets_sent, bytes_sent, packets_rcvd, bytes_rcvd, duration_seconds, "
        "connections_out, connections_in "
        "FROM traffic_log WHERE recorded_at >= ? ORDER BY recorded_at",
        (fetch_since,),
    ).fetchall()

    for r in rows:
        try:
            end_ts = datetime.fromisoformat(r["recorded_at"])
        except ValueError:
            continue
        duration = max(r["duration_seconds"] or 0, 1)
        start_ts = end_ts - timedelta(seconds=duration)
        if end_ts < first_bucket_start:
            continue  # finita prima dell'inizio della finestra, nessuna sovrapposizione

        cursor = first_bucket_start
        while cursor <= now:
            bucket_end = cursor + timedelta(minutes=bucket_minutes)
            overlap = (min(end_ts, bucket_end) - max(start_ts, cursor)).total_seconds()
            if overlap > 0:
                frac = overlap / duration
                b = buckets[cursor.isoformat(timespec="minutes")]
                b["packets_sent"] += (r["packets_sent"] or 0) * frac
                b["bytes_sent"] += (r["bytes_sent"] or 0) * frac
                b["packets_rcvd"] += (r["packets_rcvd"] or 0) * frac
                b["bytes_rcvd"] += (r["bytes_rcvd"] or 0) * frac
                b["connections_out"] += (r["connections_out"] or 0) * frac
                b["connections_in"] += (r["connections_in"] or 0) * frac
            cursor += timedelta(minutes=bucket_minutes)

    series = []
    for k in sorted(buckets):
        b = buckets[k]
        series.append({
            "t": b["t"],
            "packets_sent": round(b["packets_sent"], 2),
            "bytes_sent": round(b["bytes_sent"], 2),
            "packets_rcvd": round(b["packets_rcvd"], 2),
            "bytes_rcvd": round(b["bytes_rcvd"], 2),
            "connections_out": round(b["connections_out"], 2),
            "connections_in": round(b["connections_in"], 2),
        })
    return {"total": total, "series": series, "bucket_minutes": bucket_minutes}
