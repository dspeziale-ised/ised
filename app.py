"""Applicazione Flask per navigare l'inventario di rete raccolto da scan_and_store.py."""

import datetime
import hashlib
import math
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from flask import Flask, abort, g, jsonify, render_template, request, url_for

import cve_lookup
import scanner_db

BASE_DIR = Path(__file__).parent
DB_PATH = Path(os.environ.get("INVENTORY_DB", BASE_DIR / "instance" / "inventory.db"))
SCAN_INPUT_FILE = Path(os.environ.get("SCAN_INPUT", BASE_DIR / "up_ips.txt"))

app = Flask(__name__)

if DB_PATH.exists():
    _startup_conn = scanner_db.connect(str(DB_PATH))
    scanner_db.ensure_ai_columns(_startup_conn)
    scanner_db.ensure_service_columns(_startup_conn)
    scanner_db.normalize_device_types(_startup_conn)
    _startup_conn.close()

DEVICE_BADGE = {
    "router": "primary",
    "switch": "info",
    "printer": "secondary",
    "camera/dvr": "dark",
    "storage-misc": "warning",
    "hypervisor": "success",
    "firewall": "danger",
    "phone": "info",
    "WAP": "primary",
    "general purpose": "light",
    "general purpose (windows-like)": "light",
    "unknown": "secondary",
}


@app.template_filter("badge_class")
def badge_class(device_type):
    return DEVICE_BADGE.get(device_type, "secondary")


DEVICE_COLOR = {
    "router": "#4e79a7",
    "switch": "#76b7b2",
    "firewall": "#e15759",
    "WAP": "#59a14f",
    "printer": "#9c755f",
    "camera/dvr": "#af7aa1",
    "storage-misc": "#f28e2b",
    "hypervisor": "#b6992d",
    "phone": "#ff9da7",
    "load balancer": "#ffbe7d",
    "proxy server": "#d4a6c8",
    "general purpose": "#6b6ecf",
    "general purpose (windows-like)": "#17a2b8",
    "unknown": "#c9ccd1",
}
DEFAULT_DEVICE_COLOR = "#c9ccd1"


def color_for_device_type(name):
    """Colore per il tipo dispositivo: valore curato se noto, altrimenti un
    colore HSL deterministico (stesso tipo -> sempre stesso colore) così anche
    tipi non previsti restano ben distinguibili invece di un grigio anonimo."""
    if name in DEVICE_COLOR:
        return DEVICE_COLOR[name]
    if not name or name == "unknown":
        return DEFAULT_DEVICE_COLOR
    h = int(hashlib.md5(name.encode("utf-8")).hexdigest(), 16) % 360
    return f"hsl({h}, 65%, 48%)"


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def is_nmap_running():
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq nmap.exe"],
            capture_output=True, text=True, timeout=5,
        )
        return "nmap.exe" in out.stdout.lower()
    except Exception:
        return False


def is_scan_and_store_running():
    """True solo se il processo scan_and_store.py di QUESTO progetto è
    attivo — a differenza di is_nmap_running(), non viene ingannato da un
    nmap.exe indipendente (es. una ping-sweep lanciata a mano dall'utente)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"Name LIKE '%python%'\" "
             "| Select-Object -ExpandProperty CommandLine"],
            capture_output=True, text=True, timeout=8,
        )
        return "scan_and_store.py" in out.stdout
    except Exception:
        return False


def is_pid_alive(pid):
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True, text=True, timeout=5,
        )
        return str(pid) in out.stdout
    except Exception:
        return False


# Job in background avviabili dalla UI (niente più comandi a mano da terminale):
# - rescan: estrae gli IP up da data/ised.xml e scansiona quelli nuovi (nmap)
# - classify: classifica il tipo di dispositivo via LLM (Groq/Gemini/Ollama)
# - vuln: cerca CVE per le CPE rilevate (nmap --script vulners, con cache)
JOBS = {
    "rescan": {
        "cmd": [sys.executable, str(BASE_DIR / "run_rescan.py")],
        "lock_file": BASE_DIR / "rescan.lock",
        "log_file": BASE_DIR / "rescan_log.txt",
        "label": "Aggiornamento scansione",
        "uses_nmap": True,  # copre anche scansioni avviate fuori da questo meccanismo
    },
    "classify": {
        "cmd": [sys.executable, str(BASE_DIR / "classify_devices.py")],
        "lock_file": BASE_DIR / "classify.lock",
        "log_file": BASE_DIR / "classify_log.txt",
        "label": "Classificazione AI",
        "uses_nmap": False,
    },
    "vuln": {
        "cmd": [sys.executable, str(BASE_DIR / "vuln_scan.py")],
        "lock_file": BASE_DIR / "vuln.lock",
        "log_file": BASE_DIR / "vuln_log.txt",
        "label": "Scansione vulnerabilità",
        # False: usa sempre il proprio lock file (mai avviato fuori da questo
        # meccanismo), quindi il fallback su nmap.exe darebbe solo falsi
        # positivi quando è "rescan" (altro job) a usare nmap in quel momento.
        "uses_nmap": False,
    },
}
_job_processes = {}


def is_job_running(name):
    """True se il job è già attivo. Verificato tramite lock file con PID
    (sopravvive ai riavvii del processo Flask, es. per l'auto-reload in
    debug mode) e, per il job 'rescan', anche tramite il processo
    scan_and_store.py (copre scansioni avviate fuori da questo meccanismo,
    es. da riga di comando) — non un generico nmap.exe, per non confondersi
    con scansioni nmap indipendenti (es. una ping-sweep lanciata a mano)."""
    job = JOBS[name]
    proc = _job_processes.get(name)
    if proc is not None and proc.poll() is None:
        return True

    lock_file = job["lock_file"]
    if lock_file.exists():
        try:
            pid = int(lock_file.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            pid = None
        if pid and is_pid_alive(pid):
            return True
        try:
            lock_file.unlink()
        except OSError:
            pass

    return is_scan_and_store_running() if job["uses_nmap"] else False


def start_job(name, extra_args=None):
    """Lancia il job in background. Ritorna (ok, motivo se non avviato)."""
    if is_job_running(name):
        return False, f"{JOBS[name]['label']} già in corso."

    job = JOBS[name]
    log = open(job["log_file"], "a", encoding="utf-8")
    proc = subprocess.Popen(
        job["cmd"] + (extra_args or []),
        cwd=BASE_DIR, stdout=log, stderr=subprocess.STDOUT,
    )
    _job_processes[name] = proc
    return True, None


def tail_log(log_file, max_lines=200):
    if not Path(log_file).exists():
        return ""
    lines = Path(log_file).read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


def count_input_ips():
    if not SCAN_INPUT_FILE.exists():
        return 0
    return sum(
        1 for line in SCAN_INPUT_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def get_scan_progress():
    db = get_db()
    total_ips = count_input_ips()
    hosts_recorded = db.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
    batches_done = db.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
    last_batch = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    avg_row = db.execute(
        "SELECT AVG((julianday(finished_at) - julianday(started_at)) * 86400.0) avg_s, "
        "AVG(target_count) avg_batch FROM scans"
    ).fetchone()
    avg_duration = avg_row["avg_s"]
    avg_batch_size = avg_row["avg_batch"] or 32

    batches_expected = math.ceil(total_ips / avg_batch_size) if avg_batch_size and total_ips else 0
    percent = round(min(hosts_recorded, total_ips) / total_ips * 100, 1) if total_ips else 0.0
    running = is_scan_and_store_running()

    eta_seconds = None
    if running and avg_duration and batches_expected > batches_done:
        eta_seconds = avg_duration * (batches_expected - batches_done)

    if running:
        status = "running"
    elif total_ips and hosts_recorded >= total_ips:
        status = "completed"
    elif batches_done > 0:
        status = "paused"
    else:
        status = "idle"

    return {
        "status": status,
        "running": running,
        "total_ips": total_ips,
        "hosts_recorded": hosts_recorded,
        "batches_done": batches_done,
        "batches_expected": batches_expected,
        "percent": percent,
        "eta_seconds": eta_seconds,
        "last_batch_finished_at": last_batch["finished_at"] if last_batch else None,
    }


@app.route("/api/scan-status")
def scan_status_api():
    return jsonify(get_scan_progress())


@app.route("/operations")
def operations():
    data_dir = BASE_DIR / "data"
    xml_files = []
    if data_dir.is_dir():
        for p in sorted(data_dir.glob("*.xml")):
            xml_files.append({
                "name": p.name,
                "mtime": datetime.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
                "size_mb": round(p.stat().st_size / (1024 * 1024), 1),
            })
    return render_template(
        "operations.html",
        xml_files=xml_files,
        jobs_running={name: is_job_running(name) for name in JOBS},
    )


@app.route("/jobs/<name>/start", methods=["POST"])
def job_start(name):
    if name not in JOBS:
        return jsonify({"started": False, "reason": "Job sconosciuto."}), 404
    extra_args = ["--force"] if request.values.get("force") == "1" else None
    ok, reason = start_job(name, extra_args=extra_args)
    return jsonify({"started": ok, "reason": reason})


@app.route("/api/jobs/<name>/status")
def job_status(name):
    if name not in JOBS:
        return jsonify({"error": "Job sconosciuto."}), 404
    return jsonify({
        "running": is_job_running(name),
        "log": tail_log(JOBS[name]["log_file"]),
    })


def dt_params():
    """Estrae i parametri standard di una richiesta DataTables server-side."""
    args = request.values
    draw = args.get("draw", type=int, default=1)
    start = args.get("start", type=int, default=0)
    length = args.get("length", type=int, default=25)
    if length is None or length < 0:
        length = 25
    search_value = (args.get("search[value]") or "").strip()

    orders = []
    i = 0
    while True:
        col = args.get(f"order[{i}][column]", type=int)
        if col is None:
            break
        direction = args.get(f"order[{i}][dir]", default="asc")
        orders.append((col, "DESC" if direction == "desc" else "ASC"))
        i += 1

    return draw, start, length, search_value, orders


def dt_order_sql(orders, order_map, default):
    if not orders:
        return default
    col_idx, direction = orders[0]
    col_name = order_map.get(col_idx)
    if not col_name:
        return default
    return f"{col_name} {direction}"


@app.route("/")
def dashboard():
    db = get_db()
    total_hosts = db.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
    scans_total = db.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
    total_open_services = db.execute(
        "SELECT COUNT(*) c FROM services WHERE state='open'"
    ).fetchone()["c"]
    by_device = db.execute(
        "SELECT COALESCE(device_type,'unknown') device_type, COUNT(*) c "
        "FROM hosts GROUP BY device_type ORDER BY c DESC"
    ).fetchall()
    by_os_family = db.execute(
        "SELECT COALESCE(os_family,'sconosciuto') os_family, COUNT(*) c "
        "FROM hosts WHERE os_family IS NOT NULL GROUP BY os_family ORDER BY c DESC LIMIT 10"
    ).fetchall()
    top_services = db.execute(
        "SELECT port, protocol, COALESCE(service_name,'unknown') service_name, "
        "COUNT(DISTINCT host_id) hosts_count "
        "FROM services WHERE state='open' GROUP BY port, protocol, service_name "
        "ORDER BY hosts_count DESC LIMIT 10"
    ).fetchall()
    last_scan = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()

    return render_template(
        "dashboard.html",
        total_hosts=total_hosts,
        scans_total=scans_total,
        total_open_services=total_open_services,
        by_device=by_device,
        by_os_family=by_os_family,
        top_services=top_services,
        last_scan=last_scan,
        scan_progress=get_scan_progress(),
    )


@app.route("/hosts")
def hosts_list():
    db = get_db()
    device_types = db.execute(
        "SELECT DISTINCT COALESCE(device_type,'unknown') d FROM hosts ORDER BY d"
    ).fetchall()
    os_families = db.execute(
        "SELECT DISTINCT os_family d FROM hosts WHERE os_family IS NOT NULL ORDER BY d"
    ).fetchall()
    return render_template("hosts.html", device_types=device_types, os_families=os_families)


HOSTS_ORDER_MAP = {
    0: "h.ip", 1: "device_type", 2: "h.ai_provider", 3: "os_family",
    4: "h.os_accuracy", 5: "h.mac_address", 6: "open_ports", 7: "h.last_scanned",
}


@app.route("/api/hosts")
def api_hosts():
    db = get_db()
    draw, start, length, search_value, orders = dt_params()
    device_type = request.values.get("device_type", "").strip()
    os_family = request.values.get("os_family", "").strip()

    fixed_where = []
    fixed_params = []
    if device_type:
        fixed_where.append("COALESCE(h.device_type,'unknown') = ?")
        fixed_params.append(device_type)
    if os_family:
        fixed_where.append("h.os_family = ?")
        fixed_params.append(os_family)

    total_sql = "SELECT COUNT(*) c FROM hosts h" + (
        " WHERE " + " AND ".join(fixed_where) if fixed_where else ""
    )
    records_total = db.execute(total_sql, fixed_params).fetchone()["c"]

    where = list(fixed_where)
    params = list(fixed_params)
    if search_value:
        where.append(
            "(h.ip LIKE ? OR h.hostname LIKE ? OR COALESCE(h.device_type,'unknown') LIKE ? "
            "OR h.os_family LIKE ? OR h.os_name LIKE ? OR h.mac_address LIKE ?)"
        )
        like = f"%{search_value}%"
        params.extend([like] * 6)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    filtered_sql = f"SELECT COUNT(*) c FROM hosts h {where_sql}"
    records_filtered = db.execute(filtered_sql, params).fetchone()["c"]

    order_sql = dt_order_sql(orders, HOSTS_ORDER_MAP, "h.ip ASC")
    query = f"""
        SELECT h.ip, h.hostname, COALESCE(h.device_type,'unknown') device_type,
               h.ai_provider, h.os_family, h.os_name, h.os_accuracy, h.mac_address, h.last_scanned,
               (SELECT COUNT(*) FROM services s WHERE s.host_id = h.id AND s.state = 'open') open_ports
        FROM hosts h
        {where_sql}
        ORDER BY {order_sql}
        LIMIT ? OFFSET ?
    """
    rows = db.execute(query, params + [length, start]).fetchall()

    data = [
        {
            "ip": r["ip"],
            "ip_url": url_for("host_detail", ip=r["ip"]),
            "hostname": r["hostname"] or "",
            "device_type": r["device_type"],
            "device_badge": badge_class(r["device_type"]),
            "ai_provider": r["ai_provider"] or "",
            "os_family": r["os_family"] or "",
            "os_name": r["os_name"] or "",
            "os_accuracy": r["os_accuracy"],
            "mac_address": r["mac_address"] or "",
            "open_ports": r["open_ports"],
            "last_scanned": r["last_scanned"] or "",
        }
        for r in rows
    ]

    return jsonify({
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": data,
    })


@app.route("/hosts/<ip>")
def host_detail(ip):
    db = get_db()
    host = db.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)).fetchone()
    if host is None:
        abort(404)
    os_matches = db.execute(
        "SELECT * FROM os_matches WHERE host_id = ? ORDER BY accuracy DESC", (host["id"],)
    ).fetchall()
    services = db.execute(
        "SELECT * FROM services WHERE host_id = ? ORDER BY port", (host["id"],)
    ).fetchall()
    roles = scanner_db.get_host_roles(db, host["id"])
    vulnerabilities = db.execute(
        "SELECT * FROM host_vulnerabilities WHERE host_id = ? ORDER BY cvss DESC NULLS LAST, cve_id",
        (host["id"],),
    ).fetchall()
    return render_template(
        "host_detail.html", host=host, os_matches=os_matches, services=services,
        device_type_options=sorted(DEVICE_COLOR.keys()), roles=roles,
        vulnerabilities=vulnerabilities,
    )


@app.route("/hosts/<ip>/device-type", methods=["POST"])
def update_device_type(ip):
    json_data = request.get_json(silent=True) or {}
    device_type = (request.form.get("device_type") or json_data.get("device_type") or "").strip().lower()
    if not device_type:
        return jsonify({"ok": False, "error": "Il tipo dispositivo non può essere vuoto."}), 400

    db = get_db()
    host = db.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
    if host is None:
        return jsonify({"ok": False, "error": "Host non trovato."}), 404

    db.execute(
        "UPDATE hosts SET device_type = ?, device_type_manual = 1 WHERE id = ?",
        (device_type, host["id"]),
    )
    db.commit()
    return jsonify({"ok": True, "device_type": device_type, "badge_class": badge_class(device_type)})


@app.route("/services")
def services_list():
    return render_template("services.html")


SERVICES_ORDER_MAP = {0: "port", 1: "protocol", 2: "service_name", 3: "hosts_count"}
SERVICES_BASE_SQL = """
    SELECT port, protocol, COALESCE(service_name,'unknown') service_name,
           COUNT(DISTINCT host_id) hosts_count
    FROM services
    WHERE state = 'open'
    GROUP BY port, protocol, service_name
"""


@app.route("/api/services")
def api_services():
    db = get_db()
    draw, start, length, search_value, orders = dt_params()

    records_total = db.execute(
        f"SELECT COUNT(*) c FROM ({SERVICES_BASE_SQL})"
    ).fetchone()["c"]

    where_sql = ""
    params = []
    if search_value:
        where_sql = "WHERE (CAST(port AS TEXT) LIKE ? OR protocol LIKE ? OR service_name LIKE ?)"
        like = f"%{search_value}%"
        params = [like, like, like]

    records_filtered = db.execute(
        f"SELECT COUNT(*) c FROM ({SERVICES_BASE_SQL}) agg {where_sql}", params
    ).fetchone()["c"]

    order_sql = dt_order_sql(orders, SERVICES_ORDER_MAP, "hosts_count DESC")
    rows = db.execute(
        f"""SELECT * FROM ({SERVICES_BASE_SQL}) agg
            {where_sql}
            ORDER BY {order_sql}
            LIMIT ? OFFSET ?""",
        params + [length, start],
    ).fetchall()

    data = [
        {
            "port": r["port"],
            "protocol": r["protocol"],
            "service_name": r["service_name"],
            "hosts_count": r["hosts_count"],
            "hosts_url": url_for(
                "service_hosts", port=r["port"], protocol=r["protocol"],
                service_name=r["service_name"],
            ),
        }
        for r in rows
    ]

    return jsonify({
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": data,
    })


@app.route("/services/hosts")
def service_hosts():
    port = request.args.get("port", type=int)
    protocol = request.args.get("protocol", default="tcp")
    service_name = request.args.get("service_name", default="unknown")
    return render_template(
        "service_hosts.html", port=port, protocol=protocol, service_name=service_name
    )


SERVICE_HOSTS_ORDER_MAP = {
    0: "h.ip", 1: "h.device_type", 2: "h.os_name",
    3: "s.product", 4: "s.version",
}


@app.route("/api/service-hosts")
def api_service_hosts():
    db = get_db()
    draw, start, length, search_value, orders = dt_params()
    port = request.values.get("port", type=int)
    protocol = request.values.get("protocol", default="tcp")
    service_name = request.values.get("service_name", default="unknown")

    fixed_where = (
        "s.port = ? AND s.protocol = ? AND COALESCE(s.service_name,'unknown') = ? "
        "AND s.state = 'open'"
    )
    fixed_params = [port, protocol, service_name]

    records_total = db.execute(
        f"""SELECT COUNT(*) c FROM services s
            JOIN hosts h ON h.id = s.host_id WHERE {fixed_where}""",
        fixed_params,
    ).fetchone()["c"]

    where = [fixed_where]
    params = list(fixed_params)
    if search_value:
        where.append(
            "(h.ip LIKE ? OR h.hostname LIKE ? OR COALESCE(h.device_type,'unknown') LIKE ? "
            "OR h.os_name LIKE ? OR s.product LIKE ? OR s.version LIKE ?)"
        )
        like = f"%{search_value}%"
        params.extend([like] * 6)

    where_sql = "WHERE " + " AND ".join(where)
    records_filtered = db.execute(
        f"""SELECT COUNT(*) c FROM services s
            JOIN hosts h ON h.id = s.host_id {where_sql}""",
        params,
    ).fetchone()["c"]

    order_sql = dt_order_sql(orders, SERVICE_HOSTS_ORDER_MAP, "h.ip ASC")
    rows = db.execute(
        f"""SELECT h.ip, h.hostname, COALESCE(h.device_type,'unknown') device_type,
                   h.os_name, s.product, s.version, s.extrainfo
            FROM services s
            JOIN hosts h ON h.id = s.host_id
            {where_sql}
            ORDER BY {order_sql}
            LIMIT ? OFFSET ?""",
        params + [length, start],
    ).fetchall()

    data = [
        {
            "ip": r["ip"],
            "ip_url": url_for("host_detail", ip=r["ip"]),
            "hostname": r["hostname"] or "",
            "device_type": r["device_type"],
            "device_badge": badge_class(r["device_type"]),
            "os_name": r["os_name"] or "",
            "product": r["product"] or "",
            "version": r["version"] or "",
            "extrainfo": r["extrainfo"] or "",
        }
        for r in rows
    ]

    return jsonify({
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": data,
    })


@app.route("/scans")
def scans_list():
    return render_template("scans.html")


SCANS_ORDER_MAP = {
    0: "id", 1: "started_at", 2: "finished_at", 3: "target_count", 4: "status",
}


@app.route("/api/scans")
def api_scans():
    db = get_db()
    draw, start, length, search_value, orders = dt_params()

    records_total = db.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]

    where_sql = ""
    params = []
    if search_value:
        where_sql = "WHERE (status LIKE ? OR xml_path LIKE ? OR command LIKE ?)"
        like = f"%{search_value}%"
        params = [like, like, like]

    records_filtered = db.execute(
        f"SELECT COUNT(*) c FROM scans {where_sql}", params
    ).fetchone()["c"]

    order_sql = dt_order_sql(orders, SCANS_ORDER_MAP, "id DESC")
    rows = db.execute(
        f"""SELECT id, started_at, finished_at, target_count, status, xml_path
            FROM scans
            {where_sql}
            ORDER BY {order_sql}
            LIMIT ? OFFSET ?""",
        params + [length, start],
    ).fetchall()

    data = [
        {
            "id": r["id"],
            "started_at": r["started_at"] or "",
            "finished_at": r["finished_at"] or "",
            "target_count": r["target_count"],
            "status": r["status"],
            "xml_path": r["xml_path"] or "",
        }
        for r in rows
    ]

    return jsonify({
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": data,
    })


@app.route("/api/cve-cache-stats")
def cve_cache_stats_api():
    return jsonify(scanner_db.cve_cache_stats(get_db()))


@app.route("/vuln/import-cache", methods=["POST"])
def vuln_import_cache():
    file = request.files.get("cve_file")
    if not file or not file.filename:
        return jsonify({"ok": False, "error": "Nessun file selezionato."}), 400

    try:
        content = file.read()
        parsed = cve_lookup.parse_cve_import(content, file.filename)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Errore nel parsing del file: {e}"}), 400

    if not parsed:
        return jsonify({
            "ok": False,
            "error": "Nessuna CPE/CVE valida trovata nel file (verifica formato/colonne).",
        }), 400

    db = get_db()
    imported_cves = sum(len(cve_list) for cve_list in parsed.values())
    for cpe, cve_list in parsed.items():
        scanner_db.merge_cached_cve(db, cpe, cve_list)

    return jsonify({"ok": True, "cpes": len(parsed), "cves": imported_cves})


@app.route("/vulnerabilities")
def vulnerabilities_list():
    db = get_db()
    stats = db.execute(
        """SELECT COUNT(*) total, COUNT(DISTINCT host_id) hosts_affected,
                  COUNT(DISTINCT cve_id) distinct_cves,
                  SUM(CASE WHEN cvss >= 9 THEN 1 ELSE 0 END) critical
           FROM host_vulnerabilities"""
    ).fetchone()
    return render_template("vulnerabilities.html", stats=stats)


VULN_ORDER_MAP = {
    0: "hv.cve_id", 1: "hv.cvss", 2: "h.ip", 3: "hv.port", 4: "hv.cpe", 5: "hv.detected_at",
}


@app.route("/api/vulnerabilities")
def api_vulnerabilities():
    db = get_db()
    draw, start, length, search_value, orders = dt_params()
    min_cvss = request.values.get("min_cvss", type=float)

    fixed_where = []
    fixed_params = []
    if min_cvss is not None:
        fixed_where.append("hv.cvss >= ?")
        fixed_params.append(min_cvss)

    base_from = "FROM host_vulnerabilities hv JOIN hosts h ON h.id = hv.host_id"
    total_sql = f"SELECT COUNT(*) c {base_from}" + (
        " WHERE " + " AND ".join(fixed_where) if fixed_where else ""
    )
    records_total = db.execute(total_sql, fixed_params).fetchone()["c"]

    where = list(fixed_where)
    params = list(fixed_params)
    if search_value:
        where.append(
            "(hv.cve_id LIKE ? OR h.ip LIKE ? OR hv.cpe LIKE ? OR COALESCE(h.device_type,'') LIKE ?)"
        )
        like = f"%{search_value}%"
        params.extend([like] * 4)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    records_filtered = db.execute(
        f"SELECT COUNT(*) c {base_from} {where_sql}", params
    ).fetchone()["c"]

    order_sql = dt_order_sql(orders, VULN_ORDER_MAP, "hv.cvss DESC")
    rows = db.execute(
        f"""SELECT hv.cve_id, hv.cvss, hv.url, hv.port, hv.cpe, hv.source, hv.detected_at,
                   h.ip, COALESCE(h.device_type,'unknown') device_type
            {base_from}
            {where_sql}
            ORDER BY {order_sql}
            LIMIT ? OFFSET ?""",
        params + [length, start],
    ).fetchall()

    data = [
        {
            "cve_id": r["cve_id"],
            "cvss": r["cvss"],
            "url": r["url"] or "",
            "ip": r["ip"],
            "ip_url": url_for("host_detail", ip=r["ip"]),
            "device_type": r["device_type"],
            "device_badge": badge_class(r["device_type"]),
            "port": r["port"],
            "cpe": r["cpe"] or "",
            "source": r["source"] or "",
            "detected_at": r["detected_at"] or "",
        }
        for r in rows
    ]

    return jsonify({
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": data,
    })


@app.route("/network-map")
def network_map():
    return render_template("network_map.html", device_colors=DEVICE_COLOR)


@app.route("/api/network-map")
def api_network_map():
    db = get_db()
    rows = db.execute(
        "SELECT ip, hostname, COALESCE(device_type,'unknown') device_type "
        "FROM hosts ORDER BY ip"
    ).fetchall()

    root = {"name": "10.0.0.0/8", "children": {}}

    def get_child(node, key):
        return node["children"].setdefault(key, {"name": key, "children": {}})

    for r in rows:
        parts = r["ip"].split(".")
        if len(parts) != 4:
            continue
        site_key = f"{parts[0]}.{parts[1]}.x.x"
        subnet_key = f"{parts[0]}.{parts[1]}.{parts[2]}.x"
        site_node = get_child(root, site_key)
        subnet_node = get_child(site_node, subnet_key)
        subnet_node["children"].setdefault("_leaves", []).append({
            "name": r["ip"],
            "ip": r["ip"],
            "hostname": r["hostname"] or "",
            "device_type": r["device_type"],
            "color": color_for_device_type(r["device_type"]),
            "leaf": True,
        })

    def finalize(node):
        children = node.pop("children")
        leaves = children.pop("_leaves", [])
        result = [finalize(c) for c in children.values()]
        result.sort(key=lambda c: c["name"])
        leaves.sort(key=lambda c: tuple(int(p) for p in c["ip"].split(".")))
        result.extend(leaves)
        node["children"] = result
        node["count"] = sum(c.get("count", 1) for c in result) if result else 0
        return node

    return jsonify(finalize(root))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5200, debug=True)
