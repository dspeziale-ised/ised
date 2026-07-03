"""Applicazione Flask per navigare l'inventario di rete raccolto da scan_and_store.py."""

import datetime
import hashlib
import math
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, url_for

import classify
import cve_lookup
import host_monitor
import monitor_schedule
import notify_gmail
import notify_telegram
import report_generator
import report_schedule
import scanner_db

BASE_DIR = Path(__file__).parent
SCAN_INPUT_FILE = Path(os.environ.get("SCAN_INPUT", BASE_DIR / "up_ips.txt"))
SCRIPTS_DIR = BASE_DIR / "scripts"
DATA_DIR = BASE_DIR / "data"

# DATABASE_URL (postgresql://...) ha priorità: è così che il container Docker
# punta al servizio Postgres. Senza, si torna al comportamento nativo di
# sempre: un file SQLite (INVENTORY_DB o instance/inventory.db di default).
_DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB_IS_POSTGRES = bool(_DATABASE_URL) and scanner_db.is_postgres_url(_DATABASE_URL)
DB_PATH = _DATABASE_URL if DB_IS_POSTGRES else Path(
    os.environ.get("INVENTORY_DB", BASE_DIR / "instance" / "inventory.db")
)
LIKE_OP = "ILIKE" if DB_IS_POSTGRES else "LIKE"

app = Flask(__name__)

if DB_IS_POSTGRES or DB_PATH.exists():
    # init_db crea le tabelle se mancano (idempotente, CREATE TABLE IF NOT
    # EXISTS) — necessario soprattutto per Postgres: a differenza di un file
    # SQLite, un DB Postgres appena creato non ha nessuno schema ad attendere
    # che uno script CLI lo popoli, e l'app web è spesso la prima a connettersi.
    _startup_conn = scanner_db.connect(str(DB_PATH))
    scanner_db.init_db(_startup_conn)
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
        g.db = scanner_db.connect(str(DB_PATH))
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


def is_discovery_running():
    """True solo se lo script di discovery di questo progetto è attivo
    (stesso principio di is_scan_and_store_running: query sulla command
    line dei processi, non un generico nmap.exe/powershell.exe che darebbe
    falsi positivi con processi indipendenti). Copre sia lo script
    PowerShell nativo sia l'equivalente Python (discovery_scan.py) usato in
    modalità container."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process "
             "| Select-Object -ExpandProperty CommandLine"],
            capture_output=True, text=True, timeout=8,
        )
        return "nmap-discovery-10net.ps1" in out.stdout or "discovery_scan.py" in out.stdout
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


# In modalità container (NMAP_PROXY_URL impostata) non c'è PowerShell/nmap
# nativo nel container: si usa l'equivalente Python (discovery_scan.py, che
# passa da nmap_proxy_client) invece dello script PowerShell originale, che
# resta il default per l'uso nativo su Windows (più maturo, in uso da tempo).
USE_PYTHON_DISCOVERY = bool(os.environ.get("NMAP_PROXY_URL"))

# Job in background avviabili dalla UI (niente più comandi a mano da terminale):
# - discovery: ping-sweep -sn su tutta 10.0.0.0/8 -> data/*.xml
# - rescan: estrae gli IP up da data/*.xml e scansiona quelli nuovi (nmap)
# - classify: classifica il tipo di dispositivo via LLM (Groq/Gemini/Ollama)
# - vuln: cerca CVE per le CPE rilevate (nmap --script vulners, con cache)
# - attack: mappa servizi/vulnerabilità sulle tecniche MITRE ATT&CK
JOBS = {
    "discovery": {
        "cmd": (
            [sys.executable, str(BASE_DIR / "discovery_scan.py")] if USE_PYTHON_DISCOVERY else
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(SCRIPTS_DIR / "nmap-discovery-10net.ps1")]
        ),
        "lock_file": BASE_DIR / "discovery.lock",
        "log_file": BASE_DIR / "discovery_log.txt",
        "label": "Discovery iniziale",
    },
    "rescan": {
        "cmd": [sys.executable, str(BASE_DIR / "run_rescan.py")],
        "lock_file": BASE_DIR / "rescan.lock",
        "log_file": BASE_DIR / "rescan_log.txt",
        "label": "Aggiornamento scansione",
    },
    "classify": {
        "cmd": [sys.executable, str(BASE_DIR / "classify_devices.py")],
        "lock_file": BASE_DIR / "classify.lock",
        "log_file": BASE_DIR / "classify_log.txt",
        "label": "Classificazione AI",
    },
    "vuln": {
        "cmd": [sys.executable, str(BASE_DIR / "vuln_scan.py")],
        "lock_file": BASE_DIR / "vuln.lock",
        "log_file": BASE_DIR / "vuln_log.txt",
        "label": "Scansione vulnerabilità",
    },
    "attack": {
        "cmd": [sys.executable, str(BASE_DIR / "attack_scan.py")],
        "lock_file": BASE_DIR / "attack.lock",
        "log_file": BASE_DIR / "attack_log.txt",
        "label": "Mappatura MITRE ATT&CK",
    },
}
_job_processes = {}

# Fallback di rilevamento "in corso" per job avviabili anche fuori da questo
# meccanismo (riga di comando): controlla la command line dei processi per
# il nome dello script specifico, MAI un generico nmap.exe/powershell.exe
# attivo — altrimenti un processo indipendente dell'utente (es. una
# ping-sweep manuale) farebbe scattare un falso positivo.
JOB_FALLBACK_CHECK = {
    "discovery": is_discovery_running,
    "rescan": is_scan_and_store_running,
}


def is_job_running(name):
    """True se il job è già attivo. Verificato tramite lock file con PID
    (sopravvive ai riavvii del processo Flask, es. per l'auto-reload in
    debug mode) e, dove applicabile, tramite JOB_FALLBACK_CHECK (copre
    esecuzioni avviate fuori da questo meccanismo, es. da riga di comando)."""
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

    fallback = JOB_FALLBACK_CHECK.get(name)
    return fallback() if fallback else False


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
    log.close()  # il figlio ha già la sua copia duplicata del descrittore; non serve tenerlo aperto
    # Scrive subito il PID nel lock file: script non Python (es. discovery,
    # PowerShell) non gestiscono da soli un JobLock — farlo qui garantisce
    # comunque la persistenza dello stato "in corso" a un riavvio di Flask.
    # Per gli script Python è un doppio scritto innocuo: il loro JobLock
    # scriverà a sua volta lo stesso PID (Popen esegue python direttamente,
    # senza shell intermedia, quindi è lo stesso processo/PID).
    try:
        job["lock_file"].write_text(str(proc.pid), encoding="utf-8")
    except OSError:
        pass
    return True, None


def stop_job(name):
    """Termina il job in corso, compreso l'intero albero di processi figli
    (es. nmap lanciato da scan_and_store.py) tramite 'taskkill /T' — su
    Windows terminare solo il processo padre non termina i figli."""
    job = JOBS[name]
    pid = None

    proc = _job_processes.get(name)
    if proc is not None and proc.poll() is None:
        pid = proc.pid
    elif job["lock_file"].exists():
        try:
            pid = int(job["lock_file"].read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            pid = None

    if not pid or not is_pid_alive(pid):
        return False, f"{job['label']}: nessun processo attivo trovato."

    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        return False, f"Errore durante l'arresto: {e}"

    try:
        job["lock_file"].unlink(missing_ok=True)
    except OSError:
        pass
    _job_processes.pop(name, None)

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
    duration_expr = (
        "EXTRACT(EPOCH FROM (finished_at::timestamptz - started_at::timestamptz))" if DB_IS_POSTGRES
        else "(julianday(finished_at) - julianday(started_at)) * 86400.0"
    )
    avg_row = db.execute(
        f"SELECT AVG({duration_expr}) avg_s, AVG(target_count) avg_batch FROM scans"
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
def operations_redirect():
    return redirect(url_for("admin_panel"))


@app.route("/admin")
def admin_panel():
    xml_files = []
    if DATA_DIR.is_dir():
        for p in sorted(DATA_DIR.glob("*.xml")):
            xml_files.append({
                "name": p.name,
                "mtime": datetime.datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
                "size_mb": round(p.stat().st_size / (1024 * 1024), 1),
            })
    return render_template(
        "admin.html",
        xml_files=xml_files,
        data_dir=str(DATA_DIR),
        input_ip_count=count_input_ips(),
        jobs_running={name: is_job_running(name) for name in JOBS},
        notify_status=notify_status_dict(),
        report_schedule_config=report_schedule.load(),
    )


JOB_FORCE_FLAG = {"attack": "--update-matrix"}


DISCOVERY_TIMING_CHOICES = {"0", "1", "2", "3", "4", "5"}
RESCAN_TIMING_CHOICES = {"1", "2", "3", "4", "5"}


def build_discovery_args(values):
    """Costruisce gli argomenti CLI per il job discovery dai campi del form
    (BatchSize/OutputDir/NmapPath/Timing). Di default scrive gli XML
    direttamente in data/, cosi il job 'rescan' successivo li trova senza
    passaggi manuali. Il formato dei flag dipende da quale script è attivo
    (vedi USE_PYTHON_DISCOVERY): PowerShell (nativo) o discovery_scan.py
    (container). 'timing' (-T0..-T5, default 3) controlla l'aggressività
    del ping-sweep: valori bassi per non affaticare firewall/IDS, a costo
    di una scansione più lenta — il numero di thread/subnet in parallelo
    resta invece controllato da 'batch_size'."""
    output_dir = (values.get("output_dir") or "").strip() or str(DATA_DIR)
    batch_size = values.get("batch_size", type=int)
    timing = (values.get("timing") or "").strip()
    if timing not in DISCOVERY_TIMING_CHOICES:
        timing = None

    if USE_PYTHON_DISCOVERY:
        args = ["--output-dir", output_dir]
        if batch_size and batch_size > 0:
            args += ["--batch-size", str(batch_size)]
        if timing:
            args += ["--timing", timing]
        return args

    args = []
    if batch_size and batch_size > 0:
        args += ["-BatchSize", str(batch_size)]
    args += ["-OutputDir", output_dir]
    if timing:
        args += ["-Timing", timing]
    nmap_path = (values.get("nmap_path") or "").strip()
    if nmap_path:
        args += ["-NmapPath", nmap_path]
    return args


def build_rescan_args(values):
    """Costruisce gli argomenti CLI per run_rescan.py dai campi del form:
    solo 'timing' (-T1..-T5, default 4 se non indicato) per controllare
    l'aggressività della scansione OS/servizi, stesso motivo di discovery."""
    timing = (values.get("timing") or "").strip()
    if timing not in RESCAN_TIMING_CHOICES:
        return []
    return ["--timing", timing]


JOB_ARGS_BUILDERS = {"discovery": build_discovery_args, "rescan": build_rescan_args}


@app.route("/jobs/<name>/start", methods=["POST"])
def job_start(name):
    if name not in JOBS:
        return jsonify({"started": False, "reason": "Job sconosciuto."}), 404
    builder = JOB_ARGS_BUILDERS.get(name)
    if builder:
        extra_args = builder(request.values)
    elif request.values.get("force") == "1":
        extra_args = [JOB_FORCE_FLAG.get(name, "--force")]
    else:
        extra_args = None
    ok, reason = start_job(name, extra_args=extra_args)
    return jsonify({"started": ok, "reason": reason})


@app.route("/jobs/<name>/stop", methods=["POST"])
def job_stop(name):
    if name not in JOBS:
        return jsonify({"stopped": False, "reason": "Job sconosciuto."}), 404
    ok, reason = stop_job(name)
    return jsonify({"stopped": ok, "reason": reason})


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
    os_names = db.execute(
        "SELECT DISTINCT os_name d FROM hosts WHERE os_name IS NOT NULL ORDER BY d"
    ).fetchall()
    return render_template(
        "hosts.html", device_types=device_types, os_families=os_families, os_names=os_names
    )


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
    os_name = request.values.get("os_name", "").strip()

    fixed_where = []
    fixed_params = []
    if device_type:
        fixed_where.append("COALESCE(h.device_type,'unknown') = ?")
        fixed_params.append(device_type)
    if os_family:
        fixed_where.append("h.os_family = ?")
        fixed_params.append(os_family)
    if os_name:
        fixed_where.append("h.os_name = ?")
        fixed_params.append(os_name)

    total_sql = "SELECT COUNT(*) c FROM hosts h" + (
        " WHERE " + " AND ".join(fixed_where) if fixed_where else ""
    )
    records_total = db.execute(total_sql, fixed_params).fetchone()["c"]

    where = list(fixed_where)
    params = list(fixed_params)
    if search_value:
        where.append(
            f"(h.ip {LIKE_OP} ? OR h.hostname {LIKE_OP} ? OR COALESCE(h.device_type,'unknown') {LIKE_OP} ? "
            f"OR h.os_family {LIKE_OP} ? OR h.os_name {LIKE_OP} ? OR h.mac_address {LIKE_OP} ?)"
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
    attack_techniques = scanner_db.get_host_attack_techniques(db, host["id"])
    ttl_baseline, ttl_hops = classify.guess_ttl_baseline(host["ttl"])
    return render_template(
        "host_detail.html", host=host, os_matches=os_matches, services=services,
        device_type_options=sorted(DEVICE_COLOR.keys()), roles=roles,
        vulnerabilities=vulnerabilities, attack_techniques=attack_techniques,
        ttl_baseline=ttl_baseline, ttl_hops=ttl_hops,
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
        where_sql = f"WHERE (CAST(port AS TEXT) {LIKE_OP} ? OR protocol {LIKE_OP} ? OR service_name {LIKE_OP} ?)"
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
            f"(h.ip {LIKE_OP} ? OR h.hostname {LIKE_OP} ? OR COALESCE(h.device_type,'unknown') {LIKE_OP} ? "
            f"OR h.os_name {LIKE_OP} ? OR s.product {LIKE_OP} ? OR s.version {LIKE_OP} ?)"
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
        where_sql = f"WHERE (status {LIKE_OP} ? OR xml_path {LIKE_OP} ? OR command {LIKE_OP} ?)"
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
            f"(hv.cve_id {LIKE_OP} ? OR h.ip {LIKE_OP} ? OR hv.cpe {LIKE_OP} ? OR COALESCE(h.device_type,'') {LIKE_OP} ?)"
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


@app.route("/attack-matrix")
def attack_matrix():
    db = get_db()
    scanner_db.ensure_attack_tables(db)
    matrix = scanner_db.attack_matrix_data(db, only_exposed=False)
    total_hosts = db.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
    hosts_exposed = db.execute(
        "SELECT COUNT(DISTINCT host_id) c FROM host_attack_techniques"
    ).fetchone()["c"]
    loaded = db.execute("SELECT COUNT(*) c FROM attack_techniques").fetchone()["c"] > 0
    return render_template(
        "attack_matrix.html", tactics=matrix["tactics"],
        techniques_by_tactic=matrix["techniques_by_tactic"],
        total_hosts=total_hosts, hosts_exposed=hosts_exposed, loaded=loaded,
    )


@app.route("/api/attack-matrix/technique/<technique_id>/hosts")
def api_attack_technique_hosts(technique_id):
    db = get_db()
    hosts = scanner_db.hosts_for_technique(db, technique_id)
    technique = db.execute(
        "SELECT technique_id, name, description, url FROM attack_techniques WHERE technique_id = ?",
        (technique_id,),
    ).fetchone()
    return jsonify({
        "technique": dict(technique) if technique else None,
        "hosts": [
            {**h, "ip_url": url_for("host_detail", ip=h["ip"]), "device_badge": badge_class(h["device_type"])}
            for h in hosts
        ],
    })


@app.route("/monitoring")
def monitoring():
    db = get_db()
    scanner_db.ensure_monitor_tables(db)
    return render_template(
        "monitoring.html",
        summary=scanner_db.monitor_summary(db),
        monitor_config=monitor_schedule.load(),
    )


MONITORING_ORDER_MAP = {0: "h.ip", 1: "device_type", 2: "status", 3: "checked_at"}


@app.route("/api/monitoring")
def api_monitoring():
    db = get_db()
    draw, start, length, search_value, orders = dt_params()
    status_filter = request.values.get("status", "").strip()

    records_total = db.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]

    where = []
    params = []
    if search_value:
        where.append(f"(h.ip {LIKE_OP} ? OR COALESCE(h.device_type,'unknown') {LIKE_OP} ?)")
        like = f"%{search_value}%"
        params.extend([like, like])
    if status_filter == "unknown":
        where.append("latest_status.status IS NULL")
    elif status_filter:
        where.append("latest_status.status = ?")
        params.append(status_filter)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    base_sql = f"""
        FROM hosts h
        LEFT JOIN (
            SELECT hsc.host_id, hsc.status, hsc.checked_at
            FROM host_status_checks hsc
            JOIN (SELECT host_id, MAX(id) max_id FROM host_status_checks GROUP BY host_id) latest
              ON latest.host_id = hsc.host_id AND latest.max_id = hsc.id
        ) latest_status ON latest_status.host_id = h.id
        {where_sql}
    """
    records_filtered = db.execute(f"SELECT COUNT(*) c {base_sql}", params).fetchone()["c"]

    order_sql = dt_order_sql(orders, MONITORING_ORDER_MAP, "h.ip ASC")
    query = f"""
        SELECT h.id, h.ip, COALESCE(h.device_type,'unknown') device_type,
               latest_status.status, latest_status.checked_at
        {base_sql}
        ORDER BY {order_sql}
        LIMIT ? OFFSET ?
    """
    rows = db.execute(query, params + [length, start]).fetchall()

    data = []
    for r in rows:
        uptime = scanner_db.host_uptime_percent(db, r["id"], since_hours=24) if r["status"] else None
        data.append({
            "ip": r["ip"],
            "ip_url": url_for("host_detail", ip=r["ip"]),
            "device_type": r["device_type"],
            "device_badge": badge_class(r["device_type"]),
            "status": r["status"] or "unknown",
            "checked_at": r["checked_at"] or "",
            "uptime_24h": uptime,
        })

    return jsonify({
        "draw": draw,
        "recordsTotal": records_total,
        "recordsFiltered": records_filtered,
        "data": data,
    })


@app.route("/api/monitoring/host/<ip>/history")
def api_monitoring_host_history(ip):
    db = get_db()
    host = db.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
    if host is None:
        abort(404)
    history = scanner_db.get_host_status_history(db, host["id"], limit=200)
    return jsonify({
        "history": history,
        "uptime_24h": scanner_db.host_uptime_percent(db, host["id"], since_hours=24),
        "uptime_7d": scanner_db.host_uptime_percent(db, host["id"], since_hours=24 * 7),
    })


@app.route("/api/monitoring/hourly")
def api_monitoring_hourly():
    db = get_db()
    date_str = request.args.get("date") or datetime.date.today().isoformat()
    try:
        datetime.datetime.fromisoformat(date_str)
    except ValueError:
        return jsonify({"error": "Data non valida (attesa YYYY-MM-DD)."}), 400

    hourly_by_host = scanner_db.hosts_hourly_status(db, date_str)
    hosts = db.execute(
        "SELECT id, ip, COALESCE(device_type,'unknown') device_type FROM hosts ORDER BY ip"
    ).fetchall()

    def ip_key(ip):
        try:
            return tuple(int(p) for p in ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)

    data = [
        {
            "ip": h["ip"],
            "ip_url": url_for("host_detail", ip=h["ip"]),
            "device_type": h["device_type"],
            "device_badge": badge_class(h["device_type"]),
            "hours": hourly_by_host.get(h["id"], [None] * 24),
        }
        for h in sorted(hosts, key=lambda h: ip_key(h["ip"]))
    ]
    return jsonify({"date": date_str, "hosts": data})


@app.route("/monitoring/run-now", methods=["POST"])
def monitoring_run_now():
    config = monitor_schedule.load()
    db = get_db()
    summary = host_monitor.run_monitor_cycle(
        db, batch_size=config.get("batch_size") or 60, heartbeat_minutes=config.get("heartbeat_minutes") or 60,
    )
    monitor_schedule.mark_run(datetime.datetime.now(), summary)
    return jsonify({"ok": True, "summary": summary})


@app.route("/api/monitor-schedule", methods=["GET", "POST"])
def api_monitor_schedule():
    if request.method == "POST":
        existing = monitor_schedule.load()
        config = {
            "enabled": request.form.get("enabled") == "1",
            "interval_minutes": request.form.get("interval_minutes", type=int) or 5,
            "batch_size": request.form.get("batch_size", type=int) or 60,
            "heartbeat_minutes": request.form.get("heartbeat_minutes", type=int) or 60,
            "last_run_at": existing.get("last_run_at"),
            "last_run_summary": existing.get("last_run_summary"),
        }
        monitor_schedule.save(config)
    return jsonify(monitor_schedule.load())


REPORT_KIND_CHOICES = ("summary", "hosts")


def _clean_kinds(values):
    kinds = tuple(k for k in values if k in REPORT_KIND_CHOICES)
    return kinds or REPORT_KIND_CHOICES


@app.route("/reports/generate")
def reports_generate():
    kinds = _clean_kinds(request.args.get("kinds", "summary,hosts").split(","))
    db = get_db()
    pdf_bytes = report_generator.generate_report_pdf(db, kinds=kinds)
    filename = report_generator.default_filename()
    return Response(
        pdf_bytes, mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/reports/send", methods=["POST"])
def reports_send():
    kinds = _clean_kinds(request.form.getlist("kinds"))
    db = get_db()
    pdf_bytes = report_generator.generate_report_pdf(db, kinds=kinds)
    filename = report_generator.default_filename()

    results = {}
    if request.form.get("telegram") == "1":
        try:
            notify_telegram.send_document(pdf_bytes, filename, caption="Report inventario di rete - ised.net")
            results["telegram"] = {"ok": True}
        except notify_telegram.TelegramError as e:
            results["telegram"] = {"ok": False, "error": str(e)}
    if request.form.get("gmail") == "1":
        try:
            notify_gmail.send_document(pdf_bytes, filename, to_address=request.form.get("gmail_to") or None)
            results["gmail"] = {"ok": True}
        except notify_gmail.GmailError as e:
            results["gmail"] = {"ok": False, "error": str(e)}

    ok = bool(results) and all(r["ok"] for r in results.values())
    return jsonify({"ok": ok, "results": results})


def notify_status_dict():
    return {
        "telegram_configured": notify_telegram.is_configured(),
        "telegram_chat_id": notify_telegram.get_chat_id_display(),
        "telegram_token_set": notify_telegram.has_token(),
        "telegram_from_env": notify_telegram.token_from_env() or notify_telegram.chat_id_from_env(),
        "gmail_configured": notify_gmail.is_configured(),
        "gmail_address": notify_gmail.get_address_display(),
        "gmail_app_password_set": notify_gmail.has_app_password(),
        "gmail_default_to": notify_gmail.default_recipient() or "",
        "gmail_from_env": notify_gmail.address_from_env() or notify_gmail.app_password_from_env(),
    }


@app.route("/api/notify-status")
def api_notify_status():
    return jsonify(notify_status_dict())


@app.route("/api/notify-config", methods=["POST"])
def api_notify_config():
    notify_telegram.save_credentials(
        token=(request.form.get("telegram_bot_token") or "").strip(),
        chat_id=(request.form.get("telegram_chat_id") or "").strip(),
    )
    notify_gmail.save_credentials(
        address=(request.form.get("gmail_address") or "").strip(),
        app_password=(request.form.get("gmail_app_password") or "").strip(),
        default_to=(request.form.get("gmail_default_to") or "").strip(),
    )
    return jsonify({"ok": True})


@app.route("/api/report-schedule", methods=["GET", "POST"])
def api_report_schedule():
    if request.method == "POST":
        existing = report_schedule.load()
        config = {
            "enabled": request.form.get("enabled") == "1",
            "interval_hours": request.form.get("interval_hours", type=int) or 24,
            "kinds": list(_clean_kinds(request.form.getlist("kinds"))),
            "send_telegram": request.form.get("send_telegram") == "1",
            "send_gmail": request.form.get("send_gmail") == "1",
            "gmail_to": (request.form.get("gmail_to") or "").strip(),
            "last_sent_at": existing.get("last_sent_at"),
        }
        report_schedule.save(config)
    return jsonify(report_schedule.load())


def run_scheduled_report_if_due():
    """Se la schedulazione è attiva ed è trascorso l'intervallo configurato,
    genera il report e lo invia ai canali abilitati. Chiamato periodicamente
    dal thread avviato in start_report_scheduler()."""
    config = report_schedule.load()
    now = datetime.datetime.now()
    if not report_schedule.is_due(config, now):
        return

    conn = scanner_db.connect(str(DB_PATH))
    try:
        pdf_bytes = report_generator.generate_report_pdf(conn, kinds=_clean_kinds(config.get("kinds") or []))
    finally:
        conn.close()
    filename = report_generator.default_filename()

    errors = []
    if config.get("send_telegram"):
        try:
            notify_telegram.send_document(pdf_bytes, filename, caption="Report periodico inventario di rete")
        except notify_telegram.TelegramError as e:
            errors.append(f"Telegram: {e}")
    if config.get("send_gmail"):
        try:
            notify_gmail.send_document(pdf_bytes, filename, to_address=config.get("gmail_to") or None)
        except notify_gmail.GmailError as e:
            errors.append(f"Gmail: {e}")

    report_schedule.mark_sent(now)
    if errors:
        print("[report-scheduler] invio con errori: " + "; ".join(errors))


def _report_scheduler_loop():
    while True:
        try:
            run_scheduled_report_if_due()
        except Exception as e:
            print(f"[report-scheduler] errore inatteso: {e}")
        time.sleep(900)  # controlla ogni 15 minuti se la schedulazione è "due"


def start_report_scheduler():
    """Avvia il thread di controllo della schedulazione, una sola volta —
    con il reloader di Flask in debug mode lo script viene eseguito anche da
    un processo "watcher" che non serve mai richieste: WERKZEUG_RUN_MAIN è
    'true' solo nel processo figlio che effettivamente gira, quindi è la
    guardia giusta per non avviare due thread duplicati."""
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not APP_DEBUG:
        threading.Thread(target=_report_scheduler_loop, daemon=True).start()


def run_scheduled_monitor_if_due():
    """Se il monitoraggio è attivo ed è trascorso l'intervallo configurato,
    esegue un ciclo di controllo raggiungibilità su tutti gli host noti."""
    config = monitor_schedule.load()
    now = datetime.datetime.now()
    if not monitor_schedule.is_due(config, now):
        return

    conn = scanner_db.connect(str(DB_PATH))
    try:
        scanner_db.ensure_monitor_tables(conn)
        summary = host_monitor.run_monitor_cycle(
            conn,
            batch_size=config.get("batch_size") or 60,
            heartbeat_minutes=config.get("heartbeat_minutes") or 60,
        )
    finally:
        conn.close()
    monitor_schedule.mark_run(now, summary)


def _monitor_scheduler_loop():
    while True:
        try:
            run_scheduled_monitor_if_due()
        except Exception as e:
            print(f"[monitor-scheduler] errore inatteso: {e}")
        time.sleep(30)  # granularità minuti: controlla più spesso del report scheduler


def start_monitor_scheduler():
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not APP_DEBUG:
        threading.Thread(target=_monitor_scheduler_loop, daemon=True).start()


if __name__ == "__main__":
    # Uso nativo di sempre: 127.0.0.1, debug/reloader attivi. Nel container
    # Docker (Dockerfile imposta APP_HOST=0.0.0.0/FLASK_DEBUG=0) il server
    # deve essere raggiungibile da fuori e il reloader va disattivato.
    APP_DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"
    APP_HOST = os.environ.get("APP_HOST", "127.0.0.1")
    APP_PORT = int(os.environ.get("APP_PORT", "5200"))
    start_report_scheduler()
    start_monitor_scheduler()
    app.run(host=APP_HOST, port=APP_PORT, debug=APP_DEBUG)
