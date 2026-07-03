"""Conteggio approssimato delle connessioni TCP/UDP aperte da un processo
nmap durante la sua esecuzione, via polling psutil sul PID del processo:
nmap non riporta mai un conteggio "connessioni" nel suo output (solo
pacchetti/byte totali via -v, vedi nmap_proxy_client.parse_traffic_stats),
quindi l'unico modo per stimarlo è osservare i socket del suo processo
dall'esterno mentre gira.

APPROSSIMATO PER DIFETTO: un poll ogni ~100ms non cattura connessioni più
brevi dell'intervallo — tipico delle scansioni SYN (-sS, il default di
nmap con privilegi), che aprono e chiudono un socket per pochi
millisecondi. Utile come indicatore approssimativo dell'attività di rete
generata, non come conteggio esatto (richiesto esplicitamente così
nonostante il limite, invece di derivarlo — con precisione esatta ma
un significato diverso — dalle porte scansionate/aperte nell'XML nmap).

Richiede psutil; se non installato o senza permessi sufficienti per
ispezionare il processo, ritorna sempre 0 invece di far fallire la
scansione (una metrica accessoria non deve mai bloccare lo scanning vero).
"""

import subprocess
import threading

try:
    import psutil
except ImportError:
    psutil = None

_POLL_INTERVAL = 0.1
_RESPONDED_STATUSES = {"ESTABLISHED", "CLOSE_WAIT"}


def _poll_connections(pid, stop_event, seen_all, seen_responded):
    if psutil is None:
        return
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    get_conns = proc.net_connections if hasattr(proc, "net_connections") else proc.connections
    while not stop_event.is_set():
        try:
            conns = get_conns(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            break
        for c in conns:
            if not c.raddr:
                continue
            key = (c.raddr[0], c.raddr[1], c.type)
            seen_all.add(key)
            if c.status in _RESPONDED_STATUSES:
                seen_responded.add(key)
        stop_event.wait(_POLL_INTERVAL)


def run_and_count_connections(cmd, timeout=None):
    """Esegue cmd (argv completo, binario incluso) come subprocess,
    monitorando in un thread separato le connessioni di rete aperte dal
    processo. Ritorna (returncode, stdout_bytes, stderr_bytes, timed_out,
    connections_out, connections_in):
    - connections_out: connessioni distinte osservate (per indirizzo:porta
      remoti + protocollo), incluse quelle mai arrivate a una risposta
      (es. SYN_SENT su una porta filtrata/host down);
    - connections_in: il sottoinsieme che ha raggiunto uno stato che indica
      una risposta dall'altro capo (ESTABLISHED/CLOSE_WAIT).

    Se psutil non è disponibile, connections_out/connections_in sono
    sempre 0 (comportamento della subprocess invariato)."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    seen_all = set()
    seen_responded = set()
    stop_event = threading.Event()
    poll_thread = threading.Thread(
        target=_poll_connections, args=(proc.pid, stop_event, seen_all, seen_responded), daemon=True,
    )
    poll_thread.start()

    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        timed_out = True
    finally:
        stop_event.set()
        poll_thread.join(timeout=2)

    return proc.returncode, stdout, stderr, timed_out, len(seen_all), len(seen_responded)
