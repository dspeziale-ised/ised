"""Conteggio approssimato delle connessioni TCP/UDP aperte da un processo
nmap durante la sua esecuzione, via polling psutil sul PID del processo:
nmap non riporta mai un conteggio "connessioni" nel suo output (solo
pacchetti/byte totali via -v, vedi nmap_proxy_client.parse_traffic_stats),
quindi l'unico modo per stimarlo è osservare i socket del suo processo
dall'esterno mentre gira.

LIMITE STRUTTURALE VERIFICATO (non solo un problema di campionamento): con
-sS (SYN scan, la tecnica di DEFAULT usata da discovery/rescan/monitor in
questo progetto) nmap costruisce i pacchetti grezzi da sé via raw
socket/Npcap, SENZA mai passare dalle connect() del sistema operativo — di
conseguenza non esiste alcun socket nella tabella connessioni del SO che
psutil possa osservare, e connections_out/connections_in risultano SEMPRE
0, indipendentemente dalla frequenza di polling. Solo con -sT (TCP connect
scan, che usa connect() reali) i socket sono osservabili — ma con -sT nmap
NON stampa affatto la riga "Raw packets sent" usata per bytes/pacchetti
(verificato): le due metriche (bytes/pacchetti vs connessioni) sono quindi
alternative a seconda della tecnica scelta, mai disponibili insieme sulla
stessa scansione. In pratica: bytes/pacchetti funzionano sempre (tecnica di
default -sS), le connessioni sono valorizzate solo scegliendo -sT
esplicitamente nella Scansione nmap personalizzata.

Anche con -sT, il campionamento resta approssimato per difetto: un poll
ogni ~100ms può non catturare connessioni più brevi dell'intervallo
(tipico su host a bassa latenza, dove l'intero ciclo connect/risposta/
chiusura dura pochi millisecondi).

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

# Poll ogni 100ms: anche così, una connessione TCP di un port scan (aperta
# e chiusa in millisecondi non appena nmap ottiene la risposta) può benissimo
# non essere mai catturata — vedi il modulo docstring.
_POLL_INTERVAL = 0.1
# "Risposta ricevuta": qualunque stato OLTRE il semplice invio iniziale
# (SYN_SENT), non solo ESTABLISHED/CLOSE_WAIT — quegli stati durano spesso
# solo pochi millisecondi in una probe di scansione (nmap chiude subito la
# connessione una volta determinato lo stato della porta), quindi anche
# TIME_WAIT/FIN_WAIT*/CLOSING/LAST_ACK (raggiunti solo se la connessione è
# arrivata a compimento) contano come prova che l'altro capo ha risposto.
_RESPONDED_STATUSES = {
    "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2", "CLOSING", "LAST_ACK",
}


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
