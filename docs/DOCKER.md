# Esecuzione in Docker

## Architettura

L'app (Flask) e il database (**PostgreSQL**, al posto di SQLite) girano in
container Docker. **nmap resta fuori dal container** ed è eseguito
nativamente sull'host Windows: su Docker Desktop/Windows i driver raw-socket
(Npcap) richiesti da nmap non funzionano in modo affidabile dentro il
namespace di rete di un container. Le scansioni vengono invece inoltrate a
un piccolo proxy HTTP (`nmap_proxy_server.py`) che gira nativamente
sull'host, con nmap installato come sempre.

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│  Host Windows                │        │  Docker (compose)            │
│                              │        │                              │
│  nmap_proxy_server.py :8765  │◄───────┤  webapp (Flask) :5200        │
│  (nmap nativo/Npcap)         │  HTTP  │   - scan_and_store.py        │
│                              │        │   - vuln_scan.py             │
│                              │        │   - discovery_scan.py        │
│                              │        │   - host_monitor.py          │
│                              │        │         │ DATABASE_URL       │
│                              │        │         ▼                   │
│                              │        │  postgres :5432              │
└─────────────────────────────┘        └──────────────────────────────┘
```

Ogni script che invoca nmap passa da `nmap_proxy_client.run_nmap(args, ...)`
invece di chiamare `subprocess.run(["nmap", ...])` direttamente:
- se `NMAP_PROXY_URL` è impostata (caso del container), inoltra la
  richiesta al proxy sull'host
- altrimenti (uso nativo, come sempre) esegue nmap in locale — **nessun
  cambio di comportamento fuori da Docker**

Il proxy gestisce anche la traduzione dei pattern di I/O su file (`-oX
<path>` → cattura su stdout scritta poi nel path locale del chiamante,
`-iL <path>` → i target letti dal file locale e passati come argomenti
posizionali), dato che il vero processo nmap gira su una macchina diversa
dal chiamante.

**Discovery iniziale**: in modalità nativa usa lo script PowerShell
`scripts/nmap-discovery-10net.ps1` (invariato). In modalità container (dove
non esiste PowerShell) usa invece `discovery_scan.py`, un'implementazione
Python equivalente che passa anch'essa da `nmap_proxy_client` — la scelta è
automatica in base a `NMAP_PROXY_URL`.

## 1. Avvia il proxy nmap sull'host Windows

```
python nmap_proxy_server.py
```

Di default ascolta su `0.0.0.0:8765` (necessario per essere raggiungibile
da un container via `host.docker.internal`). Configura un token condiviso
**prima** di lasciarlo in ascolto oltre `127.0.0.1`, dato che esegue i
comandi nmap che il chiamante gli passa:

```
mkdir -p keys && echo il-tuo-token-segreto > keys/nmap_proxy_token
```

(oppure imposta la variabile d'ambiente `NMAP_PROXY_TOKEN` invece del file).
Il proxy stampa un avviso all'avvio se nessun token è configurato.

Verifica che risponda:
```
curl http://127.0.0.1:8765/health
```

## 2. Configura le variabili d'ambiente

```
cp .env.example .env
```

Valorizza almeno `NMAP_PROXY_TOKEN` (stesso valore del passo 1) e
`POSTGRES_PASSWORD`. Le altre variabili (chiavi AI, NVD, Telegram, Gmail)
sono opzionali — senza, le relative funzionalità restano disattivate con un
messaggio d'errore chiaro nell'interfaccia, il resto dell'app funziona
comunque.

## 3. Avvia i container

```
docker compose up -d --build
```

Apri `http://localhost:5200`. Al primo avvio l'app crea da sé lo schema nel
database Postgres (nessuna migrazione manuale).

## Variabili d'ambiente principali

| Variabile | Dove | Descrizione |
|---|---|---|
| `DATABASE_URL` | webapp (impostata da docker-compose) | `postgresql://user:pass@postgres:5432/db` — se assente, l'app usa SQLite come in uso nativo |
| `NMAP_PROXY_URL` | webapp | URL del proxy nmap sull'host, es. `http://host.docker.internal:8765` |
| `NMAP_PROXY_TOKEN` | webapp + proxy | Token condiviso per autenticare le richieste al proxy |
| `APP_HOST` / `APP_PORT` | webapp | Indirizzo/porta di ascolto Flask (Dockerfile imposta `APP_HOST=0.0.0.0`) |
| `FLASK_DEBUG` | webapp | `0` nel container (disattiva reloader/debug), `1` di default in uso nativo |

## Limitazioni note

- **Discovery** in modalità container copre solo il ping-sweep -sn tramite
  `discovery_scan.py` (via proxy) — funzionalmente equivalente allo script
  PowerShell, ma quest'ultimo resta il default più maturo per l'uso nativo.
- Su **Linux** (non Docker Desktop), `host.docker.internal` richiede la riga
  `extra_hosts: host.docker.internal:host-gateway` già presente in
  `docker-compose.yml`. Su Docker Desktop (Windows/Mac) funziona anche senza.
- Il proxy nmap esegue i comandi che riceve: non esporlo su reti non
  fidate senza `NMAP_PROXY_TOKEN` configurato.
- Il server Flask nel container resta quello di sviluppo (`app.run`), come
  in uso nativo — per un deployment di produzione andrebbe messo dietro un
  WSGI server dedicato (es. gunicorn) e un reverse proxy.

## Sviluppo/debug del container

```
docker compose logs -f webapp        # segue i log dell'app
docker compose exec webapp bash      # shell dentro il container
docker compose down                  # ferma tutto (i dati Postgres restano nel volume postgres_data)
docker compose down -v               # ferma tutto e CANCELLA anche i dati Postgres
```
