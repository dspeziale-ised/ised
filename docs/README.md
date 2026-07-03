# Network Inventory — ised.net

Applicazione web (Flask + AdminLTE) che scansiona una rete con **nmap**,
registra host/servizi/OS in **SQLite o PostgreSQL**, li classifica per tipo
di dispositivo (euristica + **LLM** con fallback Ollama/Groq/Gemini),
associa **CVE reali** ai servizi rilevati (NVD ufficiale + cache locale),
mappa l'esposizione dei singoli host sulla matrice **MITRE ATT&CK**
ufficiale, **monitora periodicamente** la raggiungibilità degli host con
uno storico consultabile, e genera **report PDF** inviabili via Telegram/
Gmail. Tutte le operazioni si avviano dalla UI web (sezione
**Amministrazione**), senza comandi manuali da terminale — con l'eccezione
del ping-sweep iniziale in uso nativo (vedi sotto), automatizzato invece
quando l'app gira in Docker.

## Indice documentazione

- [ARCHITECTURE.md](ARCHITECTURE.md) — moduli, flusso dati, schema database
- [SETUP.md](SETUP.md) — installazione, dipendenze, chiavi API
- [DOCKER.md](DOCKER.md) — esecuzione in container (Postgres + proxy nmap sull'host)
- [PROMPT.md](PROMPT.md) — specifica completa per ricreare l'applicazione da zero con un assistente AI

## Avvio rapido

```
pip install -r requirements.txt
python app.py
```

Apri `http://127.0.0.1:5200`. Dalla pagina **Amministrazione** puoi:

1. **Discovery iniziale** — ping-sweep su tutta `10.0.0.0/8` (256 subnet
   /16 in parallelo), scrive gli XML in `data/`
2. **Aggiornare la scansione** — estrae gli IP "up" da `data/*.xml` e
   scansiona (OS/servizi) quelli nuovi
3. **Classificare con AI** — determina tipo dispositivo, vendor e ruoli per
   ogni host
4. **Scansionare le vulnerabilità** — associa le CVE note ai servizi con CPE
   rilevata (fonte primaria: NVD)
5. **Mappare la matrice MITRE ATT&CK** — scarica (una volta) la matrice
   ufficiale e mappa servizi/vulnerabilità/tipo dispositivo di ogni host
   sulle tecniche ATT&CK applicabili
6. **Report** — genera un PDF (riepilogo + elenco host), lo invia subito o
   pianifica un invio periodico via Telegram/Gmail

In cima alla pagina **Amministrazione** c'è anche l'**effort di rete
globale** (Debole/Normale/Fast, vedi sotto): orchestra quanto sono discrete
tutte le attività di scansione, per non affaticare firewall/IDS.

Da **Inventario → Scansione nmap** si può inoltre lanciare una scansione
nmap libera su target scelti a mano, con (quasi) tutte le opzioni nmap
disponibili in un form (tecnica di scansione, porte, versione/OS, script
NSE, timing, evasione firewall) più un campo di argomenti extra per
qualunque flag non esposto esplicitamente: i risultati confluiscono negli
host con lo stesso meccanismo di classificazione automatica delle altre
scansioni.

Il **Monitoraggio** (raggiungibilità host, storico) parte da solo in
background non appena l'app è in esecuzione — non richiede un avvio manuale.

## Effort di rete globale

Una leva unica (**Debole** / **Normale** / **Fast**), impostabile in cima ad
Amministrazione, che orchestra quanto sono discrete tutte le attività di
scansione verso la rete:

- il **monitoraggio periodico** (`host_monitor.py`) e il **fallback
  vulnerabilità** (`nmap --script vulners` in `vuln_scan.py`) la seguono
  **automaticamente e dal vivo** ad ogni esecuzione (non hanno un form
  dedicato per scegliere l'effort volta per volta);
- **Discovery iniziale**, **Aggiorna scansione** e **Scansione nmap**
  (i job con controlli manuali già esistenti: timing, max-rate, batch
  size/thread paralleli, porte) la usano come **valore pre-compilato** nei
  rispettivi form quando li apri, restando comunque liberamente modificabile
  per la singola esecuzione.

Persistita in `instance/scan_effort.json` (modulo `scan_effort.py`), non
versionata.

## Struttura del progetto

```
app.py                    Applicazione Flask (routing, API, job runner, scheduler)
scanner_db.py              Schema DB e funzioni di accesso — dual-backend SQLite/PostgreSQL
nmap_parser.py              Parser XML output nmap (CPE, script NSE, OS match, reason/TTL)
classify.py                 Classificazione euristica device_type (fallback senza AI, euristica TTL)
extract_up_ips.py           Estrae IP "up" da uno o più file data/*.xml
scan_and_store.py           Orchestratore scansione nmap -sV -O -sC a batch
run_rescan.py               Concatena extract_up_ips.py + scan_and_store.py --resume
discovery_scan.py           Ping-sweep 10.0.0.0/8 a 256 subnet (equivalente Python, usato in Docker)
scripts/nmap-discovery-10net.ps1  Ping-sweep 10.0.0.0/8 (script PowerShell, uso nativo Windows)
custom_scan.py               Scansione nmap libera (target + argomenti a scelta), risultati negli host
scan_effort.py               Effort di rete globale (Debole/Normale/Fast): default per tutti i job di scansione
scan_pipeline.py             Pipeline comune run nmap -> parse -> classifica -> upsert host -> log scan
secrets_store.py              Lettura/scrittura credenziali: env var prima, file in keys/ poi (comune a tutti i client)
json_settings.py              Load/save di config JSON in instance/ con default (comune a schedulazioni/effort)

nmap_proxy_client.py        Client per instradare le chiamate nmap verso il proxy (modalità container)
nmap_proxy_server.py        Proxy HTTP per nmap, gira nativamente sull'host (nmap fuori da Docker)

llm_common.py               Eccezioni/prompt condivisi tra i provider AI
groq_client.py               Client Groq (llama-3.3-70b-versatile)
gemini_client.py             Client Gemini (gemini-2.5-flash)
ollama_client.py             Client Ollama Cloud/locale (nemotron-3-super:cloud)
classify_devices.py         Orchestratore classificazione AI con fallback multi-provider
enrich.py                    Arricchimento evidenze (banner HTTP, share SMB, banner TCP)

nvd_client.py                Client API NVD (CVE ufficiali per CPE)
cve_lookup.py                Parsing output nmap/vulners + cache CVE (get/merge)
vuln_scan.py                 Orchestratore scansione vulnerabilità (NVD + fallback vulners)
import_cve_cache.py          Import manuale cache CVE da file CSV/JSON

attack_data.py               Download/parsing/cache della matrice ufficiale MITRE ATT&CK
attack_mapping.py            Regole euristiche servizi/vulnerabilità/device_type -> tecniche ATT&CK
attack_scan.py                Orchestratore mappatura ATT&CK su tutti gli host

host_monitor.py              Ciclo di controllo raggiungibilità host (ping-sweep a batch)
monitor_schedule.py          Configurazione/stato della schedulazione del monitoraggio

report_generator.py          Generazione report PDF (reportlab): riepilogo + elenco host
notify_telegram.py           Invio documenti/messaggi a un bot Telegram
notify_gmail.py               Invio email con allegato via Gmail SMTP
report_schedule.py           Configurazione/stato della schedulazione dei report

job_lock.py                  Lock file basato su PID per i job in background

templates/                   Template Jinja (AdminLTE 3, DataTables server-side)
instance/inventory.db        Database SQLite (uso nativo, non versionato)
instance/attack_enterprise.json  Cache locale della matrice ufficiale MITRE ATT&CK (~47MB, non versionato)
data/*.xml                   Output nmap ping-sweep da cui si estraggono gli IP (non versionato)
keys/                         Chiavi API/token, un file per credenziale (non versionato)
logs/                         Log dei job in background, un file per job (non versionato)

Dockerfile, docker-compose.yml   Containerizzazione (app + PostgreSQL, nmap resta sull'host)
```

## Sicurezza / dati sensibili

- Le chiavi/token (`keys/groq_api_key`, `keys/gemini_api_key`,
  `keys/ollama_api_key`, `keys/nvd_api_key`, `keys/telegram_bot_token`,
  `keys/telegram_chat_id`, `keys/gmail_address`, `keys/gmail_app_password`,
  `keys/gmail_to`, `keys/nmap_proxy_token`) e il database (`instance/`)
  **non sono versionati** (`.gitignore` esclude l'intera cartella `keys/`)
  — in Docker si passano come variabili d'ambiente (vedi `.env.example` e
  [DOCKER.md](DOCKER.md))
- I dati di scansione (IP, hostname, vulnerabilità della rete interna) non
  vanno pubblicati in repository pubblici
- Il proxy nmap (`nmap_proxy_server.py`) esegue i comandi che riceve: va
  protetto con un token prima di esporlo oltre `127.0.0.1`
