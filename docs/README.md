# Network Inventory — ised.net

Applicazione web (Flask + AdminLTE) che scansiona una rete con **nmap**,
registra host/servizi/OS in **SQLite**, li classifica per tipo di
dispositivo tramite **LLM** (Ollama/Groq/Gemini con fallback automatico),
associa **CVE reali** ai servizi rilevati (NVD ufficiale + cache locale) e
mappa l'esposizione dei singoli host sulla matrice **MITRE ATT&CK**
ufficiale. Tutte le operazioni si avviano dalla UI web, senza comandi
manuali da terminale.

## Indice documentazione

- [ARCHITECTURE.md](ARCHITECTURE.md) — moduli, flusso dati, schema database
- [SETUP.md](SETUP.md) — installazione, dipendenze, chiavi API
- [PROMPT.md](PROMPT.md) — specifica completa per ricreare l'applicazione da zero con un assistente AI

## Avvio rapido

```
pip install -r requirements.txt
python app.py
```

Apri `http://127.0.0.1:5200`. Dalla pagina **Operazioni** puoi:

1. **Aggiornare la scansione** — estrae gli IP "up" da `data/*.xml` (output
   nmap ping-sweep) e scansiona (OS/servizi) quelli nuovi
2. **Classificare con AI** — determina tipo dispositivo, vendor e ruoli per
   ogni host
3. **Scansionare le vulnerabilità** — associa le CVE note ai servizi con CPE
   rilevata (fonte primaria: NVD)
4. **Mappare la matrice MITRE ATT&CK** — scarica (una volta) la matrice
   ufficiale e mappa servizi/vulnerabilità/tipo dispositivo di ogni host
   sulle tecniche ATT&CK applicabili, consultabile in **Matrice ATT&CK**

## Struttura del progetto

```
app.py                  Applicazione Flask (routing, API, job runner)
scanner_db.py            Schema SQLite e funzioni di accesso al DB
nmap_parser.py            Parser XML output nmap (CPE, script NSE, OS match)
classify.py               Classificazione euristica device_type (fallback senza AI)
extract_up_ips.py         Estrae IP "up" da uno o più file data/*.xml
scan_and_store.py         Orchestratore scansione nmap -sV -O -sC a batch
run_rescan.py             Concatena extract_up_ips.py + scan_and_store.py --resume

llm_common.py             Eccezioni/prompt condivisi tra i provider AI
groq_client.py            Client Groq (llama-3.3-70b-versatile)
gemini_client.py          Client Gemini (gemini-2.5-flash)
ollama_client.py          Client Ollama Cloud/locale (nemotron-3-super:cloud)
classify_devices.py       Orchestratore classificazione AI con fallback multi-provider
enrich.py                  Arricchimento evidenze (banner HTTP, share SMB, banner TCP)

nvd_client.py              Client API NVD (CVE ufficiali per CPE)
cve_lookup.py              Parsing output nmap/vulners + cache CVE (get/merge)
vuln_scan.py               Orchestratore scansione vulnerabilità (NVD + fallback vulners)
import_cve_cache.py        Import manuale cache CVE da file CSV/JSON

attack_data.py             Download/parsing/cache della matrice ufficiale MITRE ATT&CK
attack_mapping.py          Regole euristiche servizi/vulnerabilità/device_type -> tecniche ATT&CK
attack_scan.py             Orchestratore mappatura ATT&CK su tutti gli host

job_lock.py                Lock file basato su PID per i job in background

templates/                 Template Jinja (AdminLTE 3, DataTables server-side)
instance/inventory.db      Database SQLite (non versionato)
instance/attack_enterprise.json  Cache locale della matrice ufficiale MITRE ATT&CK (~47MB, non versionato)
data/*.xml                 Output nmap ping-sweep da cui si estraggono gli IP (non versionato)
```

## Sicurezza / dati sensibili

- Le chiavi API (`.groq_api_key`, `.gemini_api_key`, `.ollama_api_key`,
  `.nvd_api_key`) e il database (`instance/`) **non sono versionati**
  (`.gitignore`)
- I dati di scansione (IP, hostname, vulnerabilità della rete interna) non
  vanno pubblicati in repository pubblici
