# Architettura

## Flusso dati end-to-end

```
1. nmap -sn (ping sweep, manuale/esterno)  →  data/*.xml
2. extract_up_ips.py                        →  up_ips.txt (IP "up", uniti/deduplicati da TUTTI i file data/*.xml)
3. scan_and_store.py --resume                →  instance/inventory.db (hosts, os_matches, services, service_scripts, scans)
   (nmap -sV -O -sC a batch, salta gli IP già presenti se --resume)
4. classify_devices.py                       →  hosts.device_type/device_vendor + host_roles
   (raggruppa per fingerprint identico, un LLM per gruppo, fallback multi-provider)
5. vuln_scan.py                              →  cve_cache + host_vulnerabilities
   (raggruppa per CPE identica, NVD diretto per CPE, fallback nmap --script vulners)
6. attack_scan.py                            →  attack_tactics/attack_techniques + host_attack_techniques
   (scarica/cacha la matrice ufficiale MITRE ATT&CK, poi mappa servizi/vulnerabilità/
    tipo dispositivo di ogni host sulle tecniche applicabili, euristica locale)
```

I passi 2-6 sono tutti avviabili dalla UI web (pagina **Operazioni**), non
richiedono l'uso del terminale. Il passo 1 (ping sweep iniziale, tipicamente
`nmap -sn 10.0.0.0/8`) resta manuale/esterno perché scansiona range enormi e
può richiedere ore/giorni; il suo output XML va semplicemente depositato in
`data/`.

## Il meccanismo "job" (background task da UI)

Quattro operazioni lunghe (`rescan`, `classify`, `vuln`, `attack`) sono
gestite da un meccanismo comune in `app.py`:

- `JOBS = {"rescan": {...}, "classify": {...}, "vuln": {...}, "attack": {...}}`
  — per ciascuna: comando da eseguire, file di lock, file di log
- `start_job(name)` — se non già in corso, lancia lo script come
  `subprocess.Popen` in background, scrivendo stdout/stderr su un file di log
- `stop_job(name)` — termina il job in corso con `taskkill /F /T /PID <pid>`:
  il flag `/T` termina anche l'intero albero di processi figli (es. nmap
  lanciato da `scan_and_store.py`), necessario su Windows dove terminare solo
  il processo padre lascia i figli orfani ancora in esecuzione
- `is_job_running(name)` — verifica se già attivo tramite:
  1. Riferimento al processo in memoria (`_job_processes`, se lo stesso
     processo Flask ha avviato il job)
  2. **Lock file con PID** (`job_lock.py`, `JobLock`): ogni script scrive il
     proprio PID in un file all'avvio e lo rimuove alla fine. Verificato
     leggendo il file e controllando con `tasklist` se quel PID è ancora
     vivo — sopravvive ai riavvii del processo Flask (es. auto-reload in
     debug mode), a differenza di una variabile in memoria
  3. Per il job `rescan` soltanto: fallback su "esiste un processo
     scan_and_store.py in esecuzione" (via query WMI sulla command line dei
     processi python), per coprire scansioni avviate da riga di comando
     fuori da questo meccanismo. **Non** si usa un generico "nmap.exe è
     attivo": altrimenti un nmap indipendente dell'utente (es. una
     ping-sweep manuale) farebbe scattare un falso positivo
- Endpoint generici: `POST /jobs/<name>/start`, `POST /jobs/<name>/stop`,
  `GET /api/jobs/<name>/status`. Il flag "force" del form di avvio viene
  tradotto nel flag CLI corretto per lo script (`JOB_FORCE_FLAG`): normalmente
  `--force`, ma `--update-matrix` per il job `attack` (dove non si tratta di
  "riclassificare" ma di ri-scaricare la matrice ufficiale MITRE)
- Frontend: `templates/_jobs_script.html` (funzione `initJobWidgets`)
  cerca nella pagina corrente elementi `.job-start-btn[data-job=X]`,
  `.job-stop-btn[data-job=X]`, `.job-status-badge[data-job=X]`,
  `.job-log[data-job=X]` e li collega automaticamente agli endpoint sopra,
  con polling ogni 4s

## Schema database (SQLite, `instance/inventory.db`)

```
hosts
  id, ip (unique), hostname, mac_address, mac_vendor, state, timed_out,
  distance, os_name, os_accuracy, os_family, os_gen,
  device_type, device_vendor,          -- tipo/vendor "operativo", usato in tutta la UI
  device_type_manual,                   -- 1 se impostato a mano dall'utente (protegge da sovrascrittura)
  ai_device_type, ai_confidence, ai_reasoning, ai_provider, ai_classified_at,  -- audit della classificazione AI
  fingerprint_signature,                -- hash di (os + porte/servizi aperti), usato per raggruppare host identici
  last_scanned, scan_duration, raw_xml_path

os_matches        (host_id →) name, accuracy, os_family, os_gen, os_type, vendor
services          (host_id →) port, protocol, state, service_name, product, version, extrainfo, tunnel, cpe
service_scripts   (service_id →) script_id, output, collected_at         -- output script NSE (-sC)
host_roles        (host_id →) role, source, created_at                   -- sotto-tipi/ruoli AI (es. "web server nginx")
scans             started_at, finished_at, target_count, xml_path, command, status  -- log batch scan_and_store.py

cve_cache         cpe (PK), cve_json, fetched_at         -- cache CVE per CPE (lista di {id, cvss, url})
host_vulnerabilities  (host_id →) port, cpe, cve_id, cvss, url, source, detected_at

attack_tactics             shortname (PK), name, description, url, sort_order      -- le 15 tattiche ATT&CK Enterprise
attack_techniques          technique_id (PK, es. 'T1021.001'), name, description, url,
                            is_subtechnique, parent_technique_id, platforms          -- tecniche/sotto-tecniche ufficiali
attack_technique_tactics   (technique_id, tactic_shortname) PK composita              -- relazione N:M tecnica<->tattica
host_attack_techniques     (host_id →) technique_id, reason, source, detected_at      -- mappatura euristica per host
```

Note di design:
- `device_type`/`device_vendor` sono i campi **operativi** usati ovunque
  (badge, filtri, dashboard, mappa di rete). Vengono popolati dall'euristica
  in `classify.py` durante lo scan, poi eventualmente sovrascritti dalla
  classificazione AI (`classify_devices.py`), a meno che
  `device_type_manual = 1`
- `ai_device_type`/`ai_confidence`/`ai_reasoning`/`ai_provider` sono un
  **registro separato** di cosa ha detto l'AI (per audit/debug), distinto
  dal campo operativo
- `host_roles` separa il tipo principale (es. "server linux") dai ruoli
  specifici (es. "web server nginx", "application server apache tomcat"),
  invece di un'unica stringa composita
- `cve_cache` è la cache **per CPE** (non per host): molti host condividono
  la stessa CPE (stesso prodotto/versione), quindi il lookup avviene una
  sola volta per CPE e si applica a tutti gli host che la condividono
- Tutte le migrazioni (`ensure_ai_columns`, `ensure_service_columns`) sono
  additive e idempotenti — sicure da chiamare ripetutamente su un DB già
  popolato

## Classificazione AI: raggruppamento e fallback

`classify_devices.py`:
1. Raggruppa gli host per `fingerprint_signature` = hash di
   `(os_name, os_family, os_gen, mac_vendor, porte/servizi aperti ordinati)`
   — host con fingerprint identico sono trattati come lo stesso dispositivo,
   una sola chiamata AI per gruppo (non per host)
2. Per ogni gruppo, arricchisce con evidenze extra (`enrich.py`: banner
   HTTP, condivisioni SMB via script NSE, banner TCP grezzi su porte
   tcpwrapped) — anche questo una volta per gruppo
3. Più gruppi vengono raggruppati in un'unica richiesta HTTP (batch, default
   6 gruppi) per ridurre il numero di chiamate
4. Catena provider (default `ollama -> groq -> gemini`, configurabile via
   `--providers`): se un provider fallisce (quota esaurita, errore, timeout,
   JSON malformato), si passa al successivo **per lo stesso batch**. Se
   TUTTI falliscono, il batch viene saltato ma il batch **successivo**
   ricomincia dal primo provider (bug storico: un fallimento totale non
   deve disabilitare i batch restanti)
5. Se un batch supera i limiti di token del provider (`LLMTooLargeError`),
   viene diviso in due e ritentato (stesso provider)
6. Il parsing della risposta (`llm_common.extract_json`) è tollerante: se il
   testo attorno al JSON è malformato (tipico dei modelli "reasoning" come
   Nemotron), isola comunque l'array `"results"` con una scansione a
   parentesi bilanciate

Per default classifica solo gli host con `ai_device_type IS NULL` (nuovi);
`--force`/`--all` per riclassificare tutto.

## Vulnerability scanning: NVD diretto + cache

`vuln_scan.py`:
1. Raggruppa i servizi per CPE identica (`services.cpe`, popolata da nmap
   `-sV` quando riconosce prodotto/versione con sufficiente confidenza)
2. Per ogni CPE non ancora in cache (o scaduta, default 30 giorni):
   interroga **direttamente l'API NVD** (`nvd_client.py`) convertendo la CPE
   2.2 di nmap (`cpe:/a:vendor:product:version`) nel formato URI 2.3
   richiesto da NVD (`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`) — non
   serve nessuna scansione dal vivo, solo la stringa CPE già nel DB
3. Se NVD non risponde o non trova nulla, fallback su
   `nmap --script vulners <host_rappresentativo>` (interroga vulners.com)
4. Il risultato (lista di `{id, cvss, url}`) viene cachato per CPE
   (`cve_cache`) e applicato a **tutti** gli host che condividono quella CPE
5. Rate limiting NVD: pausa conservativa tra le richieste (6.5s senza API
   key, 0.7s con key — il limite pubblico NVD è 5 richieste/30s senza key,
   50/30s con key gratuita)

`import_cve_cache.py` / upload da UI (`/vuln/import-cache`) permettono di
**pre-popolare** la cache da un file CSV/JSON esterno, con **merge** (non
sovrascrittura) sulle CVE già in cache per la stessa CPE.

## MITRE ATT&CK: matrice ufficiale + mappatura euristica

`attack_data.py`:
1. Scarica il dataset ufficiale MITRE ATT&CK Enterprise (STIX 2.1,
   `github.com/mitre/cti`, ~47MB) e lo cacha in
   `instance/attack_enterprise.json` (non riscaricato ad ogni avvio)
2. Estrae tattiche (`x-mitre-tactic`), tecniche/sotto-tecniche
   (`attack-pattern`, escludendo revoked/deprecated) e la loro relazione
   N:M, popolando `attack_tactics`/`attack_techniques`/`attack_technique_tactics`
3. L'ordine delle tattiche (colonne della matrice) segue `tactic_refs`
   dell'oggetto `x-mitre-matrix` ufficiale, non un ordine arbitrario

`attack_mapping.py` contiene le regole euristiche (verificate contro il
dataset reale, non tecniche inventate): porta/servizio esposto ->
tecnica ATT&CK plausibile (es. porta 3389 -> T1021.001 "Remote Desktop
Protocol"), CVE critiche note -> T1210 "Exploitation of Remote Services",
tipo dispositivo (router/switch/firewall) -> T1599/T1016. **Non è
un'analisi di exploit reali**: segnala esposizione potenziale in base a
cosa un host espone sulla rete.

`attack_scan.py` (job `attack` in Operazioni):
1. Garantisce che la matrice sia caricata (download solo se mancante, o
   sempre con `--update-matrix`)
2. Ricalcola la mappatura per **tutti** gli host ad ogni esecuzione (nessuna
   chiamata esterna oltre l'eventuale download matrice, quindi il costo è
   trascurabile — a differenza di classify/vuln non c'è un concetto di "solo
   i nuovi")

La vista `/attack-matrix` mostra una matrice colorata (colonne = tattiche,
celle = tecniche, colore/intensità = numero di host esposti); click su una
cella apre il dettaglio degli host coinvolti e del motivo della mappatura.

## Route Flask principali

| Route | Metodo | Descrizione |
|---|---|---|
| `/` | GET | Dashboard: stat box, stato scansione live, distribuzione tipo dispositivo |
| `/hosts`, `/api/hosts` | GET | Elenco host (DataTable server-side, filtri tipo dispositivo/famiglia OS/OS) |
| `/hosts/<ip>` | GET | Dettaglio host: OS match, servizi, ruoli AI, vulnerabilità, tecniche ATT&CK |
| `/hosts/<ip>/device-type` | POST | Modifica manuale device_type (imposta `device_type_manual=1`) |
| `/services`, `/api/services` | GET | Servizi aggregati per porta/nome |
| `/services/hosts`, `/api/service-hosts` | GET | Host che espongono un dato servizio |
| `/network-map`, `/api/network-map` | GET | Mappa di rete: albero HTML collassabile sito/subnet/host |
| `/vulnerabilities`, `/api/vulnerabilities` | GET | CVE rilevate (DataTable, filtro CVSS minimo) |
| `/vuln/import-cache` | POST | Upload file CSV/JSON per pre-popolare la cache CVE |
| `/api/cve-cache-stats` | GET | Statistiche cache CVE (n. CPE, n. CVE totali) |
| `/attack-matrix` | GET | Matrice MITRE ATT&CK colorata per esposizione |
| `/api/attack-matrix/technique/<id>/hosts` | GET | Host esposti a una data tecnica ATT&CK |
| `/scans`, `/api/scans` | GET | Log dei batch di scansione nmap |
| `/operations` | GET | Pagina unica (4 tab) per avviare rescan/classify/vuln/attack |
| `/jobs/<name>/start` | POST | Avvia un job in background (`rescan`\|`classify`\|`vuln`\|`attack`) |
| `/jobs/<name>/stop` | POST | Interrompe un job in corso (intero albero di processi) |
| `/api/jobs/<name>/status` | GET | Stato + log di un job |
| `/api/scan-status` | GET | Progresso dettagliato della scansione (% completamento, ETA) |

## Frontend

- **AdminLTE 3** (tema chiaro di default, toggle scuro persistente via
  `localStorage`) + Bootstrap 4, caricati da CDN (jsdelivr/cdnjs)
- **DataTables** (server-side processing) per tutte le tabelle elenco:
  ordinamento/ricerca/paginazione gestiti lato server (`dt_params()`,
  `dt_order_sql()` in `app.py`), CDN da `cdn.datatables.net` (jsdelivr non
  distribuisce i plugin DataTables per admin-lte, causa 404)
- **Font PT Sans Narrow** (Google Fonts) + controllo dimensione carattere
  (A-/A+, CSS custom property `--app-font-scale` su `<html>`)
- **Mappa di rete**: albero HTML/CSS/JS puro (nessuna libreria SVG come
  D3.js — sostituita perché causava una UI illeggibile con centinaia di
  nodi), stesso pattern del menu collassabile della sidebar AdminLTE
- **Matrice ATT&CK**: griglia CSS pura (colonne flex scrollabili
  orizzontalmente, una per tattica), nessuna libreria matrice/grafo esterna;
  colore delle celle calcolato lato server in base al numero di host esposti,
  click su una cella apre un modal Bootstrap con l'elenco host via fetch
