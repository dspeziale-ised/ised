# Architettura

## Flusso dati end-to-end

```
0. discovery (nmap -sn a 256 subnet /16, in parallelo)  →  data/*.xml
   (scripts/nmap-discovery-10net.ps1 in uso nativo, discovery_scan.py in Docker)
1. extract_up_ips.py                        →  up_ips.txt (IP "up", uniti/deduplicati da TUTTI i file data/*.xml)
2. scan_and_store.py --resume                →  instance/inventory.db (hosts, os_matches, services, service_scripts, scans)
   (nmap -sV -O -sC a batch, salta gli IP già presenti se --resume)
3. classify_devices.py                       →  hosts.device_type/device_vendor + host_roles
   (raggruppa per fingerprint identico, un LLM per gruppo, fallback multi-provider)
4. vuln_scan.py                              →  cve_cache + host_vulnerabilities
   (raggruppa per CPE identica, NVD diretto per CPE, fallback nmap --script vulners)
5. attack_scan.py                            →  attack_tactics/attack_techniques + host_attack_techniques
   (scarica/cacha la matrice ufficiale MITRE ATT&CK, poi mappa servizi/vulnerabilità/
    tipo dispositivo di ogni host sulle tecniche applicabili, euristica locale)

In parallelo, sempre attivi in background:
- host_monitor.py     →  host_status_checks (ping-sweep periodico, storico raggiungibilità)
- report_schedule.py  →  genera/invia un report PDF quando la schedulazione lo richiede
```

Tutti i passi (0-5) sono avviabili dalla UI web (pagina **Amministrazione**,
`/admin`), non richiedono l'uso del terminale. Il passo 0 (discovery) è
l'unico che può richiedere ore su una rete /8: viene eseguito come job in
background con log/stop, non blocca l'interfaccia.

## Il meccanismo "job" (background task da UI)

Sei operazioni lunghe (`discovery`, `rescan`, `classify`, `vuln`, `attack`,
`customscan`) sono gestite da un meccanismo comune in `app.py`:

- `JOBS = {"discovery": {...}, "rescan": {...}, "classify": {...}, "vuln": {...}, "attack": {...}, "customscan": {...}}`
  — per ciascuna: comando da eseguire, file di lock, file di log
- `start_job(name)` — se non già in corso, lancia lo script come
  `subprocess.Popen` in background, scrivendo stdout/stderr su un file di
  log. Scrive subito il PID nel lock file (necessario per script non
  Python come lo storico `nmap-discovery-10net.ps1`, che non gestisce da
  solo un `JobLock`)
- `stop_job(name)` — termina il job in corso con `taskkill /F /T /PID <pid>`:
  il flag `/T` termina anche l'intero albero di processi figli (es. nmap
  lanciato da `scan_and_store.py`), necessario su Windows dove terminare solo
  il processo padre lascia i figli orfani ancora in esecuzione
- `is_job_running(name)` — verifica se già attivo tramite:
  1. Riferimento al processo in memoria (`_job_processes`, se lo stesso
     processo Flask ha avviato il job)
  2. **Lock file con PID** (`job_lock.py`, `JobLock`): ogni script Python
     scrive il proprio PID in un file all'avvio e lo rimuove alla fine.
     Verificato leggendo il file e controllando con `tasklist` se quel PID
     è ancora vivo — sopravvive ai riavvii del processo Flask (es.
     auto-reload in debug mode), a differenza di una variabile in memoria
  3. `JOB_FALLBACK_CHECK` per `rescan`/`discovery`: query sulla command
     line dei processi per il nome dello script specifico
     (`scan_and_store.py`, `nmap-discovery-10net.ps1`/`discovery_scan.py`),
     per coprire esecuzioni avviate fuori da questo meccanismo (es. da
     riga di comando). **Non** si usa un generico "nmap.exe è attivo":
     altrimenti un nmap indipendente dell'utente (es. una ping-sweep
     manuale) farebbe scattare un falso positivo
- Endpoint generici: `POST /jobs/<name>/start`, `POST /jobs/<name>/stop`,
  `GET /api/jobs/<name>/status`. `JOB_ARGS_BUILDERS`/`build_discovery_args`
  costruiscono gli argomenti CLI dai campi del form (es. BatchSize/OutputDir
  per discovery); `JOB_FORCE_FLAG` traduce il checkbox "force" generico nel
  flag corretto per lo script (`--force`, o `--update-matrix` per `attack`)
- `JOB_VALIDATORS` (es. `customscan`, che richiede un target obbligatorio):
  eseguiti **prima** di `start_job`, ritornano un messaggio d'errore invece
  di far partire un processo condannato a fallire subito
- Frontend: `templates/_jobs_script.html` (funzione `initJobWidgets`)
  cerca nella pagina corrente elementi `.job-start-btn[data-job=X]`,
  `.job-stop-btn[data-job=X]`, `.job-status-badge[data-job=X]`,
  `.job-log[data-job=X]` e li collega automaticamente agli endpoint sopra,
  con polling ogni 4s. Supporta anche campi form aggiuntivi (`cfg.fields`)
  per job con parametri custom come `discovery`

**Discovery iniziale**: in uso nativo lancia `scripts/nmap-discovery-10net.ps1`
(PowerShell, `Start-Job` per il parallelismo). In modalità container
(`NMAP_PROXY_URL` impostata, niente PowerShell/nmap nel container) lancia
invece `discovery_scan.py`, un'implementazione Python equivalente
(`ThreadPoolExecutor`) che passa da `nmap_proxy_client` — la scelta fra i
due è automatica (`USE_PYTHON_DISCOVERY` in `app.py`).

## Scheduler in background (thread interni, non job)

Due funzionalità girano come thread daemon avviati in `app.py` (non tramite
il meccanismo job sopra, dato che sono cicli continui e non operazioni
one-shot):

- **Monitoraggio** (`_monitor_scheduler_loop`, ogni 30s controlla se è
  "due" secondo `monitor_schedule.json`): esegue `host_monitor.run_monitor_cycle`
  quando l'intervallo configurato è trascorso. Attivo di default.
- **Report periodici** (`_report_scheduler_loop`, ogni 15 minuti controlla
  `report_schedule.json`): genera e invia un report PDF quando l'intervallo
  configurato è trascorso. Disattivo di default.

Entrambi si avviano una sola volta anche col reloader di Flask in debug
mode (guardia su `WERKZEUG_RUN_MAIN`, lo stesso principio usato per i job).

## Schema database (SQLite o PostgreSQL — vedi "Backend database" sotto)

```
hosts
  id, ip (unique), hostname, mac_address, mac_vendor, state, timed_out,
  status_reason, ttl,                   -- reason/TTL della risposta nmap (echo-reply, syn-ack, ...)
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

host_status_checks   (host_id →) status ('up'/'down'), checked_at    -- storico raggiungibilità, vedi "Monitoraggio"
```

Note di design:
- `device_type`/`device_vendor` sono i campi **operativi** usati ovunque
  (badge, filtri, dashboard, mappa di rete). Vengono popolati dall'euristica
  in `classify.py` durante lo scan, poi eventualmente sovrascritti dalla
  classificazione AI (`classify_devices.py`), a meno che
  `device_type_manual = 1`
- `status_reason`/`ttl`: il `reason` (`echo-reply` = risposta a ping ICMP,
  `syn-ack` = porta TCP aperta, ...) e il TTL con cui è arrivata la risposta
  di stato nmap. `classify.guess_ttl_baseline(ttl)` stima il TTL di partenza
  (64=Linux/Unix, 128=Windows, 255=apparato di rete) e gli hop attraversati
  (baseline - ttl); usato come euristica di riserva quando OS match/porte
  non bastano (es. un host visto solo in ping-sweep, senza scansione porte),
  insieme alla convenzione "IP che finisce per .1 = spesso un gateway"
- `ai_device_type`/`ai_confidence`/`ai_reasoning`/`ai_provider` sono un
  **registro separato** di cosa ha detto l'AI (per audit/debug), distinto
  dal campo operativo
- `host_roles` separa il tipo principale (es. "server linux") dai ruoli
  specifici (es. "web server nginx", "application server apache tomcat"),
  invece di un'unica stringa composita
- `cve_cache` è la cache **per CPE** (non per host): molti host condividono
  la stessa CPE (stesso prodotto/versione), quindi il lookup avviene una
  sola volta per CPE e si applica a tutti gli host che la condividono
- `host_status_checks` registra una riga solo al **cambio di stato** o dopo
  un "battito" periodico (default ogni 60 minuti anche senza cambi), per
  contenere la crescita della tabella pur mantenendo uno storico utile per
  calcolare l'uptime% (ricostruito dagli intervalli fra check consecutivi,
  vedi `scanner_db.host_uptime_percent`)
- Tutte le migrazioni (`ensure_ai_columns`, `ensure_service_columns`,
  `ensure_fingerprint_columns`, `ensure_monitor_tables`,
  `ensure_attack_tables`) sono additive e idempotenti — sicure da chiamare
  ripetutamente su un DB già popolato, e usate sia per SQLite sia per Postgres

## Backend database: SQLite (nativo) o PostgreSQL (Docker)

`scanner_db.connect(db_path)` sceglie il backend in base alla stringa
passata: un percorso file → SQLite (comportamento di sempre); una URL
`postgresql://...` → PostgreSQL, usato quando l'app gira in Docker
(`DATABASE_URL` impostata, vedi [DOCKER.md](DOCKER.md)).

Per evitare di duplicare tutte le query, `PgConnection`/`_PgCursor` in
`scanner_db.py` avvolgono `psycopg2` con un'interfaccia compatibile con
l'uso di `sqlite3.Connection` in questo progetto:
- `conn.execute(sql, params)` diretto (non solo su un cursore), placeholder
  `?` tradotti in `%s`
- righe leggibili come dict (`row["col"]`), anche iterando direttamente sul
  cursore (`for row in conn.execute(...)`, come fa `sqlite3.Cursor`)
- `.lastrowid` emulato: un `INSERT` in una tabella con colonna `id` (elenco
  in `_TABLES_WITH_ID`) si vede aggiungere automaticamente `RETURNING id`
- `.executescript(sql)` esegue lo script DDL multi-statement in un colpo
  solo, dopo `_adapt_schema_for_postgres` (traduce `INTEGER PRIMARY KEY
  AUTOINCREMENT` in `SERIAL PRIMARY KEY`, l'unica differenza di sintassi
  DDL rilevante fra i due dialetti in questo schema)

Altre differenze di dialetto gestite:
- `LIKE` vs `ILIKE` (Postgres è case-sensitive di default): `app.py` sceglie
  `LIKE_OP` in base al backend e lo usa nelle query di ricerca
- `datetime('now')` lato SQL è stato sostituito ovunque da un timestamp
  Python (`_now()`, ISO 8601) passato come parametro — le colonne sono TEXT
  su entrambi i backend, quindi non serve nessuna funzione SQL specifica
- introspezione colonne: `PRAGMA table_info` (SQLite) vs
  `information_schema.columns` (Postgres), astratta in `_get_columns`
- `INSERT OR IGNORE` (solo SQLite) sostituito da `ON CONFLICT DO NOTHING`,
  supportato da entrambi i backend
- durata media batch in `get_scan_progress()`: `julianday()` (SQLite) vs
  `EXTRACT(EPOCH FROM ...)` (Postgres), scelto in base a `DB_IS_POSTGRES`

Gli script CLI (`classify_devices.py`, `vuln_scan.py`, `attack_scan.py`,
`host_monitor.py`, `scan_and_store.py`, `import_cve_cache.py`) risolvono il
DB target con `scanner_db.resolve_db_target(default_sqlite_path)`: usa
`DATABASE_URL` se impostata (coerente con l'app web), altrimenti il file
SQLite di default — nessun flag `--db` da passare manualmente nei job
avviati dalla UI.

## Proxy nmap: nmap fuori da Docker

Su Docker Desktop/Windows, i driver raw-socket (Npcap) richiesti da nmap
non funzionano in modo affidabile dentro il namespace di rete di un
container. Tutti gli script che invocano nmap (`scan_and_store.py`,
`vuln_scan.py`, `enrich.py`, `host_monitor.py`, `discovery_scan.py`,
`custom_scan.py`) non
chiamano `subprocess.run(["nmap", ...])` direttamente, ma passano da
`nmap_proxy_client.run_nmap(args, ...)`:

- se `NMAP_PROXY_URL` **non** è impostata (uso nativo, di default):
  comportamento identico a sempre, `subprocess.run(["nmap", *args], ...)`
  in locale
- se è impostata (modalità container): inoltra via HTTP POST a
  `nmap_proxy_server.py`, che gira nativamente sull'host Windows con nmap
  vero, autenticato con un token condiviso (header `X-Proxy-Token`)

Dato che il vero processo nmap gira su una macchina diversa dal chiamante
in modalità proxy, il client traduce due pattern di I/O su file usati nel
progetto:
- `-oX <path>` (path reale, non `-`): tradotto in `-oX -` verso il proxy,
  l'XML ricevuto via stdout (base64 nel JSON di risposta, per sicurezza
  sull'encoding) viene scritto nel path locale originariamente richiesto
- `-iL <path>`: il file locale con la lista IP viene letto dal client e i
  target passati al proxy come argomenti posizionali diretti

`subprocess.TimeoutExpired` viene sollevata anche in modalità proxy (il
proxy la segnala con `timed_out: true` nella risposta), così il codice
chiamante esistente (che la intercetta) funziona invariato in entrambe le
modalità — vedi [DOCKER.md](DOCKER.md) per l'architettura completa e come
avviare il proxy.

## Scansione nmap personalizzata

`custom_scan.py` (job `customscan`, pagina **Inventario → Scansione nmap**):
a differenza di `scan_and_store.py` (set fisso di flag, pensato per batch da
file) accetta target e argomenti nmap **arbitrari**, costruiti dal form
(`templates/custom_scan.html`, che espone quasi tutte le categorie di
opzioni nmap via JS in un'unica stringa `args`, più un campo di argomenti
extra per qualunque flag non coperto esplicitamente) o passati a mano da
CLI. Usa la stessa pipeline di `scan_and_store.py` (run nmap → parse XML →
classifica → upserta host → log scan), estratta in `scan_pipeline.py` per
non duplicarla identica nei due script: `scan_pipeline.run_and_store(cmd,
xml_out, conn, ...)` esegue `nmap_proxy_client.run_nmap`, poi
`nmap_parser.parse_nmap_xml`, `classify.classify_device`,
`scanner_db.upsert_host` per ogni host 'up' e infine `scanner_db.log_scan`
— non solleva per timeout/errori nmap o XML troncato, li registra come
stato del batch e prosegue con l'XML parziale eventualmente già scritto.
Flag di output/input file
(`-oX`/`-oN`/`-oG`/`-oA`/`-iL`) digitati per errore negli argomenti extra
vengono rimossi prima di aggiungere il proprio `-oX` obbligatorio, per
evitare conflitti con nmap (non accetta due `-oX`).

## Effort di rete globale

`scan_effort.py`: tre profili (`low`="Debole", `normal`="Normale",
`fast`="Fast", persistiti come stringa in `instance/scan_effort.json`
tramite `json_settings.py` — lo stesso modulo di load/save-con-default usato
da `monitor_schedule.py`/`report_schedule.py`, centralizzato per non
duplicare la stessa logica di merge/tolleranza a file assente/corrotto in
ogni configurazione), ognuno
con i valori di timing/max-rate/batch-size/porte da usare per una data
"discrezione" verso firewall/IDS. Impostabile con tre pulsanti in cima ad
Amministrazione (`POST /api/scan-effort`).

Due modalità di applicazione, diverse per necessità:
- **live/automatica**: `host_monitor.py` (ciclo di monitoraggio periodico) e
  il fallback `nmap --script vulners` in `vuln_scan.py` non hanno un form
  per scegliere l'effort ad ogni esecuzione (girano in background, senza
  intervento utente) — leggono `scan_effort.current_profile()` direttamente
  ad ogni ciclo/chiamata
- **default pre-compilato**: Discovery iniziale, Aggiorna scansione e
  Scansione nmap hanno già i loro controlli manuali (richiesti in
  precedenza: timing, max-rate, batch size, porte) — l'effort globale ne
  imposta solo il **valore iniziale** nel form (lato server, in
  `admin_panel()`/`nmap_scan_page()`) e nei builder (`build_discovery_args`/
  `build_rescan_args`, come fallback se il campo arriva vuoto/non valido),
  senza togliere la possibilità di scegliere altro per la singola esecuzione

## Monitoraggio: raggiungibilità host con storico

`host_monitor.py`:
1. Raggruppa tutti gli host noti in batch (default 60 IP) e lancia
   `nmap -sn` su ciascun batch (via `nmap_proxy_client`, come sopra)
2. Per ogni host, registra lo stato ('up'/'down') in `host_status_checks`
   **solo se è cambiato** rispetto all'ultimo check noto, o se è passato più
   del "battito" configurato (default 60 minuti) — limita la crescita della
   tabella pur permettendo di calcolare un uptime% accurato
3. Girato periodicamente da un thread interno (`monitor_schedule.json`:
   intervallo, batch size, battito — configurabili da `/monitoring`)

`scanner_db.host_uptime_percent(conn, host_id, since_hours)` ricostruisce
gli intervalli fra check consecutivi (lo stato "vale" fino al check
successivo) e calcola la percentuale di tempo "up" nella finestra
richiesta — necessario perché lo storico è sparso (punto 2 sopra), non un
check ogni minuto.

`scanner_db.hosts_hourly_status(conn, date)` calcola, per ogni host, lo
stato "riportato avanti" per ciascuna delle 24 ore di un giorno (l'ultimo
check noto entro la fine di ogni ora, `None` se non c'è ancora nessun dato)
— usato dalla vista a griglia (tab **Storico** in `/monitoring`, una riga
per host con 24 celle colorate).

## Report PDF + notifiche

`report_generator.py` (reportlab, nessuna dipendenza da binari esterni tipo
wkhtmltopdf) genera un PDF con due sezioni componibili:
- **summary**: stat box, grafico a barre (distribuzione tipo dispositivo,
  reportlab `HorizontalBarChart`), top vulnerabilità per CVSS, esposizione
  MITRE ATT&CK per tattica
- **hosts**: tabella completa di tutti gli host (IP, tipo, OS, porte,
  vulnerabilità), con intestazione ripetuta su ogni pagina

`notify_telegram.py`/`notify_gmail.py` inviano il PDF generato: Telegram via
Bot API (`sendDocument`), Gmail via SMTP con App Password. Entrambi leggono
le credenziali tramite `secrets_store.py` (variabile d'ambiente prima, file
dedicato in `keys/` poi — stesso modulo usato da `groq_client.py`,
`gemini_client.py`, `ollama_client.py`, `nvd_client.py`,
`nmap_proxy_client.py`/`nmap_proxy_server.py`, centralizzato per non
duplicare lo stesso meccanismo in ogni client), e sono opzionali — l'app
segnala chiaramente in UI se non sono configurati, senza bloccare le altre
funzionalità.

`report_schedule.py` + il thread `_report_scheduler_loop` in `app.py`
permettono l'invio automatico periodico (6h/12h/24h/settimanale),
configurabile dalla tab **Report** in Amministrazione.

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

`attack_scan.py` (job `attack` in Amministrazione):
1. Garantisce che la matrice sia caricata (download solo se mancante, o
   sempre con `--update-matrix`)
2. Ricalcola la mappatura per **tutti** gli host ad ogni esecuzione (nessuna
   chiamata esterna oltre l'eventuale download matrice, quindi il costo è
   trascurabile — a differenza di classify/vuln non c'è un concetto di "solo
   i nuovi")

La vista `/attack-matrix` mostra ogni tattica come pannello collassabile
(non una griglia a scroll orizzontale — sostituita perché scomoda con
molte colonne), con le tecniche come chip colorati per numero di host
esposti; click su una tecnica apre il dettaglio degli host coinvolti e del
motivo della mappatura.

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

`import_cve_cache.py` / upload da UI (tab Report in Amministrazione)
permettono di **pre-popolare** la cache da un file CSV/JSON esterno, con
**merge** (non sovrascrittura) sulle CVE già in cache per la stessa CPE.

## Route Flask principali

| Route | Metodo | Descrizione |
|---|---|---|
| `/` | GET | Dashboard: stat box, stato scansione live, distribuzione tipo dispositivo |
| `/hosts`, `/api/hosts` | GET | Elenco host (DataTable server-side, filtri tipo dispositivo/famiglia OS/OS) |
| `/hosts/<ip>` | GET | Dettaglio host: OS match, servizi, ruoli AI, vulnerabilità, tecniche ATT&CK, storico raggiungibilità, TTL/reason |
| `/hosts/<ip>/device-type` | POST | Modifica manuale device_type (imposta `device_type_manual=1`) |
| `/services`, `/api/services` | GET | Servizi aggregati per porta/nome |
| `/services/hosts`, `/api/service-hosts` | GET | Host che espongono un dato servizio |
| `/network-map`, `/api/network-map` | GET | Mappa di rete: albero HTML collassabile sito/subnet/host |
| `/vulnerabilities`, `/api/vulnerabilities` | GET | CVE rilevate (DataTable, filtro CVSS minimo) |
| `/attack-matrix` | GET | Pannelli MITRE ATT&CK per tattica, colorati per esposizione |
| `/api/attack-matrix/technique/<id>/hosts` | GET | Host esposti a una data tecnica ATT&CK |
| `/monitoring` | GET | Stato raggiungibilità host (tab Stato attuale + Storico a 24 led) |
| `/api/monitoring`, `/api/monitoring/host/<ip>/history`, `/api/monitoring/hourly` | GET | Dati per le viste di monitoraggio |
| `/monitoring/run-now` | POST | Esegue subito un ciclo di monitoraggio |
| `/api/monitor-schedule` | GET/POST | Configurazione schedulazione monitoraggio |
| `/reports/generate`, `/reports/send` | GET/POST | Genera/invia un report PDF |
| `/api/report-schedule`, `/api/notify-status` | GET/POST | Configurazione schedulazione report, stato Telegram/Gmail |
| `/scans`, `/api/scans` | GET | Log dei batch di scansione nmap |
| `/admin` | GET | Amministrazione: effort globale + 6 tab (discovery/rescan/classify/vuln/attack/report) |
| `/nmap-scan` | GET | Form di scansione nmap personalizzata (Inventario) |
| `/jobs/<name>/start` | POST | Avvia un job in background (`discovery`\|`rescan`\|`classify`\|`vuln`\|`attack`\|`customscan`) |
| `/jobs/<name>/stop` | POST | Interrompe un job in corso (intero albero di processi) |
| `/api/jobs/<name>/status` | GET | Stato + log di un job |
| `/api/scan-status` | GET | Progresso dettagliato della scansione (% completamento, ETA) |
| `/api/scan-effort` | GET/POST | Legge/imposta l'effort di rete globale (Debole/Normale/Fast) |

## Frontend

- **AdminLTE 3** (tema chiaro di default, toggle scuro persistente via
  `localStorage`) + Bootstrap 4, caricati da CDN (jsdelivr/cdnjs)
- **Sidebar a menu/sottomenu** (Inventario, Monitoraggio, Sicurezza,
  Sistema), ciascuno con icona propria; il sottomenu della sezione attiva
  si apre da solo in base a `request.endpoint`
- **DataTables** (server-side processing) per tutte le tabelle elenco:
  ordinamento/ricerca/paginazione gestiti lato server (`dt_params()`,
  `dt_order_sql()` in `app.py`), CDN da `cdn.datatables.net` (jsdelivr non
  distribuisce i plugin DataTables per admin-lte, causa 404)
- **Font PT Sans Narrow** (Google Fonts) + controllo dimensione carattere
  (A-/A+, CSS custom property `--app-font-scale` su `<html>`)
- **Mappa di rete**: albero HTML/CSS/JS puro (nessuna libreria SVG come
  D3.js — sostituita perché causava una UI illeggibile con centinaia di
  nodi), stesso pattern del menu collassabile della sidebar AdminLTE
- **Matrice ATT&CK**: pannelli collassabili per tattica (non una griglia a
  scroll orizzontale — sostituita perché scomoda), nessuna libreria
  matrice/grafo esterna
- **Storico monitoraggio**: griglia CSS pura (24 celle colorate per riga),
  caricata via fetch al primo accesso alla tab (non al caricamento pagina)
