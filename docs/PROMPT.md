# Prompt per ricreare l'applicazione da zero

Testo pensato per essere copiato e incollato in una chat con un assistente
di coding AI, per rigenerare questa applicazione partendo da zero. Include
non solo le funzionalità, ma anche gli accorgimenti scoperti debuggando
problemi reali durante lo sviluppo (sezione finale) — utili per non
ripetere gli stessi errori.

---

## Obiettivo

Crea un'applicazione web Python (Flask) per l'inventario di una rete
aziendale privata (range 10.0.0.0/8), che:

1. Fa **discovery** (ping-sweep automatizzato su tutta la /8) e scansiona la
   rete con **nmap** (OS detection, servizi, script NSE), registrando tutto
   in un database (**SQLite** in uso nativo, **PostgreSQL** se containerizzata)
2. Classifica il **tipo di dispositivo** di ogni host usando un **LLM**
   (con fallback automatico tra più provider: Ollama, Groq, Gemini) più
   un'euristica di riserva basata su porte/OS/TTL della risposta ping
3. Associa alle porte/servizi rilevati le **CVE reali** note (fonte
   ufficiale NVD, con cache locale) e le mappa sulla matrice **MITRE
   ATT&CK** ufficiale
4. **Monitora periodicamente** la raggiungibilità di ogni host, con uno
   storico consultabile (uptime%, griglia oraria)
5. Genera **report PDF** su richiesta o in automatico, inviabili via
   **Telegram**/**Gmail**
6. Espone tutto tramite una **web UI** (Flask + AdminLTE 3 + DataTables),
   dalla quale si avviano tutte le operazioni — **nessun comando da
   terminale richiesto** per l'uso quotidiano
7. È **containerizzabile** (Docker + docker-compose): nmap resta fuori dal
   container (problemi noti coi driver raw-socket dentro Docker su
   Windows), le scansioni passano da un proxy HTTP che gira nativamente
   sull'host

## Stack tecnico

- Backend: Python 3 + Flask (no ORM). Accesso DB con un'interfaccia
  "di comodo" unica per due backend: `sqlite3` diretto con `Row` factory in
  uso nativo, oppure un wrapper su `psycopg2` (stessa interfaccia:
  `conn.execute(sql, params)` con placeholder `?`, righe come dict,
  `.lastrowid` emulato) quando containerizzata (vedi sezione Docker)
- Frontend: AdminLTE 3 (tema chiaro di default con toggle scuro, sidebar a
  menu/sottomenu) + Bootstrap 4 + DataTables (server-side processing) +
  Chart.js, tutto via CDN (nessun asset da compilare/bundlare)
- Scanner: `nmap` invocato tramite un client (`nmap_proxy_client.run_nmap`)
  che in uso nativo esegue `subprocess.run(["nmap", *args], ...)` e in
  modalità container inoltra via HTTP a un proxy sull'host — stesso
  comportamento visto dal chiamante in entrambi i casi. Output parsato da
  XML (`xml.etree.ElementTree`, con `iterparse` per file grandi/troncati)
- LLM: chiamate HTTP dirette via `urllib.request` (no SDK) verso Ollama
  Cloud, Groq, Gemini — tutte con interfaccia Chat Completions compatibile
  OpenAI (tranne Gemini che ha un formato proprio)
- CVE: API REST pubblica NVD (`https://services.nvd.nist.gov/rest/json/cves/2.0`)
- PDF: `reportlab` (nessuna dipendenza da binari esterni tipo wkhtmltopdf)
- Notifiche: Telegram Bot API (`requests`), Gmail via `smtplib`/App Password

## Struttura dati (schema SQLite; PostgreSQL è lo stesso schema tradotto, vedi sezione Docker)

```sql
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    hostname TEXT, mac_address TEXT, mac_vendor TEXT,
    state TEXT, status_reason TEXT, ttl INTEGER,  -- reason/TTL della risposta nmap (echo-reply, syn-ack, ...)
    timed_out INTEGER DEFAULT 0, distance INTEGER,
    os_name TEXT, os_accuracy INTEGER, os_family TEXT, os_gen TEXT,
    device_type TEXT, device_vendor TEXT,       -- campo "operativo", usato in tutta la UI
    device_type_manual INTEGER DEFAULT 0,        -- 1 = impostato a mano, protetto da sovrascrittura
    ai_device_type TEXT, ai_confidence INTEGER, ai_reasoning TEXT,
    ai_provider TEXT, ai_classified_at TEXT,     -- audit separato della classificazione AI
    fingerprint_signature TEXT,                   -- hash(os + porte/servizi) per raggruppare host identici
    last_scanned TEXT, scan_duration REAL, raw_xml_path TEXT
);
CREATE TABLE os_matches (id, host_id FK, name, accuracy, os_family, os_gen, os_type, vendor);
CREATE TABLE services (id, host_id FK, port, protocol, state, service_name, product, version, extrainfo, tunnel, cpe);
CREATE TABLE service_scripts (id, service_id FK, script_id, output, collected_at);  -- output script NSE
CREATE TABLE host_roles (id, host_id FK, role, source, created_at);  -- sotto-tipi AI, es. "web server nginx"
CREATE TABLE scans (id, started_at, finished_at, target_count, xml_path, command, status);
CREATE TABLE cve_cache (cpe TEXT PRIMARY KEY, cve_json TEXT, fetched_at TEXT);  -- cache CVE PER CPE, non per host
CREATE TABLE host_vulnerabilities (id, host_id FK, port, cpe, cve_id, cvss, url, source, detected_at);

-- Matrice ufficiale MITRE ATT&CK (scaricata da github.com/mitre/cti, cachata localmente)
CREATE TABLE attack_tactics (shortname TEXT PRIMARY KEY, name, description, url, sort_order);
CREATE TABLE attack_techniques (technique_id TEXT PRIMARY KEY, name, description, url,
                                 is_subtechnique INTEGER DEFAULT 0, parent_technique_id, platforms);
CREATE TABLE attack_technique_tactics (technique_id FK, tactic_shortname FK, PRIMARY KEY (technique_id, tactic_shortname));
CREATE TABLE host_attack_techniques (id, host_id FK, technique_id, reason, source, detected_at);  -- mappatura euristica

-- Storico raggiungibilità (monitoraggio periodico)
CREATE TABLE host_status_checks (id, host_id FK, status TEXT, checked_at TEXT);  -- 'up'/'down', una riga per cambio+battito
```

Tutte le migrazioni devono essere **additive e idempotenti** (`ALTER TABLE
... ADD COLUMN` solo se la colonna non esiste già, verificato con
`PRAGMA table_info` su SQLite / `information_schema.columns` su Postgres),
eseguite automaticamente all'avvio di ogni script (compresa la creazione
delle tabelle stesse, `CREATE TABLE IF NOT EXISTS`: importante soprattutto
per Postgres, dove un database appena creato non ha nessuno schema ad
attenderlo — l'app web è spesso la prima a connettersi), mai a mano.

## Funzionalità da implementare (in ordine logico)

### 1. Discovery iniziale

Script che esegue un **ping-sweep** (`nmap -sn`) su tutte le 256 subnet
/16 di una rete /8, con parallelismo controllato (default 8 in parallelo),
un file XML per subnet. Due implementazioni equivalenti:
- **PowerShell** (`Start-Job` per il parallelismo, throttle "rolling" a
  N job attivi): usata in esecuzione nativa su Windows
- **Python** (`ThreadPoolExecutor`, stesso limite di parallelismo): usata
  quando l'app è containerizzata (niente PowerShell in un container Linux),
  passa dal client nmap descritto nella sezione Docker

La scelta fra le due è automatica in base a una variabile d'ambiente che
segnala la modalità container. Su Windows, `-sn` richiede privilegi di
amministratore per risultati completi — se l'app non gira elevata, avvisa
chiaramente in UI che alcuni host potrebbero non essere rilevati.

### 2. Estrazione IP attivi

Script che parsa uno o più file XML di output nmap (`nmap -sn ... -oX
file.xml`, ping sweep) ed estrae gli IP con `status state="up"`. Deve:
- Gestire file **troncati** (scansione ancora in corso quando viene letto):
  parsing incrementale con `iterparse`, ignora `ParseError` a fine file
  mantenendo gli host già completi
- Accettare **più file** in input (o auto-scoprire tutti i `*.xml` in una
  cartella `data/`), unendo gli IP e deduplicando

### 3. Scansione OS/servizi a batch

Script che, dato un file di IP:
- Li divide in batch (default 32 host)
- Per ciascun batch lancia `nmap -sV -O -sC -Pn -T4 --top-ports 200
  --host-timeout 180s -oX batch_N.xml -iL <lista_ip>`
  (**`--host-timeout` a 90s è troppo aggressivo** su reti con molti hop:
  causa il fallimento della maggioranza degli host prima che completino
  OS detection — usa almeno 180s)
- Parsa l'XML risultante e per ogni host estrae: IP, hostname, MAC/vendor,
  stato, `timedout`, distanza (hop), tutti gli OS match (nome, accuratezza,
  famiglia, generazione, tipo, vendor), e per ogni porta: stato, servizio,
  prodotto, versione, extrainfo, tunnel, **CPE** (se presente in
  `<service><cpe>`), e tutti gli **script NSE** eseguiti su quella porta
  (`<script id=... output=...>`, salvati in `service_scripts`)
- Applica un'euristica di classificazione device_type di fallback (senza
  AI): usa l'`osclass type` di nmap se disponibile, altrimenti deduce da
  porte note (stampante 9100/515/631, telecamera 554, ecc.)
- Supporta `--resume` (salta IP già presenti nel DB) per rilanci incrementali
- Registra ogni batch in una tabella `scans` (per il log/stato UI)

### 4. Classificazione AI multi-provider con fallback

Modulo condiviso (`llm_common`) con:
- **Eccezioni comuni** tra provider: `LLMError`, `LLMTooLargeError`,
  `LLMRateLimitError` (con `retry_after` opzionale), `LLMDailyLimitError`
  (sottoclasse di RateLimit — quota giornaliera, ha poco senso ritentare a
  breve termine)
- **Prompt di sistema condiviso** che istruisce il modello a rispondere
  SOLO con `{"results": [{"signature_id", "device_type", "roles": [...],
  "vendor", "confidence", "reasoning"}]}` per un batch di gruppi di host,
  con `device_type` **sempre minuscolo**, generico (2-4 parole, es. "server
  linux"), e `roles` come lista di funzioni/applicazioni specifiche
  separate (es. `["web server nginx", "application server apache tomcat"]`)
- **Parsing JSON robusto**: prova `json.loads` diretto, poi un fallback con
  regex `\{.*\}`, poi — se anche questo fallisce — isola specificamente
  l'array `"results": [...]` con una scansione a parentesi bilanciate
  (ignorando parentesi dentro stringhe). Necessario perché i modelli
  "reasoning" (es. Nemotron) a volte producono testo/JSON malformato
  **attorno** a un array altrimenti valido

Tre client separati con la stessa interfaccia
`classify_signature_groups(groups, timeout, model) -> {signature_id: {...}}`:
- **Ollama**: endpoint OpenAI-compatible, cloud (`https://ollama.com/v1/chat/completions`,
  con header `Authorization: Bearer <key>`) o locale (`http://localhost:11434/v1/chat/completions`,
  senza auth) in base alla presenza di una API key. Se il modello contiene
  "nemotron" nel nome, **prependi `"detailed thinking off\n\n"` al prompt di
  sistema** (convenzione NVIDIA per disabilitare la catena di pensiero
  estesa: riduce drasticamente latenza — da minuti a ~30s — e il rischio di
  output malformato). Timeout più alto del default (240s) per i modelli
  reasoning
- **Groq**: `https://api.groq.com/openai/v1/chat/completions`, modello
  `llama-3.3-70b-versatile`, `response_format: {"type": "json_object"}`
- **Gemini**: `https://generativelanguage.googleapis.com/v1beta/models/<model>:generateContent`,
  header `x-goog-api-key`, `generationConfig.responseMimeType: "application/json"`,
  `systemInstruction` separato da `contents`

Orchestratore che:
- Raggruppa gli host per **fingerprint identico**
  (`hash(os_name+os_family+os_gen+mac_vendor+porte/servizi_aperti_ordinate)`):
  una sola chiamata AI per gruppo, non per host — fondamentale per limitare
  l'uso delle API key su reti con migliaia di host
- Arricchisce ogni gruppo (una volta, tramite un host rappresentativo) con
  evidenze extra: banner HTTP (GET sulla porta, estrai `Server` header e
  `<title>`), condivisioni SMB (`nmap --script smb-enum-shares,smb-os-discovery`),
  banner TCP grezzi per porte "tcpwrapped"/sconosciute
- Raggruppa più gruppi in un'unica richiesta HTTP (batch, default 6 gruppi)
- Prova i provider **in ordine** (default `ollama, groq, gemini`,
  configurabile): se uno fallisce (qualsiasi `LLMError`), passa al
  successivo per lo **stesso batch**. Se la richiesta è troppo grande
  (`LLMTooLargeError`), divide il batch a metà e ritenta (stesso provider)
  prima di arrendersi. Se rate-limited (non giornaliero), attende
  `retry_after` (o 15s) e ritenta fino a un massimo di tentativi
- **Bug critico da evitare**: se TUTTI i provider falliscono per un batch,
  il batch **successivo** deve ripartire dal primo provider, non restare
  "bloccato" su un indice fuori range che salta ogni tentativo per tutti i
  batch restanti (facile errore quando si propaga l'indice del provider
  che ha avuto successo come punto di partenza per il batch successivo,
  senza gestire il caso "nessuno ha avuto successo")
- Per default classifica solo gli host non ancora classificati (mostra
  chiaramente all'avvio quanti vengono saltati); flag `--force`/`--all`
  per riclassificare tutto
- Il `device_type`/`vendor` risultante aggiorna i campi operativi su
  `hosts` **solo se** `device_type_manual != 1`; i campi `ai_*` si
  aggiornano sempre (registro di audit)
- Salva anche `roles` in una tabella separata (sostituendo quelli
  precedenti per la stessa fonte "ai")
- Gestisci l'encoding stdout su Windows (`sys.stdout.reconfigure(encoding="utf-8", errors="replace")`):
  il testo generato dai provider AI può contenere caratteri che il
  codepage di default della console Windows non sa rappresentare,
  causando `UnicodeEncodeError` a metà esecuzione

### 5. Scansione vulnerabilità (CVE)

- Raggruppa i servizi per **CPE identica** (non per host: molti host
  condividono lo stesso prodotto/versione)
- Per ogni CPE non in cache (o scaduta, default 30 giorni): interroga
  **direttamente l'API NVD** convertendo la CPE 2.2 di nmap
  (`cpe:/a:vendor:product:version`) in URI 2.3
  (`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`) — non richiede nessuna
  scansione dal vivo, solo la stringa CPE già nel DB. **Non serve una API
  key** per usare NVD (rate limit pubblico 5 richieste/30s, 50/30s con key
  gratuita) — rispetta questo limite con una pausa tra le richieste
- Se NVD non risponde/non trova nulla: fallback su
  `nmap --script vulners <host_rappresentativo>` (interroga vulners.com),
  parsando l'output testuale dello script con una regex
  `(CVE-\d{4}-\d+)\s+([\d.]+)\s+(\S+)` (righe tipo `CVE-2021-41617  7.0
  https://vulners.com/cve/...`), deduplicando per CVE (tieni il punteggio
  più alto se compare più volte)
- Cache **per CPE** (non per host): il risultato si applica a tutti gli
  host che condividono quella CPE, senza ripetere la richiesta esterna
- Supporta anche un **import manuale** da file CSV (`cpe,cve_id,cvss,url`)
  o JSON (oggetto `{"<cpe>": [...]}` o lista di record), che fa **merge**
  con la cache esistente per la stessa CPE (non sovrascrive)

### 6. Mappatura MITRE ATT&CK

- Scarica il dataset ufficiale **MITRE ATT&CK Enterprise** (STIX 2.1,
  `raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`,
  ~47MB) e lo cacha localmente (non riscaricare ad ogni avvio, solo su
  richiesta esplicita di aggiornamento)
- Estrai dal bundle STIX: tattiche (`x-mitre-tactic`, 15 in Enterprise),
  tecniche/sotto-tecniche (`attack-pattern`, **escludendo** quelle
  `revoked`/`x_mitre_deprecated`), e la relazione N:M tecnica<->tattica
  (`kill_chain_phases` con `kill_chain_name == "mitre-attack"`). L'ordine
  delle tattiche (colonne della matrice) segue `tactic_refs` dell'oggetto
  `x-mitre-matrix`, non un ordine arbitrario/da training
- **Non inventare ID tecnica a memoria**: verificali sempre contro il
  dataset scaricato prima di usarli in una regola euristica (gli ID
  cambiano/vengono deprecati nel tempo, es. la vecchia tattica "Defense
  Evasion" è oggi divisa in "Stealth" + "Defense Impairment")
- Regole euristiche **locali** (nessuna chiamata esterna oltre al download
  della matrice) che mappano porta/servizio esposto, CVE note e tipo
  dispositivo su tecniche ATT&CK plausibili, es.: porta 3389 aperta ->
  T1021.001 "Remote Desktop Protocol"; porta 445/SMB -> T1021.002 +
  T1552 (credenziali) + T1039 (accesso a condivisioni); CVE con CVSS >= 9
  nota -> T1210 "Exploitation of Remote Services"; device_type contenente
  "router"/"firewall"/"switch" -> T1599 + T1016. Ogni regola deve essere
  giustificabile da un'evidenza di scansione reale — **non** aggiungere
  tecniche "di impatto" (es. ransomware, DoS) senza un segnale concreto,
  sarebbero solo rumore/falsi allarmi
- Essendo una computazione locale ed economica, ricalcola la mappatura per
  **tutti** gli host ad ogni esecuzione (a differenza di classify/vuln non
  serve un concetto di "solo i nuovi")
- Vista a **pannelli collassabili per tattica** (non una griglia a scroll
  orizzontale — scomoda con 15+ colonne): ogni tattica è un pannello con le
  sue tecniche come chip colorati per numero di host esposti; click su una
  tecnica mostra l'elenco degli host coinvolti e il motivo della mappatura

### 7. Monitoraggio raggiungibilità host

Script che esegue periodicamente un ping-sweep (`nmap -sn`, a batch) su
tutti gli host noti e ne registra lo stato in uno storico:
- Registra una riga **solo al cambio di stato** rispetto all'ultimo check
  noto, o dopo un "battito" periodico (default 60 minuti anche senza
  cambi) — limita la crescita della tabella pur permettendo di calcolare
  un uptime% accurato
- Girato da un thread interno dell'app (non un job one-shot: un ciclo
  continuo), con intervallo/batch-size/battito configurabili da UI,
  **attivo di default**
- Uptime% ricostruito dagli intervalli fra check consecutivi (lo stato
  "vale" fino al check successivo), non da un semplice conteggio di righe
- Vista "Storico": una riga per host, **24 celle colorate** (una per ora
  del giorno selezionato, 00:00-24:00) — verde se up in quell'ora, rosso se
  down, grigio se non c'è ancora dato (nessun check registrato fino a quel
  punto). Lo stato di ogni ora è quello dell'ultimo check noto entro la
  fine dell'ora stessa ("riportato avanti" dall'ultimo cambio)

### 8. Report PDF + notifiche

- Genera un PDF (libreria pura Python, niente binari esterni) con sezioni
  componibili: **riepilogo** (stat box, grafico a barre distribuzione tipo
  dispositivo, top vulnerabilità per CVSS, esposizione MITRE ATT&CK per
  tattica) ed **elenco host completo** (tabella con intestazione ripetuta
  su ogni pagina)
- Invio via **Telegram** (Bot API, `sendDocument`) e/o **Gmail** (SMTP con
  App Password) — credenziali opzionali lette da file dedicati o variabili
  d'ambiente, stesso pattern delle chiavi AI/NVD; senza configurazione,
  l'app segnala chiaramente cosa manca in UI senza bloccare le altre
  funzionalità
- Generazione/invio manuali (bottone "Genera e scarica" / "Invia ora") più
  una **schedulazione periodica** opzionale (6h/12h/24h/settimanale),
  gestita da un thread interno separato da quello del monitoraggio

### 9. Web UI (Flask + AdminLTE)

- **Dashboard**: stat box (host totali, servizi aperti, tipi dispositivo
  distinti, batch scansione), stato scansione live (polling), grafico a
  **barre orizzontali** per distribuzione tipo dispositivo (NON un
  doughnut/pie: con decine di tipi diversi le fette diventano illeggibili
  — le barre restano leggibili anche con molte categorie), tabella tipo
  dispositivo come DataTable (25 righe/pagina), card "azioni rapide" per
  avviare i job direttamente da qui
- **Host** (lista): DataTable **server-side** (ordinamento/ricerca/
  paginazione gestiti da query SQL con `LIMIT`/`OFFSET`, non caricando
  tutto client-side), filtri per tipo dispositivo/famiglia OS/sistema
  operativo dietro un bottone "Filtri" collassabile (non sempre visibili:
  con centinaia di host la UI deve restare pulita)
- **Host** (dettaglio): tutte le info (incluso motivo/TTL della risposta
  nmap, con la stima "base 255 ≈ 8 hop, probabile apparato di rete" quando
  applicabile), editing inline del device_type (badge + icona penna + input
  con datalist di suggerimenti + salva/annulla via fetch), sotto-tipi/ruoli
  AI come badge separati, tabella vulnerabilità note, tabella tecniche
  MITRE ATT&CK mappate con motivo, card storico raggiungibilità (fetch al
  caricamento pagina)
- **Servizi**: aggregato per porta/nome, drill-down su "quali host
  espongono questo servizio"
- **Vulnerabilità**: DataTable con filtro CVSS minimo, colonna "Fonte"
  (nvd/vulners), link diretto alla scheda NVD/vulners della CVE
- **Mappa di rete**: albero **HTML/CSS/JS puro** (NON una libreria SVG
  come D3.js — con migliaia di nodi diventa illeggibile/inutilizzabile,
  meglio un albero HTML nativo collassabile, stesso pattern del menu
  della sidebar), struttura sito (primi 2 ottetti) → subnet (3 ottetti) →
  host, colori per tipo dispositivo, legenda **collassabile e scrollabile
  con campo di ricerca** (con decine di tipi dispositivo diversi generati
  dall'AI, una legenda a chip inline diventa un muro di testo illeggibile)
- **Matrice ATT&CK**: pannelli collassabili per tattica (NON una griglia a
  scroll orizzontale — scomoda con 15+ colonne su schermi normali), chip
  colorati per numero di host esposti, click apre un modal con l'elenco
  host e il motivo della mappatura
- **Monitoraggio**: stat box (up/down/mai controllati) + controlli
  schedulazione (attivo/intervallo/batch/battito, bottone "esegui ora") +
  due tab: **Stato attuale** (DataTable con stato/ultimo controllo/
  uptime24h, click apre lo storico dettagliato in un modal) e **Storico**
  (griglia a 24 celle per ora descritta sopra, con selettore data e
  prev/next giorno, caricata via fetch solo al primo accesso alla tab)
- **Amministrazione**: **6 tab**, una per ciascuna operazione automatizzabile
  (discovery, aggiorna scansione, classifica AI, scansione vulnerabilità,
  matrice ATT&CK, report), ciascuna con descrizione, controlli specifici
  (form con BatchSize/OutputDir per discovery, checkbox `--force` o
  equivalente per gli altri job), bottone avvio + bottone **interrompi**,
  badge di stato sulla linguetta stessa, log a piena larghezza/altezza. La
  tab "Report" include anche generazione/invio manuale PDF e configurazione
  della schedulazione periodica
- **Sidebar a menu/sottomenu**: raggruppa le voci in sezioni (Inventario:
  Host/Servizi/Mappa; Monitoraggio; Sicurezza: Vulnerabilità/ATT&CK;
  Sistema: Log/Amministrazione), ciascuna con icona propria; il sottomenu
  della sezione attiva si apre da solo in base alla pagina corrente
- **Log scansioni**: storico batch nmap

Meccanismo comune per i job in background (`discovery`, `rescan`,
`classify`, `vuln`, `attack` — **non** monitoraggio/report, che girano
come thread continui, non job one-shot):
- Ogni script scrive il proprio **PID in un file di lock** all'avvio (via
  context manager tipo `with JobLock(path): ...`) e lo rimuove alla fine
  (anche in caso di eccezione)
- Flask verifica se un job è già attivo leggendo il lock file e controllando
  con `tasklist`/equivalente se quel PID è ancora vivo — **non** una
  variabile in memoria (non sopravvive all'auto-reload di Flask in debug
  mode) — e pulisce automaticamente i lock "stantii" (PID morto)
- Endpoint generici `/jobs/<name>/start` (POST, lancia `subprocess.Popen`
  in background), `/jobs/<name>/stop` (POST, termina il processo **e
  l'intero albero di figli** — su Windows `taskkill /F /T /PID <pid>`,
  perché terminare solo il padre lascia i figli orfani in esecuzione) e
  `/api/jobs/<name>/status` (GET, stato + tail del log)
- Un solo blocco JS condiviso (`initJobWidgets`) collega bottone
  avvio/interrompi/badge/log di qualsiasi pagina agli endpoint sopra via
  `data-job="<name>"`, con polling ogni 4s — permette di avere i controlli
  di un job su più pagine diverse (dashboard, pagina dedicata, pagina del
  job stesso) senza duplicare la logica

### 10. Aspetto

- Font **PT Sans Narrow** (Google Fonts) su tutta l'app
- Toggle **tema chiaro/scuro** persistente (`localStorage`, classe
  `dark-mode` su `<body>`, nativa di AdminLTE 3), applicato **prima** del
  render per evitare un flash del tema sbagliato
- Controllo dimensione carattere (bottoni A-/A+, CSS custom property
  `--app-font-scale` su `<html>`, persistente)

## Esecuzione in Docker

L'app va resa containerizzabile senza portarsi dietro nmap nel container:

- **Proxy nmap**: un piccolo server HTTP (`nmap_proxy_server.py`) gira
  nativamente sull'host (dove nmap/Npcap funzionano), espone un endpoint
  che riceve una lista di argomenti nmap e ritorna returncode/stdout/stderr
  (base64, per sicurezza sull'encoding). Autenticato con un token condiviso
  (header custom), bind su `0.0.0.0` per essere raggiungibile da un
  container via `host.docker.internal`
- **Client nmap unico** (`nmap_proxy_client.run_nmap(args, timeout, ...)`)
  usato da ogni script che invoca nmap, al posto di
  `subprocess.run(["nmap", ...])` diretto: se una variabile d'ambiente
  "URL del proxy" non è impostata, esegue nmap in locale esattamente come
  prima (**zero cambio di comportamento in uso nativo**); se impostata,
  inoltra al proxy. Traduce due pattern di I/O su file usati nel resto del
  codice, dato che in modalità proxy nmap gira su una macchina diversa dal
  chiamante:
  - `-oX <path>` (file reale) → richiesto al proxy come `-oX -` (stdout),
    il contenuto ricevuto viene scritto dal client nel path locale originale
  - `-iL <path>` → il client legge il file localmente e passa gli IP come
    argomenti posizionali diretti (il path non esisterebbe sull'host proxy)
  - Un timeout lato proxy deve propagarsi come la stessa eccezione che
    `subprocess.run` solleverebbe nativamente, così il codice chiamante
    (che la intercetta) non deve sapere in quale modalità sta girando
- **Discovery**: la variante Python (vedi sezione 1) si usa automaticamente
  quando il proxy è configurato, al posto dello script PowerShell
- **Database Postgres**: quando containerizzata, il backend DB cambia da
  SQLite a Postgres tramite una URL di connessione. Per non duplicare tutte
  le query, un wrapper espone la stessa interfaccia usata per SQLite
  (`conn.execute(sql, params)` con placeholder `?`, righe come dict
  iterabili direttamente sul cursore, `.lastrowid` emulato con
  `RETURNING id` automatico sulle tabelle che hanno quella colonna,
  `.executescript` per il DDL multi-statement). Differenze di dialetto da
  gestire: `LIKE`/`ILIKE` (Postgres case-sensitive di default),
  `PRAGMA table_info`/`information_schema.columns` per l'introspezione
  colonne, `INSERT OR IGNORE`→`ON CONFLICT DO NOTHING` (supportato da
  entrambi), niente `datetime('now')` lato SQL (usa un timestamp Python
  passato come parametro, le colonne sono TEXT su entrambi i backend)
- **Importante**: all'avvio, l'app deve creare lo schema (`CREATE TABLE IF
  NOT EXISTS`) **prima** di provare eventuali `ALTER TABLE` di migrazione —
  su SQLite spesso non serve perché il file DB esiste già da run precedenti,
  ma su un database Postgres appena creato (primo avvio del container) non
  c'è ancora nessuna tabella, e l'app web è spesso il primo processo a
  connettersi
- **Dockerfile**: nmap non installato; server Flask in ascolto su
  `0.0.0.0` (non `127.0.0.1`) e con debug/reloader disattivati, entrambi
  controllabili da variabili d'ambiente per non cambiare i default in uso
  nativo
- **docker-compose**: due servizi (webapp + postgres), variabili
  d'ambiente per le chiavi opzionali (AI/NVD/Telegram/Gmail/proxy nmap) via
  un file `.env` non obbligatorio, `extra_hosts: host.docker.internal:host-gateway`
  per la portabilità su Linux (Docker Desktop lo risolve già da solo)

## Insidie da evitare (scoperte debuggando)

- **CDN**: verifica sempre che gli URL dei singoli asset esistano davvero
  (alcuni CDN, es. jsdelivr per pacchetti npm che non pubblicano una
  cartella `plugins/`, restituiscono 404 silenziosi) — usa il CDN
  ufficiale del progetto (es. `cdn.datatables.net` per DataTables, non il
  path sotto `admin-lte` su jsdelivr)
- **User-Agent bloccato**: alcuni provider dietro Cloudflare (Groq) o le
  richieste `urllib` di default vengono bloccate per lo User-Agent generico
  di Python — usa sempre un header `User-Agent` realistico tipo browser
- **Timeout non catturati**: `urllib.request.urlopen` non incapsula sempre
  i timeout di lettura (dopo la connessione, durante `getresponse()`) in
  `urllib.error.URLError` — serve un `except (TimeoutError, ConnectionError,
  OSError)` esplicito, altrimenti lo script crasha invece di passare al
  provider successivo
- **`--host-timeout` nmap**: troppo basso (90s) su reti con molti hop causa
  il fallimento silenzioso della maggioranza degli host (dati OS/servizi
  vuoti, campo `timedout=true`) — verifica sempre la percentuale di host
  con dati vuoti dopo una scansione, non solo il conteggio totale
- **Falsi positivi "è in esecuzione"**: se il rilevamento di un job attivo
  si basa su "un processo X.exe è in esecuzione" in generale, un'istanza
  indipendente di quello stesso eseguibile (es. una scansione nmap manuale
  dell'utente, non correlata all'app) causa un falso positivo — verifica la
  **command line** del processo specifico, non solo il nome
- **Kill del processo padre su Windows**: terminare un processo padre non
  termina automaticamente i suoi figli (a differenza di Unix con i gruppi
  di processo) — se serve fermare un'intera catena (es. script → nmap
  figlio), termina esplicitamente ogni PID della catena
- **Processi duplicati**: se un server web viene riavviato più volte senza
  verificare se un'istanza precedente sia ancora viva, si accumulano
  processi doppi che competono sulla stessa porta — verifica sempre le
  porte/processi attivi prima di avviarne un altro
- **File handle non chiuso sul log dei job**: se il file di log passato
  come `stdout` a `subprocess.Popen` non viene esplicitamente chiuso nel
  processo padre dopo l'avvio, il file resta bloccato (su Windows) o il
  descrittore perde per ogni job avviato nella vita del processo Flask —
  chiudilo subito dopo la `Popen` (il figlio ha già la sua copia duplicata)
- **Schema non creato su un DB Postgres vergine**: se il codice di startup
  fa solo `ALTER TABLE ... ADD COLUMN` (migrazioni "additive") assumendo che
  le tabelle esistano già, funziona su SQLite (il file DB di solito esiste
  già da run precedenti) ma fallisce con "relation does not exist" al primo
  avvio contro un Postgres appena creato — chiama sempre prima `CREATE
  TABLE IF NOT EXISTS`, poi le migrazioni additive
- **Cursori DB non iterabili**: `sqlite3.Cursor` supporta l'iterazione
  diretta (`for row in conn.execute(...)`), un cursore custom scritto per
  wrappare un altro driver (es. psycopg2) deve implementare esplicitamente
  `__iter__` o quel pattern (usato ovunque nel codice) si rompe con
  `TypeError: object is not iterable`
- **Ordine di lettura in una richiesta ping**: `reason_ttl` di uno
  `<status reason="echo-reply">` va confrontato con i TTL di partenza tipici
  (64/128/255) per stimare hop e tipo di sistema — un TTL osservato di
  247 non significa "quasi morto", significa "partito da 255, attraversati
  ~8 hop" (255 - 247), utile per dedurre un apparato di rete quando OS
  match/porte non bastano
- **Verifica sempre contro dati reali prima di fidarti di un'euristica
  nuova**: prima di aggiungere una regola (es. IP che finisce per `.1` =
  gateway, o baseline TTL) testala con dati/esempi concreti forniti
  dall'utente o osservati dal vivo, non solo "sembra ragionevole" — in
  questo progetto ogni euristica nuova (TTL, mappatura ATT&CK, ecc.) è
  stata verificata con un caso reale prima di essere considerata affidabile
