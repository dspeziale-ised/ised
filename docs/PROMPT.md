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

1. Scansiona la rete con **nmap** (OS detection, servizi, script NSE) e
   registra tutto in un database **SQLite**
2. Classifica il **tipo di dispositivo** di ogni host usando un **LLM**
   (con fallback automatico tra più provider: Ollama, Groq, Gemini)
3. Associa alle porte/servizi rilevati le **CVE reali** note (fonte
   ufficiale NVD, con cache locale)
4. Espone tutto tramite una **web UI** (Flask + AdminLTE 3 + DataTables),
   dalla quale si avviano tutte le operazioni — **nessun comando da
   terminale richiesto** per l'uso quotidiano

## Stack tecnico

- Backend: Python 3 + Flask (no ORM, `sqlite3` diretto con `Row` factory)
- Frontend: AdminLTE 3 (tema chiaro di default con toggle scuro) +
  Bootstrap 4 + DataTables (server-side processing) + Chart.js, tutto via
  CDN (nessun asset da compilare/bundlare)
- Scanner: `nmap` invocato via `subprocess`, output parsato da XML
  (`xml.etree.ElementTree`, con `iterparse` per file grandi/troncati)
- LLM: chiamate HTTP dirette via `urllib.request` (no SDK) verso Ollama
  Cloud, Groq, Gemini — tutte con interfaccia Chat Completions compatibile
  OpenAI (tranne Gemini che ha un formato proprio)
- CVE: API REST pubblica NVD (`https://services.nvd.nist.gov/rest/json/cves/2.0`)

## Struttura dati (schema SQLite)

```sql
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    hostname TEXT, mac_address TEXT, mac_vendor TEXT,
    state TEXT, timed_out INTEGER DEFAULT 0, distance INTEGER,
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
```

Tutte le migrazioni devono essere **additive e idempotenti** (`ALTER TABLE
... ADD COLUMN` solo se la colonna non esiste già, verificato con
`PRAGMA table_info`), eseguite automaticamente all'avvio di ogni script,
mai a mano.

## Funzionalità da implementare (in ordine logico)

### 1. Estrazione IP attivi

Script che parsa uno o più file XML di output nmap (`nmap -sn ... -oX
file.xml`, ping sweep) ed estrae gli IP con `status state="up"`. Deve:
- Gestire file **troncati** (scansione ancora in corso quando viene letto):
  parsing incrementale con `iterparse`, ignora `ParseError` a fine file
  mantenendo gli host già completi
- Accettare **più file** in input (o auto-scoprire tutti i `*.xml` in una
  cartella `data/`), unendo gli IP e deduplicando

### 2. Scansione OS/servizi a batch

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

### 3. Classificazione AI multi-provider con fallback

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

### 4. Scansione vulnerabilità (CVE)

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

### 5. Mappatura MITRE ATT&CK

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
- Vista a **matrice colorata**: colonne = tattiche, celle = tecniche,
  intensità colore = numero di host esposti a quella tecnica; click su una
  cella mostra l'elenco degli host coinvolti e il motivo della mappatura

### 6. Web UI (Flask + AdminLTE)

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
- **Host** (dettaglio): tutte le info, editing inline del device_type
  (badge + icona penna + input con datalist di suggerimenti + salva/
  annulla via fetch), sotto-tipi/ruoli AI come badge separati, tabella
  vulnerabilità note, tabella tecniche MITRE ATT&CK mappate con motivo
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
- **Matrice ATT&CK**: griglia CSS pura (colonne = tattiche, scroll
  orizzontale, nessuna libreria matrice/grafo esterna), celle colorate per
  numero di host esposti, click su una cella apre un modal con l'elenco
  host e il motivo della mappatura
- **Operazioni**: **4 tab** (una per job: aggiorna scansione, classifica AI,
  scansione vulnerabilità, matrice ATT&CK), ciascuna con descrizione,
  controlli (checkbox `--force` dove rilevante, o il flag CLI equivalente
  per quel job — es. `--update-matrix` per la matrice ATT&CK, non
  "riclassificare" ha senso lì), bottone avvio + bottone **interrompi**,
  badge di stato sulla linguetta stessa, log a piena larghezza/altezza (non
  colonne strette affiancate)
- **Log scansioni**: storico batch nmap

Meccanismo comune per i job in background (`rescan`, `classify`, `vuln`,
`attack`):
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

### 7. Aspetto

- Font **PT Sans Narrow** (Google Fonts) su tutta l'app
- Toggle **tema chiaro/scuro** persistente (`localStorage`, classe
  `dark-mode` su `<body>`, nativa di AdminLTE 3), applicato **prima** del
  render per evitare un flash del tema sbagliato
- Controllo dimensione carattere (bottoni A-/A+, CSS custom property
  `--app-font-scale` su `<html>`, persistente)

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
