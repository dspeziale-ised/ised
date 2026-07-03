# Setup

Per l'esecuzione in **Docker** (Postgres al posto di SQLite, nmap sull'host
tramite proxy) vedi invece [DOCKER.md](DOCKER.md). Questa pagina copre
l'uso nativo (Windows, SQLite).

## Requisiti

- Python 3.10+
- [nmap](https://nmap.org/download.html) installato e nel `PATH` (Windows: di
  norma in `C:\Program Files (x86)\Nmap\nmap.exe`)
- Per la scansione OS/servizi completa (`-O`) e per il ping-sweep (`-sn`),
  nmap potrebbe richiedere privilegi di amministratore/Npcap installato

## Installazione

```
pip install -r requirements.txt
python app.py                      # avvia su http://127.0.0.1:5200
```

Al primo avvio, `app.py` crea automaticamente `instance/inventory.db` con lo
schema completo (nessuna migrazione manuale richiesta). Il monitoraggio
raggiungibilità parte da solo in background (thread interno).

## Chiavi API e token (tutti opzionali)

Ogni chiave va salvata in un file dedicato nella cartella `keys/` (mai
committare — l'intera cartella è già in `.gitignore`), oppure in una
variabile d'ambiente equivalente:

| Funzionalità | File (in `keys/`) | Variabile d'ambiente | Note |
|---|---|---|---|
| Classificazione AI (Ollama) | `ollama_api_key` | `OLLAMA_API_KEY` | Ollama Cloud; senza key usa un'istanza locale (`ollama serve`) |
| Classificazione AI (Groq) | `groq_api_key` | `GROQ_API_KEY` | Free tier: 100k token/giorno |
| Classificazione AI (Gemini) | `gemini_api_key` | `GEMINI_API_KEY` | Free tier: 20 richieste/giorno per modello |
| CVE da NVD | `nvd_api_key` | `NVD_API_KEY` | Opzionale: senza key 5 richieste/30s, con key 50/30s |
| Notifica report (Telegram) | `telegram_bot_token` + `telegram_chat_id` | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Bot creato via @BotFather; anche configurabili dalla UI (Amministrazione → Report) |
| Notifica report (Gmail) | `gmail_address` + `gmail_app_password` | `GMAIL_ADDRESS` + `GMAIL_APP_PASSWORD` | Richiede App Password Google (verifica in due passaggi attiva); `gmail_to`/`GMAIL_TO` per il destinatario di default |
| Proxy nmap (solo Docker) | `nmap_proxy_token` | `NMAP_PROXY_TOKEN` | Vedi [DOCKER.md](DOCKER.md) |

Senza le chiavi AI/NVD, la classificazione AI e la scansione vulnerabilità
falliscono con un errore chiaro (non bloccano il resto dell'app). La
scansione vulnerabilità ha comunque un fallback su `nmap --script vulners`
anche senza chiave NVD. Senza le chiavi Telegram/Gmail, la generazione PDF
funziona lo stesso (solo download manuale), l'invio segnala chiaramente
cosa manca.

Modelli di default (sovrascrivibili con variabili d'ambiente
`OLLAMA_MODEL`/`GROQ_MODEL`/`GEMINI_MODEL`):
- Ollama: `nemotron-3-super:cloud`
- Groq: `llama-3.3-70b-versatile`
- Gemini: `gemini-2.5-flash`

## Popolare i dati iniziali

Tutto dalla pagina **Amministrazione** (`/admin`), nessun comando da
terminale:

1. **Discovery iniziale → Avvia**: ping-sweep su tutta `10.0.0.0/8` (256
   subnet /16 in parallelo, `BatchSize` configurabile), scrive gli XML
   direttamente in `data/`. Su Windows richiede privilegi di amministratore
   per risultati completi (avviso mostrato in UI se manca)
2. **Aggiorna scansione → Avvia**: estrae gli IP "up" da tutti i
   `data/*.xml` e lancia `nmap -sV -O -sC` a batch sugli IP nuovi
3. **Classificazione AI → Avvia**: determina tipo dispositivo/vendor/ruoli
   per gli host nuovi
4. **Scansione vulnerabilità → Avvia**: associa le CVE note ai servizi con
   CPE rilevata
5. **Matrice ATT&CK → Avvia**: scarica (la prima volta, ~47MB) la matrice
   ufficiale MITRE ATT&CK e mappa ogni host sulle tecniche applicabili
6. **Report → Genera e scarica PDF** (o **Invia ora** con Telegram/Gmail
   configurati)

Tutti i job successivi (con `--resume`/senza `--force`) elaborano solo i
dati nuovi, non ripetono lavoro già fatto. Fanno eccezione **Matrice
ATT&CK** (mappatura euristica locale, ricalcolata sempre per tutti gli
host — nessun costo/rate-limit esterno oltre al download iniziale) e il
**Monitoraggio** (ciclo periodico continuo, non un job one-shot).

Dalla pagina **Inventario → Scansione nmap** si può inoltre lanciare in
qualsiasi momento una scansione nmap libera (target + opzioni a scelta),
con i risultati salvati negli host come le altre scansioni.

**Effort di rete globale**: in cima ad Amministrazione, tre pulsanti
Debole/Normale/Fast orchestrano quanto sono discrete tutte le attività di
scansione (monitoraggio e fallback vulnerabilità lo seguono in automatico;
discovery/rescan/scansione nmap lo usano come default pre-compilato nel
form, sempre modificabile per la singola esecuzione).

## Reset completo

Per ripartire da una situazione pulita:

```
rm instance/inventory.db
python -c "import scanner_db; scanner_db.init_db(scanner_db.connect('instance/inventory.db'))"
```

(oppure semplicemente elimina il file: verrà ricreato vuoto al prossimo
avvio di qualsiasi script).
