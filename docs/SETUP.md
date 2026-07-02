# Setup

## Requisiti

- Python 3.10+
- [nmap](https://nmap.org/download.html) installato e nel `PATH` (Windows: di
  norma in `C:\Program Files (x86)\Nmap\nmap.exe`)
- Per la scansione OS/servizi completa (`-O`), nmap potrebbe richiedere
  privilegi di amministratore/Npcap installato

## Installazione

```
pip install -r requirements.txt   # Flask
python app.py                      # avvia su http://127.0.0.1:5200
```

Al primo avvio, `app.py` crea automaticamente `instance/inventory.db` con lo
schema completo (nessuna migrazione manuale richiesta).

## Chiavi API (opzionali, per le funzionalità AI/CVE)

Ogni chiave va salvata in un file dedicato nella root del progetto (mai
committare — sono già in `.gitignore`), oppure in una variabile d'ambiente
equivalente:

| Funzionalità | File | Variabile d'ambiente | Note |
|---|---|---|---|
| Classificazione AI (Ollama) | `.ollama_api_key` | `OLLAMA_API_KEY` | Ollama Cloud; senza key usa un'istanza locale (`ollama serve`) |
| Classificazione AI (Groq) | `.groq_api_key` | `GROQ_API_KEY` | Free tier: 100k token/giorno |
| Classificazione AI (Gemini) | `.gemini_api_key` | `GEMINI_API_KEY` | Free tier: 20 richieste/giorno per modello |
| CVE da NVD | `.nvd_api_key` | `NVD_API_KEY` | Opzionale: senza key 5 richieste/30s, con key 50/30s |

Senza nessuna chiave, la classificazione AI e la scansione vulnerabilità
falliscono con un errore chiaro (non bloccano il resto dell'app). La
scansione vulnerabilità ha comunque un fallback su `nmap --script vulners`
anche senza chiave NVD.

Modelli di default (sovrascrivibili con variabili d'ambiente
`OLLAMA_MODEL`/`GROQ_MODEL`/`GEMINI_MODEL`):
- Ollama: `nemotron-3-super:cloud`
- Groq: `llama-3.3-70b-versatile`
- Gemini: `gemini-2.5-flash`

## Popolare i dati iniziali

1. Esegui un ping sweep con nmap (fuori dall'app, può richiedere ore su
   range grandi), es.:
   ```
   nmap -T5 -sn 10.0.0.0/8 -oX data/ised.xml
   ```
   Puoi depositare **più file** in `data/*.xml` (es. scansioni per subnet
   separate): vengono tutti uniti e deduplicati automaticamente.
2. Dalla UI, vai su **Operazioni → Aggiorna scansione → Avvia**: estrae gli
   IP "up" e lancia `nmap -sV -O -sC` a batch sugli IP nuovi
3. **Operazioni → Classificazione AI → Avvia**: determina tipo dispositivo/
   vendor/ruoli per gli host nuovi
4. **Operazioni → Scansione vulnerabilità → Avvia**: associa le CVE note ai
   servizi con CPE rilevata
5. **Operazioni → Matrice ATT&CK → Avvia**: scarica (la prima volta, ~47MB)
   la matrice ufficiale MITRE ATT&CK e mappa ogni host sulle tecniche
   applicabili, consultabile in **Matrice ATT&CK**

Tutti i job successivi (con `--resume`/senza `--force`) elaborano solo i
dati nuovi, non ripetono lavoro già fatto. Fa eccezione il job **Matrice
ATT&CK**: essendo una mappatura euristica locale (nessun costo/rate-limit
esterno oltre al download iniziale della matrice), viene sempre ricalcolata
per tutti gli host ad ogni esecuzione.

## Reset completo

Per ripartire da una situazione pulita:

```
rm instance/inventory.db
python -c "import scanner_db; scanner_db.init_db(scanner_db.connect('instance/inventory.db'))"
```

(oppure semplicemente elimina il file: verrà ricreato vuoto al prossimo
avvio di qualsiasi script).
