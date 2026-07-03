"""Effort di rete globale (Debole / Normale / Fast): un'unica leva, scelta
in Amministrazione, che orchestra quanto sono "discrete" tutte le attività
di scansione dell'app verso la rete/i firewall, invece di dover configurare
timing/rate/batch-size separatamente in ogni job.

Due modi in cui viene usato:
- come valore LIVE (nessuna configurazione manuale possibile) per le attività
  che girano in automatico in background: il ciclo di monitoraggio
  (host_monitor.py) e lo script NSE 'vulners' di fallback (vuln_scan.py);
- come DEFAULT pre-compilato nei form con controlli manuali già esistenti
  (Discovery iniziale, Aggiorna scansione, Scansione nmap personalizzata):
  l'utente può comunque scegliere altri valori per la singola esecuzione,
  come richiesto in precedenza, ma aprendo il form vede già i valori
  coerenti con l'effort globale selezionato.

Persistito in instance/scan_effort.json, stesso pattern/posto di
monitor_schedule.py e report_schedule.py (file JSON in instance/, non
versionato, ricreato con il default se assente/corrotto).
"""

import json_settings

CONFIG_FILE = "scan_effort.json"

LEVELS = ("low", "normal", "fast")
DEFAULT_LEVEL = "normal"

# ATTENZIONE -T0/-T1/-T2 su Discovery: verificato altrove nel progetto che
# sono impraticabili su un ping-sweep dell'intera 10.0.0.0/8 (256 subnet
# /16, 65536 indirizzi ciascuna) — con T0 una singola subnet può non
# completare mai in un tempo ragionevole. Il profilo 'low' li usa comunque
# su richiesta esplicita dell'utente (priorità assoluta alla discrezione
# anche a costo di tempi lunghissimi/scansioni che non completano): la leva
# più efficace per restare praticabili resta comunque max_rate.
PROFILES = {
    "low": {
        "level": "low",
        "label": "Debole",
        "description": (
            "Minimo impatto su firewall/IDS: timing T0, pacchetti/sec molto limitati, poco "
            "parallelismo. Attenzione: con T0 una discovery sull'intera 10.0.0.0/8 può non "
            "completare mai in un tempo ragionevole (vedi guida nella tab Discovery)."
        ),
        "discovery_timing": "0",
        "discovery_max_rate": 20,
        "discovery_batch_size": 2,
        "rescan_timing": "2",
        "rescan_top_ports": 100,
        "monitor_timing": "2",
        "vuln_timing": "2",
        "customscan_timing": "2",
        "customscan_max_rate": 100,
    },
    "normal": {
        "level": "normal",
        "label": "Normale",
        "description": "Compromesso tra velocità e discrezione: il comportamento di default storico dell'app.",
        "discovery_timing": "4",
        "discovery_max_rate": 0,
        "discovery_batch_size": 8,
        "rescan_timing": "4",
        "rescan_top_ports": 200,
        "monitor_timing": "3",
        "vuln_timing": "3",
        "customscan_timing": "4",
        "customscan_max_rate": 0,
    },
    "fast": {
        "level": "fast",
        "label": "Fast",
        "description": (
            "Massima velocità, massimo impatto sulla rete: usarlo solo quando disturbare "
            "firewall/IDS non è un problema (reti/orari dedicati)."
        ),
        "discovery_timing": "5",
        "discovery_max_rate": 0,
        "discovery_batch_size": 16,
        "rescan_timing": "5",
        "rescan_top_ports": 1000,
        "monitor_timing": "4",
        "vuln_timing": "4",
        "customscan_timing": "5",
        "customscan_max_rate": 0,
    },
}


_DEFAULT_CONFIG = {"level": DEFAULT_LEVEL}


def load_level():
    level = json_settings.load(CONFIG_FILE, _DEFAULT_CONFIG)["level"]
    return level if level in LEVELS else DEFAULT_LEVEL


def save_level(level):
    if level not in LEVELS:
        raise ValueError(f"Livello di effort sconosciuto: {level}")
    json_settings.save(CONFIG_FILE, _DEFAULT_CONFIG, {"level": level})
    return level


def current_profile():
    return PROFILES[load_level()]


def all_profiles():
    return [PROFILES[level] for level in LEVELS]
