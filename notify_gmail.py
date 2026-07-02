"""Invio email (con allegato) via Gmail SMTP, usato per notificare il report
PDF dell'inventario di rete. Autenticazione con una App Password Google
(richiede la verifica in due passaggi attiva sull'account) — nessuna
libreria esterna oltre smtplib/email della standard library.

Configurazione (stesso pattern delle altre chiavi API del progetto): file
dedicati nella root del progetto (mai committare, già in .gitignore) oppure
variabili d'ambiente equivalenti.
"""

import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

_ADDRESS_FILE = Path(__file__).parent / ".gmail_address"
_APP_PASSWORD_FILE = Path(__file__).parent / ".gmail_app_password"
_DEFAULT_TO_FILE = Path(__file__).parent / ".gmail_to"


class GmailError(Exception):
    pass


def _load_address():
    value = os.environ.get("GMAIL_ADDRESS")
    if value:
        return value.strip()
    if _ADDRESS_FILE.exists():
        return _ADDRESS_FILE.read_text(encoding="utf-8").strip()
    return None


def _load_app_password():
    value = os.environ.get("GMAIL_APP_PASSWORD")
    if value:
        return value.strip()
    if _APP_PASSWORD_FILE.exists():
        return _APP_PASSWORD_FILE.read_text(encoding="utf-8").strip()
    return None


def default_recipient():
    value = os.environ.get("GMAIL_TO")
    if value:
        return value.strip()
    if _DEFAULT_TO_FILE.exists():
        return _DEFAULT_TO_FILE.read_text(encoding="utf-8").strip()
    return None


def is_configured():
    return bool(_load_address() and _load_app_password())


def send_document(file_bytes, filename, to_address=None, subject=None, body=None, timeout=30):
    """Invia un'email con un allegato (es. PDF) a to_address (o al
    destinatario di default configurato). Solleva GmailError in caso di
    problemi di configurazione/autenticazione/invio."""
    address = _load_address()
    app_password = _load_app_password()
    recipient = (to_address or default_recipient() or "").strip()

    if not address or not app_password:
        raise GmailError(
            "Account Gmail non configurato (variabili d'ambiente GMAIL_ADDRESS/"
            "GMAIL_APP_PASSWORD o file .gmail_address/.gmail_app_password)."
        )
    if not recipient:
        raise GmailError("Nessun destinatario specificato (né passato né in .gmail_to/GMAIL_TO).")

    msg = MIMEMultipart()
    msg["From"] = address
    msg["To"] = recipient
    msg["Subject"] = subject or "Report inventario di rete - ised.net"
    msg.attach(MIMEText(body or "In allegato il report PDF generato dall'applicazione.", "plain"))

    attachment = MIMEApplication(file_bytes, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(attachment)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=timeout) as server:
            server.starttls()
            server.login(address, app_password)
            server.sendmail(address, [recipient], msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        raise GmailError(
            "Autenticazione Gmail fallita: verifica che la App Password sia corretta "
            "e che la verifica in due passaggi sia attiva sull'account."
        ) from e
    except (smtplib.SMTPException, OSError) as e:
        raise GmailError(f"Errore durante l'invio email: {e}") from e

    return {"to": recipient}
