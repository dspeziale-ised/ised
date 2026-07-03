"""Invio email (con allegato) via Gmail SMTP, usato per notificare il report
PDF dell'inventario di rete. Autenticazione con una App Password Google
(richiede la verifica in due passaggi attiva sull'account) — nessuna
libreria esterna oltre smtplib/email della standard library.

Configurazione (stesso pattern delle altre chiavi API del progetto): file
dedicati nella cartella keys/ (mai committare, già in .gitignore) oppure
variabili d'ambiente equivalenti.
"""

import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import secrets_store

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


class GmailError(Exception):
    pass


def _load_address():
    return secrets_store.load_secret("GMAIL_ADDRESS", "gmail_address")


def _load_app_password():
    return secrets_store.load_secret("GMAIL_APP_PASSWORD", "gmail_app_password")


def default_recipient():
    return secrets_store.load_secret("GMAIL_TO", "gmail_to")


def has_app_password():
    return bool(_load_app_password())


def address_from_env():
    """True se l'indirizzo viene da una variabile d'ambiente (non dal file
    scrivibile da UI) — in quel caso l'env var ha sempre la priorità e un
    salvataggio da form non avrebbe effetto visibile."""
    return secrets_store.is_from_env("GMAIL_ADDRESS")


def app_password_from_env():
    return secrets_store.is_from_env("GMAIL_APP_PASSWORD")


def get_address_display():
    """Indirizzo mittente da mostrare in un form (non è un segreto quanto
    l'App Password)."""
    return _load_address() or ""


def save_credentials(address=None, app_password=None, default_to=None):
    """Salva indirizzo/App Password/destinatario di default nei file
    dedicati. Un campo vuoto/assente lascia invariato il valore già salvato
    (così il form può essere sottomesso senza dover re-inserire una
    password già configurata)."""
    secrets_store.save_secret("gmail_address", address)
    secrets_store.save_secret("gmail_app_password", app_password)
    secrets_store.save_secret("gmail_to", default_to)


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
            "GMAIL_APP_PASSWORD o file keys/gmail_address e keys/gmail_app_password)."
        )
    if not recipient:
        raise GmailError("Nessun destinatario specificato (né passato né in keys/gmail_to o GMAIL_TO).")

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
