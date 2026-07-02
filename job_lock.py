"""Lock file basato su PID: segnala che uno script è in esecuzione, in modo
verificabile anche da un altro processo (es. l'app Flask) leggendo il file
e controllando se quel PID è ancora vivo. Sopravvive ai riavvii del
processo che lo controlla (a differenza di una variabile in memoria)."""

import os
from pathlib import Path


class JobLock:
    def __init__(self, lock_path):
        self.lock_path = Path(lock_path)

    def __enter__(self):
        self.lock_path.write_text(str(os.getpid()), encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.lock_path.exists():
                self.lock_path.unlink()
        except OSError:
            pass
        return False
