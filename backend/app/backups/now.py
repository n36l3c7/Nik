"""A backup asked for from the command line: what ``deploy/backup.sh`` runs inside the api container.

    python -m app.backups.now

It does what *Back up now* does on the screen: it leaves the request, and the
server takes the backup, tests it and applies the retention as it does for
the schedule. So there is one way of making a backup, whoever asks. It waits
for the end and says how it went: 0 for a backup that passed its restore
test, 1 otherwise.
"""

from __future__ import annotations

import os
import sys
import time

from sqlalchemy import select

from ..core import audit
from ..core.db import SessionLocal
from ..core.models import Backup
from . import config, runner

POLL = 2
BY = "deploy/backup.sh"


def _say(text: str) -> None:
    sys.stderr.write(f"backup: {text}\n")
    sys.stderr.flush()


def main(wait: float | None = None) -> int:
    wait = float(os.environ.get("NIK_BACKUP_WAIT", 6 * 3600)) if wait is None else wait
    with SessionLocal() as db:
        if config.passphrase(db) is None:
            _say("no backup passphrase is set (Settings → Backup): no backup is written in clear.")
            return 1
        row = db.scalars(select(Backup).where(Backup.kind == "full", Backup.state.in_(("queued", "running")))).first()
        if row is None:
            row = runner.start_row(db, "full", BY)
            audit.record(db, BY, "backup.request", f"Asked for the backup {row.id}", target=row.id)
            db.commit()
            _say(f"asked for {row.id}: the server takes it within a few seconds.")
        else:
            _say(f"{row.id} is already being taken: waiting for it.")
        name = row.id
    said = ""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        with SessionLocal() as db:
            row = db.get(Backup, name)
            if row is None:
                _say(f"{name} is gone: it was deleted while it was waited for.")
                return 1
            state, verify, error = row.state, row.verify_state, row.error
            result, size = dict(row.verify or {}), row.size
        now = f"{state}/{verify}"
        if now != said:
            said = now
            if state == "running":
                _say("being written…")
            elif state == "done" and verify in ("queued", "running"):
                _say(f"written ({size} bytes): its restore test runs…")
        if state == "failed":
            _say(f"{name} failed: {error}")
            return 1
        if state == "done" and verify == "passed":
            _say(f"{name} is written and passed its restore test ({result.get('seconds', '?')} s).")
            for check in result.get("checks") or []:
                _say(f"  - {check}")
            return 0
        if state == "done" and verify == "failed":
            _say(f"{name} was written and FAILED its restore test: {result.get('error')}")
            return 1
        time.sleep(POLL)
    _say(f"{name} did not end in {int(wait)} seconds. Is the api container running? Its log says what it does.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
