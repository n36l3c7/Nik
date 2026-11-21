"""The entry a restore leaves in the audit log.

After a restore the log on the server is the log of the backup: what the
server wrote between that backup and the restore is not in it any more (a
syslog receiver has it, when the log was forwarded). The restore says so
with the first entry of the restored server, ``audit.restore``: which backup
was put back, and that the chain goes on from the head that backup had.

It is written with plain SQL and the columns the table always had, because
the database may be the one of an earlier version, to be migrated at the
next start. It has no number yet: the migration, or the first transaction of
the server, links it after the entries of the backup.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.engine import URL

from .verifier import RESTORE

ACTOR = "server console"


def note(url: URL, backup: str, taken_at: str = "") -> bool:
    """Add the entry to the database at ``url``. Says whether there was an audit log to add it to."""
    engine = sa.create_engine(url)
    try:
        with engine.begin() as conn:
            if "audit_log" not in sa.inspect(conn).get_table_names():
                return False
            log = sa.table(
                "audit_log",
                *(sa.column(name) for name in ("id", "at", "actor", "action", "target", "details")),
            )
            taken = f", taken {taken_at}" if taken_at else ""
            conn.execute(
                sa.insert(log).values(
                    id=str(uuid.uuid4()),
                    at=datetime.now(timezone.utc).isoformat(),
                    actor=ACTOR,
                    action=RESTORE,
                    target=backup,
                    details=(
                        f"The database was restored from the backup {backup}{taken}: the audit log is the one of "
                        "that backup and goes on from its head. What was written between the backup and this "
                        "restore is not in this log"
                    ),
                )
            )
        return True
    finally:
        engine.dispose()
