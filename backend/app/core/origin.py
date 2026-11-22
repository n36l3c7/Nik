"""On whose behalf the current thread is making changes.

A bulk job changes many items one after the other, each through the code a
single change goes through. That code does not know it is part of a job, and
does not have to: the job says so here, and the two places that write down
what happened read it. The audit log ends the entry of each change with the
job (``core/audit.py``), which is what links the entries of a job together;
the outbox of the playbooks marks each event (``automation/triggers.py``), so
a playbook can tell a change made alone from one of a thousand.
"""

from __future__ import annotations

from contextvars import ContextVar

# The id of the bulk job whose item is being worked on, if any.
bulk: ContextVar[str | None] = ContextVar("nik_bulk_job", default=None)


def bulk_mark() -> str:
    """What an audit entry of a change made by a bulk job ends with ("" outside one)."""
    job = bulk.get()
    return f" · bulk {job[:8]}" if job else ""
