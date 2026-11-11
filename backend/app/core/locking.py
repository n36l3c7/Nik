"""Row locks on incident documents.

An incident is one JSON document that many writers change: the analysts'
merge patches, a sample or an e-mail being attached, a capture finishing its
indexing, a background ``.evtx`` import. Each of them reads the document,
changes a part and writes it back, so two of them at once would lose one
change. Every writer therefore takes the row lock first (``SELECT … FOR
UPDATE``) and reads the document under it; the lock lasts until the commit.

SQLite has no row locks and ignores the clause: it serialises writers itself.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .models import Incident


def lock_incident(db: OrmSession, incident_id: str | None) -> Incident | None:
    """The incident, locked for writing and read fresh; None when it does not exist."""
    if not incident_id:
        return None
    return db.scalars(
        select(Incident).where(Incident.id == incident_id).with_for_update().execution_options(populate_existing=True)
    ).one_or_none()


def relock(db: OrmSession, incident: Incident) -> Incident:
    """Lock an incident loaded earlier in the request and reload its document.

    For the writers that load the incident first and work for a while (an
    analysis, a parse) before they touch the document.
    """
    db.refresh(incident, with_for_update=True)
    return incident
