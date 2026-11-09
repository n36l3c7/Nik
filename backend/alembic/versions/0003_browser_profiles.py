"""browser profiles

Rewrite every incident document to the 2.0.0 browser shape: each browser holds
several profiles instead of one set of artifacts. A legacy browser slot
(``{history, downloads, bookmarks, shortcuts, meta}``) becomes the profile
"Default" (id ``default``) of ``{activeProfile, profiles}``.

The transformation is copied here on purpose (not imported from the app), so
this migration keeps working whatever the application code becomes. Rows are
streamed one at a time to bound memory on large databases.

Revision ID: 0003_browser_profiles
Revises: 0002_incident_os_column
Create Date: 2026-11-04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0003_browser_profiles"
down_revision = "0002_incident_os_column"
branch_labels = None
depends_on = None

ARTIFACT_KEYS = ("history", "downloads", "bookmarks", "shortcuts")

incidents = sa.table("incidents", sa.column("id", sa.String), sa.column("doc", sa.JSON))


def _browsers(doc):
    if not isinstance(doc, dict):
        return None
    browsers = ((doc.get("data") or {}).get("browser") or {}).get("browsers")
    return browsers if isinstance(browsers, dict) else None


def _to_profiles(slot: dict) -> dict:
    profile = {
        "id": "default",
        "name": "Default",
        "createdAt": "1970-01-01T00:00:00.000Z",
        **{key: slot[key] if isinstance(slot.get(key), list) else [] for key in ARTIFACT_KEYS},
        "meta": slot["meta"] if isinstance(slot.get("meta"), dict) else {},
    }
    return {"activeProfile": "default", "profiles": {"default": profile}}


def _to_legacy(slot: dict) -> dict:
    profiles = slot.get("profiles") or {}
    chosen = profiles.get(slot.get("activeProfile")) or profiles.get("default") or next(iter(profiles.values()), {})
    return {**{key: chosen.get(key, []) for key in ARTIFACT_KEYS}, "meta": chosen.get("meta", {})}


def _rewrite(convert, should_convert) -> None:
    bind = op.get_bind()
    ids = [row.id for row in bind.execute(sa.select(incidents.c.id)).all()]
    for incident_id in ids:
        doc = bind.execute(sa.select(incidents.c.doc).where(incidents.c.id == incident_id)).scalar()
        browsers = _browsers(doc)
        if browsers is None:
            continue
        changed = False
        for browser_id, slot in list(browsers.items()):
            if isinstance(slot, dict) and should_convert(slot):
                browsers[browser_id] = convert(slot)
                changed = True
        if changed:
            bind.execute(incidents.update().where(incidents.c.id == incident_id).values(doc=doc))


def upgrade() -> None:
    _rewrite(_to_profiles, lambda slot: "profiles" not in slot)


def downgrade() -> None:
    # Lossy by nature: only the active (or Default) profile survives.
    _rewrite(_to_legacy, lambda slot: "profiles" in slot)
