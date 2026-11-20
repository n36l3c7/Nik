"""The packs of vendors' products, as the repository keeps them (``packs/<id>/``).

They are not inside Nik (they are published to the catalogue), but they are
tested like what is: each connector against its recorded exchanges, each
mapper and playbook against the Nik it is installed in.
"""

from __future__ import annotations

import json
from pathlib import Path

from app import mapping, packs
from app.automation import connector_actions as ca

REPO_PACKS = Path(__file__).resolve().parents[2] / "packs"


def folders() -> list[Path]:
    return sorted(path.parent for path in REPO_PACKS.glob("*/pack.yml"))


def connectors() -> list[tuple[str, ca.ConnectorFile]]:
    """Every connector there is to test: the ones Nik ships and the ones of the packs."""
    found = list(ca.shipped())
    for path in sorted(REPO_PACKS.glob("*/connectors/*/connector.yml")):
        text = path.read_text(encoding="utf-8")
        found.append((text, ca.load(text)))
    return found


def mappers() -> dict[str, dict]:
    """connector id → the mappers and the classifier it comes with."""
    found = dict(mapping.shipped())
    for path in sorted(REPO_PACKS.glob("*/mappers/*.json")):
        found[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    return found


def playbooks() -> dict[str, dict]:
    """file name → the playbook of a pack."""
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))["playbook"]
        for path in sorted(REPO_PACKS.glob("*/playbooks/*.json"))
    }


def install(db) -> int:
    """Install every pack of the repository, as a Nik with ``NIK_PACKS_DIR`` does at start."""
    return packs.install_folder(db, REPO_PACKS)


def install_pack(db, pack_id: str) -> None:
    """Install one pack of the repository (the caller commits)."""
    packs.apply(db, packs.read(packs.folder_bytes(REPO_PACKS / pack_id)), {}, "test", source="folder")


def said(db, source_id: str, kind: str, value: str, verdict: str | Exception, summary: str = ""):
    """Store what a source answers about an indicator, as a look-up stores it, without the source: for a
    test that is about what follows an answer (an event, a verdict), not about how it is asked for."""
    from app.enrichment import service, sources

    asked = sources.Source(
        id=source_id,
        label=source_id,
        weight=1,
        informational=False,
        commands={sources.command_kind(kind): "test"},
        connector=None,
        instance=None,
        instances=0,
    )

    def answer(*args, **more):
        if isinstance(verdict, Exception):
            raise verdict
        return {"verdict": verdict, "summary": summary or f"says {verdict}"}

    real = sources.ask
    sources.ask = answer
    try:
        return service.lookup_one(db, asked, kind, value)
    finally:
        sources.ask = real


def source(db, pack_id: str, *, key: str = "", name: str = "", enabled: bool = True, **policy):
    """A source of threat intelligence that is on: its pack installed and an instance of its connector
    made, with one key when the connector takes one. ``policy``: the limits of the instance (perMinute,
    perDay, cacheHours, mode). Commits, and gives the instance."""
    from app.automation import instance_keys
    from app.core.models import Connection, Connector
    from app.core.security import now_iso
    from app.enrichment import old_keys

    if db.get(Connector, pack_id) is None:
        install_pack(db, pack_id)
    connector = ca.parsed(db.get(Connector, pack_id))
    now = now_iso()
    row = Connection(
        id=f"{pack_id}-{len(ca.connections_of(db, pack_id))}"[:32],
        name=name or connector.name,
        connector_id=pack_id,
        config={},
        enabled=enabled,
        created_at=now,
        created_by="test",
        updated_at=now,
        updated_by="test",
    )
    if key:
        ca.store_secrets(row, {old_keys.key_field(connector): key})
    if policy:
        row.key_policy = instance_keys.clean_policy(policy)
    db.add(row)
    db.commit()
    return row
