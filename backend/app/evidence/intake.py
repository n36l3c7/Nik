"""Host evidence given whole, in one request or one playbook step (7.0).

The upload route of the API (``POST /incidents/{id}/upload``) and the playbook
node "Add evidence" both end here. They speak the parameters of 6.x: a tab
(``eventlogs``, ``commands``, ``browser``, ``endpoint``) with a shell, a
browser and a profile, a category and a source. ``take`` turns them into what
7.0 keeps: the original in the store, and a source of the incident with its
section, its parser and its source name, ready to be read by the forensics
worker. A file the incident already holds is not kept twice.

Nothing is read here. Reading is ``parse.read``; ``summary`` says what it gave.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import archive
from ..core.models import EvidenceSource, Incident
from . import imports, originals, parse

TABS = ("eventlogs", "commands", "browser", "endpoint")
SHELLS = ("bash", "zsh", "fish", "powershell")
# Browser -> the sources a file of it can be (what the tabs offered in 6.x).
_CHROMIUM = ("history", "bookmarks", "shortcuts")
BROWSERS = {
    "chrome": _CHROMIUM,
    "edge": _CHROMIUM,
    "brave": _CHROMIUM,
    "opera": _CHROMIUM,
    "firefox": ("places",),
    "safari": ("history", "downloads", "bookmarks"),
}
# The sources of the endpoint parser, by system and category (the worker refuses any other).
ENDPOINT = {
    "windows": {
        "execution": ("bam",),
        "persistence": ("runkeys", "tasks", "services", "startup", "wmi"),
        "usb": ("usbstor", "setupapi"),
    },
    "macos": {"execution": ("knowledgec",), "persistence": ("launch", "cron")},
    "linux": {
        "persistence": ("cron", "sshkeys", "rc", "systemd"),
        "fileaccess": ("recent",),
        "usb": ("journal",),
    },
}
SYSTEMS = {"windows": "windows", "macos": "macos", "mac": "macos", "linux": "linux"}
UNKNOWN_SYSTEM = "Set the incident's operating system first"
# What the tab of a section is called.
TAB_OF = {"eventlog": "eventlogs", "commands": "commands", "browser": "browser", "endpoint": "endpoint"}


def _text(params: dict[str, Any], key: str) -> str:
    return str(params.get(key) or "").strip()


def route(tab: str, params: dict[str, Any], file_name: str, system: str) -> dict[str, str]:
    """Where a file goes: ``kind``, ``parser``, ``source`` and ``profile``. Raises ``ValueError`` with a
    sentence for what cannot be told."""
    if tab == "eventlogs":
        if (file_name or "").lower().endswith(".json"):
            return {"kind": "eventlog", "parser": "eventlog-json", "source": "nik-eventlogs.json", "profile": ""}
        return {"kind": "eventlog", "parser": "evtx", "source": "evtx", "profile": ""}
    if tab == "commands":
        shell = _text(params, "shell")
        if shell not in SHELLS:
            raise ValueError(f"Unknown shell '{shell}'.")
        return {"kind": "commands", "parser": "history", "source": shell, "profile": ""}
    if tab == "browser":
        browser, name = _text(params, "browser"), _text(params, "source")
        if name not in BROWSERS.get(browser, ()):
            raise ValueError(f"Unknown browser/source '{browser}/{name}'.")
        profile = _text(params, "profile")[:120] or "Default"
        return {"kind": "browser", "parser": "browser", "source": f"{browser}.{name}", "profile": profile}
    if tab == "endpoint":
        category, name = _text(params, "category"), _text(params, "source")
        os_name = SYSTEMS.get((system or "").strip().lower())
        if os_name is None:
            raise ValueError(UNKNOWN_SYSTEM)
        if name not in ENDPOINT[os_name].get(category, ()):
            raise ValueError(f"Unknown category/source '{category}/{name}' for {os_name}.")
        return {"kind": "endpoint", "parser": "endpoint", "source": f"{os_name}.{category}.{name}", "profile": ""}
    raise ValueError(f"Unknown tab '{tab}' (expected browser|commands|endpoint|eventlogs).")


def take(
    db: OrmSession, incident: Incident, data: bytes, file_name: str, tab: str, params: dict[str, Any], actor: str
) -> EvidenceSource:
    """Keep the file as the original of a new source of the incident (the caller commits), or give the
    source the incident already has for it: ``already`` on the row says which (a source that failed is
    read again, so it is not "already"). Raises ``ValueError`` for parameters that name nothing,
    ``originals.EvidenceError`` when the store has no room, ``archive.Archived`` for an archived incident."""
    archive.guard(incident)
    where = route(tab, params, file_name, incident.os or "")
    sha256 = originals.keep_bytes(data)
    known = db.scalars(
        select(EvidenceSource.id).where(
            EvidenceSource.incident_id == incident.id,
            EvidenceSource.sha256 == sha256,
            EvidenceSource.kind == where["kind"],
            EvidenceSource.source == where["source"][:60],
        )
    ).first()
    source = imports.accept(
        db,
        incident.id,
        sha256,
        len(data),
        file_name,
        {"kind": where["kind"], "source": where["source"], "profile": where["profile"]},
        actor,
    )
    # A new row: the file is new to the incident, or it was only listed by an import (``absent``) and
    # ``accept`` put the real one in its place.
    fresh = known is None or source.id != known
    if fresh:
        source.parser = where["parser"]
    elif source.state == "failed":
        # A file that could not be read is read again when it is sent again (the worker may be there now).
        parse.again(db, source)
        fresh = True
    source.already = not fresh  # type: ignore[attr-defined] - said to the caller, not stored
    return source


def target_of(source: EvidenceSource) -> str:
    """Where the file went, as the API said it in 6.x: ``commands/bash``, ``browser/chrome/Default/history``."""
    if source.kind == "browser":
        browser, _, name = (source.source or "").partition(".")
        return f"browser/{browser}/{source.profile or 'Default'}/{name}"
    if source.kind == "endpoint":
        _, _, rest = (source.source or "").partition(".")
        return f"endpoint/{rest.replace('.', '/')}"
    return f"{TAB_OF.get(source.kind, source.kind)}/{source.source}"


def summary(source: EvidenceSource, already: bool = False) -> dict[str, Any]:
    """What a reading gave, as the upload answers it: the keys of 6.x (``target``, ``rows``, ``format``) and
    the report of 7.0 (``sourceId``, ``read``, ``kept``, ``duplicates``, ``skipped``)."""
    return {
        "target": target_of(source),
        "rows": source.kept or 0,
        "format": source.parser or "",
        "sourceId": source.id,
        "read": source.read if source.read in ("complete", "partial", "failed") else "unknown",
        "kept": source.kept or 0,
        "duplicates": source.duplicates or 0,
        "skipped": source.skipped or 0,
        "alreadyImported": already,
        "state": source.state,
    }
