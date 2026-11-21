"""What an administrator sets about the recovery to a moment, and the rows this package keeps.

Five rows of ``settings``:

- ``SETTINGS_ID`` what is set: when the base backups are taken, how far back
  one can go, how far behind the second host may fall before the
  administrators are told, how often the archive is proven;
- ``ARCHIVE_SETTINGS_ID`` what the loop of the API process knows (``archive.py``);
- ``SHIP_SETTINGS_ID`` what the process that sends the copies knows (``ship.py``):
  the two never write the same row, so neither overwrites the other;
- ``WATCH_SETTINGS_ID`` the problems the administrators were told about (``watch.py``);
- ``ROLE_SETTINGS_ID`` which server this is: its generation, when it was promoted,
  whether it was replaced (``role.py``).

Nothing here is a secret: what leaves the host is sealed under the backup
passphrase (``app/backups/config.py``) and sent to the destination set for
the backups. One passphrase and one destination, set in one place.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..backups import config as backup_config
from ..core.models import Setting

SETTINGS_ID = 60
ARCHIVE_SETTINGS_ID = 61
SHIP_SETTINGS_ID = 62
WATCH_SETTINGS_ID = 63
ROLE_SETTINGS_ID = 64

# Until an administrator sets something else: a base backup every day at 03:30 UTC; two days
# to go back in (so two or three base backups on the disk); the administrators told when what
# is on the second host is more than fifteen minutes old; the archive proven once a day.
DEFAULTS: dict[str, Any] = {
    "base": {"enabled": True, "every": "day", "hours": 12, "at": "03:30", "weekday": 6, "timezone": "UTC"},
    "keepDays": 2,
    "lagMinutes": 15,
    "testEveryHours": 24,
    "name": "",
}

ConfigError = backup_config.ConfigError
# A loop of the recovery that dies leaves its lease to the process that takes over after this
# long: after a restart the log is sent again within half a minute, not within two.
LEASE_SECONDS = 30


def acquire(db: OrmSession, holder: str, now: float | None, name: str) -> bool:
    """Take or renew a lease of the recovery (``core/leases.py``, as every loop of the server
    does): given back with the others when the process stops, and never given on a standby or on
    a server that was replaced."""
    from ..core import leases

    return leases.take(db, name, holder, LEASE_SECONDS, now)


def held(db: OrmSession, row_id: int) -> dict[str, Any]:
    row = db.get(Setting, row_id)
    return dict((row.doc if row else None) or {})


def keep(db: OrmSession, row_id: int, doc: dict[str, Any]) -> None:
    row = db.get(Setting, row_id)
    if row is None:
        db.add(Setting(id=row_id, doc=doc))
        # Written at once: the sessions of the server do not flush by themselves, and a second
        # call in the same transaction must find the row instead of adding it again.
        db.flush()
        return
    row.doc = doc
    flag_modified(row, "doc")


def read(db: OrmSession) -> dict[str, Any]:
    """The settings as kept, with the defaults where nothing was set."""
    doc = held(db, SETTINGS_ID)
    merged = {key: (dict(value) if isinstance(value, dict) else value) for key, value in DEFAULTS.items()}
    for key, value in doc.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def _whole(value: Any, low: int, high: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{what} is a whole number from {low} to {high}")
    return value


def write(db: OrmSession, sent: dict[str, Any], now: float | None = None) -> list[str]:
    """Keep what was sent (the keys that are there). Returns what changed, in words, for the audit log."""
    import time

    if not isinstance(sent, dict):
        raise ConfigError("The settings are not readable")
    doc = read(db)
    changed = []
    if "base" in sent:
        # A schedule is written as the one of the backups is: one way of saying "every day at".
        cleaned = backup_config._clean_schedule(sent["base"], doc["base"])
        if cleaned != doc["base"]:
            doc["base"] = cleaned
            doc["baseSetAt"] = time.time() if now is None else now
            changed.append("when the base backups are taken")
    if "keepDays" in sent:
        days = _whole(sent["keepDays"], 1, 60, "The number of days one can go back")
        if days != doc["keepDays"]:
            doc["keepDays"] = days
            changed.append("how far back one can go")
    if "lagMinutes" in sent:
        minutes = _whole(
            sent["lagMinutes"], 2, 24 * 60, "The delay of the second host that is warned about, in minutes,"
        )
        if minutes != doc["lagMinutes"]:
            doc["lagMinutes"] = minutes
            changed.append("the delay that is warned about")
    if "testEveryHours" in sent:
        hours = _whole(sent["testEveryHours"], 1, 24 * 30, "The hours between two recovery tests")
        if hours != doc["testEveryHours"]:
            doc["testEveryHours"] = hours
            changed.append("how often the archive is proven")
    if "name" in sent:
        name = sent["name"]
        if not isinstance(name, str) or len(name.strip()) > 120 or "\n" in name:
            raise ConfigError("The name of this server is a line of at most 120 characters")
        if name.strip() != doc["name"]:
            doc["name"] = name.strip()
            changed.append("the name of this server")
    if changed:
        keep(db, SETTINGS_ID, doc)
    return changed


def out(db: OrmSession) -> dict[str, Any]:
    doc = read(db)
    return {key: doc[key] for key in DEFAULTS}
