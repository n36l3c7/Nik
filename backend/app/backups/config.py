"""What an administrator sets about backups, and how it is kept.

One row of ``settings`` (``SETTINGS_ID``) holds the schedule, the retention,
the passphrase and the place the copy off the server goes to.

**The passphrase** is what every backup is encrypted under. It is not
``SECRET_KEY``: a backup must be readable on a host that never had this
server's ``.env``. It is kept here encrypted with the vault key, so that the
backups of the night can run without anybody typing it; whoever restores on
another host types it again, which is why the screen says to write it down.
When it is changed the earlier ones stay (encrypted the same way), because
the backups made under them are still on the disk and still have to be
tested and restored.

**The destination** is described by a kind and its own fields; today the
kind is ``sftp`` (``offsite.py``). Its secret, a private key or a password,
is kept as the passphrase is, or is the name of a stored credential written
as it is in a field of an instance (``{{ credentials.backup_host }}``).
"""

from __future__ import annotations

import re
import time
from typing import Any

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core import vault
from ..core.config import settings
from ..core.models import Setting
from . import policy
from .container import Secrets

SETTINGS_ID = 20  # 1 to 4 are taken (worker_watch.py lists them); 21 is watch.py, 22 upgrade.py
PASSPHRASE_MIN = 12
PASSPHRASE_MAX = 1000
PREVIOUS_KEPT = 10

DEFAULTS: dict[str, Any] = {
    "schedule": {"enabled": True, "every": "day", "hours": 6, "at": "02:30", "weekday": 6, "timezone": "UTC"},
    "retention": {"last": 7, "weeks": 4, "upgrades": 3},
    # The administrators are told when the last good backup is older than this.
    "warnAfterHours": 36,
    "includeKey": False,
    "destination": {"kind": ""},
}
EVERY = ("hours", "day", "week")
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$")
_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")
_KEY_LINE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+=*$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?$")


class ConfigError(ValueError):
    """What was sent cannot be kept: a sentence for the person who sent it."""


def _row(db: OrmSession) -> Setting | None:
    return db.get(Setting, SETTINGS_ID)


def read(db: OrmSession) -> dict[str, Any]:
    """The settings as kept, with the defaults where nothing was set."""
    row = _row(db)
    doc = dict((row.doc if row else None) or {})
    merged = {key: (dict(value) if isinstance(value, dict) else value) for key, value in DEFAULTS.items()}
    for key, value in doc.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def _keep(db: OrmSession, doc: dict[str, Any]) -> None:
    row = _row(db)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
        return
    row.doc = doc
    flag_modified(row, "doc")


# --------------------------------------------------------------------------- #
# The passphrase                                                              #
# --------------------------------------------------------------------------- #
def passphrase(db: OrmSession) -> str | None:
    """The backup passphrase, or None when none is set (or ``SECRET_KEY`` changed and it cannot be read)."""
    token = read(db).get("passphrase")
    return vault.decrypt(token) if token else None


def secrets(db: OrmSession | None) -> Secrets:
    """Everything a backup of this server may be opened with: the passphrase and the earlier
    ones, ``SECRET_KEY`` and the earlier ones."""
    tokens: list[str] = []
    if db is not None:
        doc = read(db)
        tokens = [doc.get("passphrase") or "", *(doc.get("previous") or [])]
    phrases = tuple(filter(None, (vault.decrypt(token) for token in tokens if token)))
    return Secrets(passphrases=phrases, secret_keys=(settings.SECRET_KEY, *settings.SECRET_KEY_PREVIOUS))


def set_passphrase(db: OrmSession, value: Any, now: float | None = None) -> None:
    if not isinstance(value, str) or len(value) < PASSPHRASE_MIN:
        raise ConfigError(f"The passphrase needs at least {PASSPHRASE_MIN} characters")
    if len(value) > PASSPHRASE_MAX or value != value.strip() or "\n" in value or "\r" in value:
        raise ConfigError("The passphrase cannot start or end with a space, hold a line break, or be that long")
    doc = read(db)
    current = doc.get("passphrase")
    if current and vault.decrypt(current) == value:
        return
    if current:
        doc["previous"] = [current, *(doc.get("previous") or [])][:PREVIOUS_KEPT]
    doc["passphrase"] = vault.encrypt(value)
    doc["passphraseSetAt"] = time.time() if now is None else now
    _keep(db, doc)


# --------------------------------------------------------------------------- #
# The rest                                                                    #
# --------------------------------------------------------------------------- #
def _whole(value: Any, low: int, high: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{what} is a whole number from {low} to {high}")
    return value


def _clean_schedule(sent: Any, before: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sent, dict):
        raise ConfigError("The schedule is not readable")
    merged = {**before, **sent}
    if merged.get("every") not in EVERY:
        raise ConfigError("A backup is taken every day, every week or every few hours")
    if not _TIME.match(str(merged.get("at") or "")):
        raise ConfigError("The time of the backup is written HH:MM, from 00:00 to 23:59")
    name = str(merged.get("timezone") or "UTC").strip()
    if not policy.known_zone(name):
        raise ConfigError(f"{name} is not a time zone Nik knows (Europe/Rome, UTC, America/New_York …)")
    return {
        "enabled": bool(merged.get("enabled")),
        "every": merged["every"],
        "hours": _whole(merged.get("hours"), 1, 23, "The number of hours between two backups"),
        "at": merged["at"],
        "weekday": _whole(merged.get("weekday"), 0, 6, "The day of the week"),
        "timezone": name,
    }


def _clean_retention(sent: Any, before: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sent, dict):
        raise ConfigError("The retention is not readable")
    merged = {**before, **sent}
    return {
        "last": _whole(merged.get("last"), 1, 365, "The number of backups kept"),
        "weeks": _whole(merged.get("weeks"), 0, 520, "The number of weeks one backup a week is kept for"),
        "upgrades": _whole(merged.get("upgrades"), 1, 50, "The number of snapshots kept from before upgrades"),
    }


def _clean_secret(db: OrmSession, sent: Any, before: str) -> str:
    """The secret of a destination as it is kept: a reference to a stored credential, as written;
    a value typed, encrypted; nothing sent, what was there."""
    from ..automation import credentials

    if sent is None:
        return before
    if not isinstance(sent, str) or len(sent) > 20_000:
        raise ConfigError("The key or password of the destination is not readable")
    if not sent.strip():
        return ""
    found = credentials.reference(sent)
    if found is not None:
        row = credentials.by_name(db, found.name)
        if row is None:
            raise ConfigError(f"There is no stored credential named {found.name}")
        if (row.kind == "pair") != (found.part == "password"):
            raise ConfigError(
                "Name a secret as {{ credentials.<name> }}, or the password of a pair as "
                "{{ credentials.<name>.password }}"
            )
        return found.text
    if credentials.mentions(sent):
        raise ConfigError(credentials.HOW)
    return "vault:" + vault.encrypt(sent.replace("\r\n", "\n"))


def destination_secret(db: OrmSession, destination: dict[str, Any]) -> str:
    """The key or password of the destination, in clear, at the moment it is used."""
    from ..automation import credentials

    kept = str(destination.get("secret") or "")
    if kept.startswith("vault:"):
        value = vault.decrypt(kept[len("vault:") :])
        if value is None:
            raise ConfigError("The key of the destination cannot be read any more (SECRET_KEY changed): enter it again")
        return value
    found = credentials.reference(kept)
    if found is None:
        return ""
    row = credentials.by_name(db, found.name)
    value = vault.decrypt(row.secret) if row is not None and row.secret else None
    if value is None:
        raise ConfigError(f"The stored credential {found.name} the destination names is not there or cannot be read")
    return value


def _clean_destination(db: OrmSession, sent: Any, before: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sent, dict):
        raise ConfigError("The destination is not readable")
    kind = sent.get("kind", before.get("kind") or "")
    if kind == "":
        return {"kind": ""}
    if kind != "sftp":
        raise ConfigError("The copy off the server goes to an SFTP server, or nowhere")
    merged = {**(before if before.get("kind") == "sftp" else {}), **sent}
    host = str(merged.get("host") or "").strip()
    user = str(merged.get("user") or "").strip()
    if not _HOST.match(host):
        raise ConfigError("The host of the destination is a name or an address")
    if not _USER.match(user):
        raise ConfigError("The account on the destination is a user name")
    port = _whole(merged.get("port", 22), 1, 65535, "The port of the destination")
    auth = merged.get("auth") or "key"
    if auth not in ("key", "password"):
        raise ConfigError("The account of the destination signs in with a key or with a password")
    path = str(merged.get("path") or "").strip()
    if not path or len(path) > 500 or "\n" in path or ".." in path.split("/"):
        raise ConfigError("The directory on the destination is a path, like /srv/nik-backups or backups")
    host_key = " ".join(str(merged.get("hostKey") or "").split()[:2])
    if host_key and not (_KEY_LINE.match(host_key) or _FINGERPRINT.match(host_key)):
        raise ConfigError(
            "The host key is the line the server publishes (ssh-ed25519 AAAA…) or its fingerprint (SHA256:…)"
        )
    secret = _clean_secret(
        db, sent.get("secret"), str(before.get("secret") or "") if before.get("auth") == auth else ""
    )
    return {
        "kind": "sftp",
        "host": host,
        "port": port,
        "user": user,
        "auth": auth,
        "path": path.rstrip("/") or "/",
        "hostKey": host_key,
        "secret": secret,
    }


def ready(destination: dict[str, Any]) -> bool:
    """Whether copies can be sent: a destination with its secret and a host key to hold it to."""
    return destination.get("kind") == "sftp" and bool(destination.get("secret")) and bool(destination.get("hostKey"))


def write(db: OrmSession, sent: dict[str, Any], now: float | None = None) -> list[str]:
    """Keep what was sent (the keys that are there). Returns what changed, in words, for the audit log."""
    if not isinstance(sent, dict):
        raise ConfigError("The settings are not readable")
    doc = read(db)
    changed = []
    if "schedule" in sent:
        cleaned = _clean_schedule(sent["schedule"], doc["schedule"])
        if cleaned != doc["schedule"]:
            doc["schedule"] = cleaned
            # A slot that passed before this moment is not owed under the new schedule.
            doc["scheduleSetAt"] = time.time() if now is None else now
            changed.append("the schedule")
    if "retention" in sent:
        cleaned = _clean_retention(sent["retention"], doc["retention"])
        if cleaned != doc["retention"]:
            doc["retention"] = cleaned
            changed.append("the retention")
    if "warnAfterHours" in sent:
        hours = _whole(sent["warnAfterHours"], 1, 24 * 60, "The age the last good backup may reach, in hours,")
        if hours != doc["warnAfterHours"]:
            doc["warnAfterHours"] = hours
            changed.append("the age that is warned about")
    if "includeKey" in sent:
        if not isinstance(sent["includeKey"], bool):
            raise ConfigError("Including SECRET_KEY is yes or no")
        if sent["includeKey"] != doc["includeKey"]:
            doc["includeKey"] = sent["includeKey"]
            changed.append("SECRET_KEY is now included" if sent["includeKey"] else "SECRET_KEY is no longer included")
    if "destination" in sent:
        cleaned = _clean_destination(db, sent["destination"], doc.get("destination") or {})
        if cleaned != doc.get("destination"):
            doc["destination"] = cleaned
            changed.append("the destination of the copy off the server")
    if changed:
        _keep(db, doc)
    return changed


def out(db: OrmSession) -> dict[str, Any]:
    """The settings as the screen shows them: no secret, only whether one is set."""
    from ..automation import credentials

    doc = read(db)
    destination = dict(doc.get("destination") or {"kind": ""})
    kept = str(destination.pop("secret", "") or "")
    if destination.get("kind"):
        found = credentials.reference(kept)
        destination["secretSet"] = bool(kept)
        destination["secretCredential"] = found.text if found else ""
        destination["ready"] = ready({**destination, "secret": kept})
    set_at = doc.get("passphraseSetAt")
    return {
        "schedule": doc["schedule"],
        "retention": doc["retention"],
        "warnAfterHours": doc["warnAfterHours"],
        "includeKey": bool(doc["includeKey"]),
        "destination": destination,
        "passphraseSet": bool(doc.get("passphrase")),
        # Set, but under a SECRET_KEY that is no longer the server's: it has to be typed again.
        "passphraseReadable": bool(doc.get("passphrase")) and passphrase(db) is not None,
        "passphraseSetAt": set_at,
        "passphraseMin": PASSPHRASE_MIN,
    }
