"""The keys of the server: what each protects, where it comes from, and changing one.

**What there is.** ``KEYS`` lists every secret the stack has. Two of them are
keys in the strict sense, and are the ones this module changes:

- ``SECRET_KEY`` encrypts the secrets kept in the database (``core/vault.py``);
- ``STORE_KEY`` seals the files of the store (``core/sealed.py``).

The backup passphrase is the third thing that encrypts, and lives in the
database (``backups/config.py``); the others are passwords between the
containers of the stack.

**Changing a key is done in two places, and each does what only it can.**
The server cannot write where its own keys are kept (a mounted secret is
read-only, and so is ``.env``), so the value changes on the host:
``deploy/secrets.sh rotate secret-key`` (or ``store-key``) asks the running
server for a new value (``new-key`` below: made here, written through a pipe
straight into the place keys live, never shown), keeps the old one beside it
as ``<NAME>_PREVIOUS``, and restarts the containers that hold the key. From
then on this module does the rest and shows it on the screen
(*Settings → Keys*):

- everything under the old key is put under the new one
  (``vault.reencrypt`` for the secrets of the database, ``rekey_snapshot`` for
  the snapshots taken before upgrades while no backup passphrase was set,
  ``store_seal.rewrap_pass`` for the files of the store);
- everything is then read back **under the new key alone**. Only when that
  holds is the change *verified*, written to the audit log and told to the
  administrators, and only then does the script remove the old key;
- until then the server holds both keys. Whatever stops in the middle, a
  secret is readable under the old key or under the new one, never under
  neither, and the next start goes on.

The screen is where the change is asked for (a signed-in administrator who
gives the password again, and a code when the account has a second factor):
the script says so when nobody asked, and goes on only if the operator says
to. The screen is also where its progress and its end are read.

Everything is kept in one row of ``settings`` (``SETTINGS_ID``). No value of
a key is ever written there, in a log, or in an answer: a key is spoken of by
its fingerprint, a few characters that are not a part of it.
"""

from __future__ import annotations

import atexit
import logging
import os
import secrets as random_source
import threading
import time
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session as OrmSession

from . import store_seal
from .core import keys, sealed, store, vault
from .core.config import settings

logger = logging.getLogger("nik.keys")

SETTINGS_ID = 51  # 50 is store_seal.py
LINK = "/settings/system/keys"
SYSTEM = "system"
REQUEST_LASTS = 24 * 3600
REKEY = ".rekey"

SECRET, STORE, AUDIT = "SECRET_KEY", "STORE_KEY", "AUDIT_KEY"
# The keys something is stored under: a change moves it all and proves it, with both keys held.
ROTATED = (SECRET, STORE)
# The keys a change of which is asked for on the screen and carried out by deploy/secrets.sh.
# The audit key is one of them and moves nothing: it signs from the next entry on, and the
# entries before it keep the key that signed them, which stays known to the server.
ASKED = (SECRET, STORE, AUDIT)
SLUGS = {SECRET: "secret-key", STORE: "store-key", AUDIT: "audit-key"}

# name, label, what it protects, which containers hold it.
KEYS: tuple[dict[str, Any], ...] = (
    {
        "name": SECRET,
        "label": "Secret key",
        "protects": "The secrets kept in the database: the keys and credentials of connector instances, stored "
        "credentials, the secrets of second factors, the backup passphrase and the key of the backup destination, "
        "the TLS key logs of captures. Also the snapshots taken before an upgrade while no backup passphrase is set.",
        "holders": ["api", "automation"],
    },
    {
        "name": STORE,
        "label": "Store key",
        "protects": "Every file of the store: samples, e-mails, captures and their logs, mailboxes, previews, "
        "screenshots, signatures. It is in no database and in no backup.",
        "holders": ["api"],
    },
    {
        "name": AUDIT,
        "label": "Audit key",
        "protects": "The signature of every entry of the audit log: whoever can write to the database can compute "
        "the chain of hashes again, not the signatures. A server that was given no key of its own signs with one "
        "derived from the secret key. It is in no database.",
        "holders": ["api", "automation"],
    },
    {
        "name": "DB_PASSWORD",
        "label": "Database password",
        "protects": "The connection to PostgreSQL. It is set when the database is first created.",
        "holders": ["db", "api", "automation"],
        "how": "Change it in PostgreSQL first (ALTER ROLE nik PASSWORD '…'), then where the keys are kept, then "
        "start the stack again.",
    },
    *(
        {
            "name": f"{worker}_TOKEN",
            "label": f"{label} token",
            "protects": f"What the backend says to the {label.lower()}, and nothing else: the worker answers only "
            "to who presents it.",
            "holders": holders,
            "how": "Put a new value where the keys are kept (deploy/secrets.sh rotate tokens writes all of them) "
            "and start the stack again: nothing is stored under it.",
        }
        for worker, label, holders in (
            ("ANALYZER", "Disassembly worker", ["api", "analyzer"]),
            ("CAPA", "capa worker", ["api", "capa"]),
            ("DOCVIEW", "Document worker", ["api", "docview"]),
            ("BROWSER", "Isolated browser", ["api", "browser"]),
            ("PCAP", "Packet capture worker", ["api", "pcap"]),
            ("SANDBOX", "Script sandbox", ["api", "automation", "sandbox"]),
        )
    ),
    {
        "name": "METRICS_TOKEN",
        "label": "Metrics token",
        "protects": "Who may read /api/metrics, beside the scrape token made in Settings → Health. Optional: "
        "without either the route answers to nobody.",
        "holders": ["api"],
        "how": "Put a new value where the keys are kept and start the api container again.",
    },
)


def _iso(at: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fingerprint(name: str) -> str:
    """The fingerprint of the key the server runs with: what two people compare, never part of it."""
    if name == STORE:
        return store.keyring().current.fingerprint if store.local() else ""
    if name == AUDIT:
        # The id the entries carry and the messages sent to syslog name: set-… or derived-….
        from .auditlog import key as signing

        return signing.current()[0]
    return sealed.fingerprint(SECRET, vault.key_id(settings.SECRET_KEY))


def _previous(name: str) -> list[str]:
    return list(settings.STORE_KEY_PREVIOUS if name == STORE else settings.SECRET_KEY_PREVIOUS)


# --------------------------------------------------------------------------- #
# The row                                                                     #
# --------------------------------------------------------------------------- #
def read(db: OrmSession) -> dict[str, Any]:
    from .core.models import Setting

    row = db.get(Setting, SETTINGS_ID)
    return dict((row.doc if row else None) or {})


def _write(db: OrmSession, doc: dict[str, Any]) -> None:
    from sqlalchemy.orm.attributes import flag_modified

    from .core.models import Setting

    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
        return
    row.doc = doc
    flag_modified(row, "doc")


def _tell_admins(db: OrmSession, kind: str, text: str) -> int:
    """Tell every administrator. Returns how many there were to tell."""
    from sqlalchemy import select

    from . import tasks
    from .core.models import User
    from .core.permissions import stored_roles

    told = 0
    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if "admin" in stored_roles(user.roles):
            tasks.notify(db, user.username, kind, text, LINK)
            told += 1
    return told


# --------------------------------------------------------------------------- #
# What a change of SECRET_KEY touches                                         #
# --------------------------------------------------------------------------- #
def _snapshots() -> list[Path]:
    """The backups of the directory that are encrypted under a key derived from ``SECRET_KEY``: the
    snapshots taken before an upgrade while no backup passphrase was set."""
    from .backups import runner
    from .backups.container import SECRET_KEY as FROM_SECRET_KEY
    from .backups.container import SUFFIX, BackupError, peek

    found = []
    folder = runner.directory()
    if folder.is_dir():
        for path in sorted(folder.glob(f"*{SUFFIX}")):
            try:
                if peek(path)["key"].get("from") == FROM_SECRET_KEY:
                    found.append(path)
            except (BackupError, OSError, KeyError):
                continue
    return found


def _under_current(path: Path) -> bool:
    from .backups.container import Secrets, WrongKey, peek

    try:
        Secrets(secret_keys=(settings.SECRET_KEY,)).key_for(peek(path)["key"])
        return True
    except WrongKey:
        return False


def rekey_snapshot(path: Path) -> bool:
    """Write a snapshot that is under an earlier ``SECRET_KEY`` again under the current one. True when
    it changed. It is written beside, read back whole with the new key alone and compared part by
    part with what was read, and only then takes the place of the old file."""
    from .backups.container import CHUNK, FORMAT, Key, Reader, Secrets, peek, walk
    from .backups.container import SECRET_KEY as FROM_SECRET_KEY

    header = peek(path)
    if header["key"].get("from") != FROM_SECRET_KEY or _under_current(path):
        return False
    beside = Path(f"{path}{REKEY}")
    about = {k: v for k, v in header.items() if k not in ("format", "cipher", "chunk", "nonce", "key")}
    try:
        from .backups.container import Writer

        with open(path, "rb") as source, open(beside, "wb") as out:
            reader = Reader(source, Secrets(secret_keys=(settings.SECRET_KEY, *settings.SECRET_KEY_PREVIOUS)))
            writer = Writer(out, Key.new(FROM_SECRET_KEY, settings.SECRET_KEY), about)
            for part in reader.parts():
                with writer.part(part.name) as target:
                    while piece := part.read(CHUNK):
                        target.write(piece)
            manifest = {k: v for k, v in (reader.manifest or {}).items() if k not in ("format", "parts")}
            writer.finish(manifest)
            out.flush()
            os.fsync(out.fileno())
            was = reader.found
        with open(beside, "rb") as source:
            now = walk(source, Secrets(secret_keys=(settings.SECRET_KEY,)))
        if now.get("parts") != was or now.get("format") != FORMAT:
            raise ValueError("what was written again is not what was read")
        os.replace(beside, path)
    finally:
        try:
            beside.unlink()
        except OSError:
            pass
    return True


def _after_rekey(db: OrmSession, path: Path) -> None:
    """The row and the note of a snapshot that was written again: its size, and its copy off the
    server, which is still under the old key and is sent again."""
    from .backups import runner
    from .backups.container import SUFFIX
    from .core.models import Backup

    name = path.name[: -len(SUFFIX)]
    size = path.stat().st_size
    note = runner.read_note(name)
    if note is not None:
        runner.write_note({**note, "size": size})
    row = db.get(Backup, name)
    if row is not None:
        row.size = size
        if row.offsite_state == "copied":
            row.offsite_state = "pending"


def audit_signed(db: OrmSession) -> dict[str, Any]:
    """How the entries of the audit log stand against the keys this server can make: how many each
    key signed (by its id, never the key), whether the server can still make it, and how many
    entries therefore cannot be checked."""
    from sqlalchemy import func, select

    from .auditlog import key as signing
    from .core.models import AuditEntry

    current, known = signing.current()[0], signing.known()
    by_key, unchecked, unsigned = [], 0, 0
    counted = db.execute(
        select(AuditEntry.key_id, func.count()).where(AuditEntry.seq.is_not(None)).group_by(AuditEntry.key_id)
    ).all()
    for key_id, count in sorted(counted, key=lambda row: (-int(row[1]), str(row[0] or ""))):
        if not key_id:
            unsigned += int(count)
            continue
        can = key_id.rsplit("-", 1)[-1] in known
        by_key.append({"keyId": key_id, "entries": int(count), "current": key_id == current, "known": can})
        unchecked += 0 if can else int(count)
    return {"byKey": by_key, "cannotBeChecked": unchecked, "unsigned": unsigned}


def audit_keys_to_carry(db: OrmSession) -> list[str]:
    """The earlier audit keys that leave with ``SECRET_KEY_PREVIOUS``: the keys derived from an
    earlier ``SECRET_KEY`` that signed entries of the log, and that the server could no longer make
    once that earlier key is taken away. Each as it is written in ``AUDIT_KEY_PREVIOUS``
    (``hex:…``). Secrets: they go to the place keys are kept and nowhere else.

    Without this, the end of a change of ``SECRET_KEY`` would turn every entry signed before it
    into one that cannot be checked, on a server whose audit key is the derived one."""
    from sqlalchemy import func, select

    from .auditlog import key as signing
    from .auditlog import verifier
    from .core.models import AuditEntry

    kept = {verifier.fingerprint(signing.current()[1]), verifier.fingerprint(signing.derived(settings.SECRET_KEY))}
    kept |= {verifier.fingerprint(verifier.key_bytes(text)) for text in signing._previous()}
    carry = []
    for secret in settings.SECRET_KEY_PREVIOUS:
        key = signing.derived(secret)
        mark = verifier.fingerprint(key)
        if mark in kept:
            continue
        signed = db.execute(
            select(func.count()).select_from(AuditEntry).where(AuditEntry.key_id == f"derived-{mark}")
        ).scalar()
        if signed:
            kept.add(mark)
            carry.append("hex:" + key.hex())
    return carry


def plan(db: OrmSession, name: str) -> dict[str, Any]:
    """What a change of this key will touch, counted now: what the screen shows before it is asked for."""
    if name == AUDIT:
        signed = audit_signed(db)
        entries = sum(entry["entries"] for entry in signed["byKey"]) + signed["unsigned"]
        return {
            "items": [
                {
                    "what": "entry of the audit log that keeps the key that signed it (nothing is signed again: "
                    "the new key signs from the next entry, the earlier one stays known to the server)",
                    "count": entries,
                },
            ],
            "total": 0,
            "restarts": ["api", "automation"],
            "command": f"deploy/secrets.sh rotate {SLUGS[AUDIT]}",
        }
    if name == STORE:
        found = store_seal.census()
        return {
            "items": [
                {"what": "file of the store (its head; the content is not rewritten)", "count": found["sealedFiles"]},
            ],
            "total": found["sealedFiles"],
            "restarts": ["api"],
            "command": f"deploy/secrets.sh rotate {SLUGS[STORE]}",
        }
    counts: dict[str, int] = {}
    for what, _token in vault.inventory(db):
        counts[what] = counts.get(what, 0) + 1
    snapshots = len(_snapshots())
    if snapshots:
        counts["snapshot taken before an upgrade (written again, whole)"] = snapshots
    return {
        "items": [{"what": what, "count": count} for what, count in sorted(counts.items())],
        "total": sum(counts.values()),
        "restarts": ["api", "automation"],
        "command": f"deploy/secrets.sh rotate {SLUGS[SECRET]}",
        # On a server that signs its audit log with the key derived from SECRET_KEY, the entries
        # signed so far keep that derived key: the script writes it beside the audit keys before
        # it takes the earlier SECRET_KEY away.
        "auditKeyDerived": not _audit_key_is_set(),
    }


def _audit_key_is_set() -> bool:
    from .auditlog import key as signing

    return signing.is_set()


def secret_needed(doc: dict[str, Any]) -> bool:
    """Whether the server holds an earlier ``SECRET_KEY`` that something may still be under."""
    if not settings.SECRET_KEY_PREVIOUS:
        return False
    return (doc.get("secret") or {}).get("verifiedFor") != fingerprint(SECRET)


def secret_pass(now: float | None = None, holder: str = store_seal.HOLDER) -> dict[str, Any]:
    """One pass of a change of ``SECRET_KEY``, when this process holds the lease: move what is left
    under an earlier key, then read everything back under the new one alone. Returns its progress."""
    from .core import audit
    from .core.db import SessionLocal

    with SessionLocal() as db:
        doc = read(db)
    if not secret_needed(doc) or not store_seal._acquire(now, holder):
        return doc.get("secret") or {}
    mine = fingerprint(SECRET)
    progress = dict(doc.get("secret") or {})
    if progress.get("to") != mine:
        progress = {"to": mine, "state": "running", "startedAt": _iso(time.time() if now is None else now), "moved": 0}
    progress["moved"] = int(progress.get("moved") or 0) + vault.reencrypt(SessionLocal)
    rewritten, failed = int(progress.get("snapshots") or 0), []
    with SessionLocal() as db:
        for path in _snapshots():
            try:
                if rekey_snapshot(path):
                    rewritten += 1
                    _after_rekey(db, path)
                    db.commit()
            except Exception as error:  # noqa: BLE001 - one file that cannot be read does not stop the others
                db.rollback()
                failed.append({"name": path.name, "reason": f"{type(error).__name__}: {error}"[:300]})
        progress["snapshots"] = rewritten
        # The proof: every secret reads under the new key alone. What no key the server holds can read
        # was lost before this change (an earlier one, done without its old key) and is said apart.
        counts: dict[str, int] = {}
        behind: dict[str, int] = {}
        lost: dict[str, int] = {}
        for what, token in vault.inventory(db):
            counts[what] = counts.get(what, 0) + 1
            if vault.reads_alone(token):
                continue
            target = behind if vault.decrypt(token) is not None else lost
            target[what] = target.get(what, 0) + 1
        for path in _snapshots():
            if not _under_current(path) and not any(entry["name"] == path.name for entry in failed):
                failed.append({"name": path.name, "reason": "it is still under an earlier key"})
        progress.update(total=sum(counts.values()), counts=counts, unreadable=lost, failed=failed)
        progress["done"] = progress["total"] - sum(behind.values())
        doc = read(db)
        if behind or failed:
            was = (doc.get("secret") or {}).get("state")
            progress["state"] = "failed" if failed else "running"
            doc["secret"] = progress
            _write(db, doc)
            if failed and was != "failed":
                said = (
                    f"The change of SECRET_KEY is not over: {len(failed)} snapshot(s) could not be written again "
                    f"under the new key (the first: {failed[0]['name']}: {failed[0]['reason']}). Keep the earlier key."
                )
                audit.record(db, SYSTEM, "key.rotate.failed", said, target=SECRET)
                _tell_admins(db, "keys.problem", said)
            db.commit()
            return progress
        progress.update(state="verified", verifiedFor=mine, verifiedAt=_iso(time.time()))
        doc["secret"] = progress
        doc.setdefault("requests", {}).pop(SECRET, None)
        seen = dict(doc.get("keys") or {})
        known = dict(seen.get(SECRET) or {})
        if known.get("fingerprint") != mine:
            known["since"] = progress["verifiedAt"]
        seen[SECRET] = {**known, "fingerprint": mine, "rotatedAt": progress["verifiedAt"]}
        doc["keys"] = seen
        _write(db, doc)
        apart = f" {sum(lost.values())} could be read by no key the server holds, as before the change." if lost else ""
        said = (
            f"SECRET_KEY was changed ({mine}): the {progress['total']} secret(s) of the database and "
            f"{rewritten} snapshot(s) are under the new key and were read back with it alone.{apart} The server "
            "no longer needs the earlier key. Keep it with the backups taken before now: the secrets inside them "
            "are under it."
        )
        audit.record(db, SYSTEM, "key.rotate.done", said, target=SECRET)
        _tell_admins(db, "keys.rotated", said)
        db.commit()
    return progress


# --------------------------------------------------------------------------- #
# Asking for a change, from the screen                                        #
# --------------------------------------------------------------------------- #
def request(db: OrmSession, name: str, actor: str, now: float | None = None) -> dict[str, Any]:
    """Write down that an administrator asked for this key to be changed (the caller commits).
    Returns what the screen shows next: what will be touched, and the command to run on the host."""
    from .core import audit

    now = time.time() if now is None else now
    doc = read(db)
    requests = dict(doc.get("requests") or {})
    requests[name] = {"by": actor, "at": _iso(now), "until": now + REQUEST_LASTS}
    if name == AUDIT:
        requests[name]["from"] = fingerprint(AUDIT)
    doc["requests"] = requests
    _write(db, doc)
    planned = plan(db, name)
    audit.record(
        db,
        actor,
        "key.rotate.request",
        f"Asked for {name} to be changed (a new key signs the audit log from the next entry on)"
        if name == AUDIT
        else f"Asked for {name} to be changed ({planned['total']} item(s) to put under the new key)",
        target=name,
    )
    return {"request": _request_out(requests[name], now), **planned}


def cancel(db: OrmSession, name: str, actor: str) -> None:
    from .core import audit

    doc = read(db)
    requests = dict(doc.get("requests") or {})
    if requests.pop(name, None) is not None:
        doc["requests"] = requests
        _write(db, doc)
        audit.record(db, actor, "key.rotate.cancel", f"Withdrew the request to change {name}", target=name)


def _request_out(entry: dict[str, Any] | None, now: float) -> dict[str, Any] | None:
    if not entry or float(entry.get("until") or 0) < now:
        return None
    return {"by": entry.get("by") or "", "at": entry.get("at") or "", "until": _iso(float(entry["until"]))}


def requested(db: OrmSession, name: str, now: float | None = None) -> dict[str, Any] | None:
    return _request_out((read(db).get("requests") or {}).get(name), time.time() if now is None else now)


# --------------------------------------------------------------------------- #
# What the screen shows                                                       #
# --------------------------------------------------------------------------- #
def _rotation(doc: dict[str, Any], store_doc: dict[str, Any], name: str) -> dict[str, Any]:
    """Where a change of this key stands: ``idle`` | ``running`` | ``failed`` | ``verified``."""
    progress = dict((store_doc.get("rewrap") if name == STORE else doc.get("secret")) or {})
    if not _previous(name):
        # No earlier key is held: nothing is in progress; the last change, if any, is history.
        # (The identifier of a store key is not shown: the screen shows fingerprints.)
        last = {k: v for k, v in progress.items() if name != STORE or k not in ("to", "verifiedFor")}
        return {"state": "idle", "last": last if progress.get("state") == "verified" else None}
    mine = fingerprint(name)
    reached = progress.get("verifiedFor")
    done = reached == (store.keyring().current.id.hex() if name == STORE else mine)
    state = (
        "verified" if done else (progress.get("state") if progress.get("state") in ("running", "failed") else "running")
    )
    return {
        "state": state,
        "previousKept": len(_previous(name)),
        "total": int(progress.get("total") or 0),
        "done": int(progress.get("done") or 0),
        "failed": progress.get("failed") or [],
        "startedAt": progress.get("startedAt") or "",
        "verifiedAt": progress.get("verifiedAt") or "",
        "unreadable": progress.get("unreadable") or {},
    }


def note_seen() -> None:
    """Write down which keys the server runs with, the first time each is seen: the date a key has
    been in use since, and (in ``_rotation``'s wake) when it last changed."""
    from .core.db import SessionLocal

    with SessionLocal() as db:
        doc = read(db)
        seen = dict(doc.get("keys") or {})
        changed = False
        for name in ASKED:
            mine = fingerprint(name)
            if not mine:
                continue
            entry = dict(seen.get(name) or {})
            if entry.get("fingerprint") != mine:
                # A key the row has not met: since now (a change done by hand is dated here too).
                entry = {"fingerprint": mine, "since": _iso(time.time()), "rotatedAt": entry.get("rotatedAt") or ""}
                if seen.get(name):
                    entry["rotatedAt"] = entry["since"]
                    if name == AUDIT:
                        # Nothing is moved when this key changes, so nothing else says it happened.
                        # The entry is itself among the first the new key signs.
                        from .core import audit

                        was = str((seen.get(name) or {}).get("fingerprint") or "")
                        said = (
                            f"The audit log is signed with another key from now on ({mine}; until now {was}). "
                            "The entries before this keep the key that signed them"
                        )
                        audit.record(db, SYSTEM, "key.rotate.done", said, target=AUDIT)
                        _tell_admins(db, "keys.rotated", said + ".")
                seen[name] = entry
                changed = True
            elif not entry.get("since"):
                entry["since"] = _iso(time.time())
                seen[name] = entry
                changed = True
        # A change of the store key that was asked for from the screen and is over: the request
        # has been used (the change of SECRET_KEY takes its own away when it is verified).
        requests = dict(doc.get("requests") or {})
        rewrap = store_seal.read(db).get("rewrap") or {}
        if (
            STORE in requests
            and settings.STORE_KEY
            and rewrap.get("verifiedFor") == store.keyring().current.id.hex()
            and str(rewrap.get("verifiedAt") or "") >= str(requests[STORE].get("at") or "")
        ):
            requests.pop(STORE)
            doc["requests"] = requests
            changed = True
        # A change of the audit key is over once the server runs with another key than the one it
        # had when the change was asked for.
        asked = requests.get(AUDIT) or {}
        if asked and asked.get("from") and asked["from"] != fingerprint(AUDIT):
            requests.pop(AUDIT)
            doc["requests"] = requests
            changed = True
        if changed:
            doc["keys"] = seen
            _write(db, doc)
            db.commit()


def overview(db: OrmSession) -> dict[str, Any]:
    """Everything *Settings → Keys* shows. Never a value, never a part of one."""
    from .backups import config as backup_config

    doc, store_doc = read(db), store_seal.read(db)
    now = time.time()
    seen = doc.get("keys") or {}
    out = []
    for key in KEYS:
        name = key["name"]
        source = keys.source(name)
        entry: dict[str, Any] = {
            "name": name,
            "label": key["label"],
            "protects": key["protects"],
            "holders": key["holders"],
            "source": source,
            "set": source != keys.DEFAULT,
            "rotates": name in ASKED,
            "how": key.get("how") or "",
        }
        if name == AUDIT:
            from .auditlog import key as signing

            entry.update(
                fingerprint=fingerprint(AUDIT),
                # Without a key of its own the server signs with one made from SECRET_KEY.
                derived=not entry["set"],
                since=(seen.get(name) or {}).get("since") or "",
                rotatedAt=(seen.get(name) or {}).get("rotatedAt") or "",
                # Nothing is moved by a change of this key: it is never half-way.
                rotation={"state": "idle", "previousKept": len(signing._previous()), "last": None},
                request=_request_out((doc.get("requests") or {}).get(name), now),
                command=f"deploy/secrets.sh rotate {SLUGS[name]}",
                signed=audit_signed(db),
            )
        if name in ROTATED:
            entry.update(
                fingerprint=fingerprint(name),
                since=(seen.get(name) or {}).get("since") or "",
                rotatedAt=(seen.get(name) or {}).get("rotatedAt") or "",
                rotation=_rotation(doc, store_doc, name),
                request=_request_out((doc.get("requests") or {}).get(name), now),
                command=f"deploy/secrets.sh rotate {SLUGS[name]}",
            )
        out.append(entry)
    backups = backup_config.read(db)
    in_environment = [entry["name"] for entry in out if entry["source"] == keys.ENVIRONMENT]
    return {
        "keys": out,
        "backupPassphrase": {
            "set": bool(backups.get("passphrase")),
            "setAt": _iso(float(backups["passphraseSetAt"])) if backups.get("passphraseSetAt") else "",
            "earlierKept": len(backups.get("previous") or []),
        },
        "inEnvironment": in_environment,
        "moveCommand": "deploy/secrets.sh move",
        "store": store_seal.status(db),
    }


def health(db: OrmSession) -> dict[str, Any]:
    """What a health page can show of the keys and of the encryption of the store, in a few values."""
    seen = overview(db)
    held = seen["store"]
    return {
        "storeEncrypted": bool(held.get("encrypted")),
        "storeState": held.get("state"),
        "storeLeft": held.get("left"),
        "storeStuck": held.get("stuckCount"),
        "damagedFiles": len(held.get("damaged") or []),
        "keysInEnvironment": seen["inEnvironment"],
        "rotations": {
            entry["name"]: entry["rotation"]["state"] for entry in seen["keys"] if entry.get("rotation") is not None
        },
        "backupPassphraseSet": seen["backupPassphrase"]["set"],
    }


def keys_state(db: OrmSession) -> list[dict[str, Any]]:
    """One fact for a health page: for each secret of the server, where it comes from (``file``,
    ``environment`` or ``default`` when none was given) and, for the two keys that are changed with
    a procedure, since when the one in use is in use, when it last changed and where a change stands
    (``idle`` | ``running`` | ``failed`` | ``verified``). Never a value."""
    return [
        {
            "name": entry["name"],
            "source": entry["source"],
            "set": entry["set"],
            "since": entry.get("since") or "",
            "rotatedAt": entry.get("rotatedAt") or "",
            "rotation": entry["rotation"]["state"] if entry.get("rotation") is not None else None,
        }
        for entry in overview(db)["keys"]
    ]


def store_encryption(db: OrmSession) -> dict[str, Any]:
    """The other fact: how far the encryption of the store is, and whether anything in clear
    remains. ``clearRemains`` is False only once the server walked the store and found every file
    sealed; ``left`` is what is still to seal, ``stuck`` the files it could not, ``damaged`` those
    that failed their check since."""
    held = store_seal.status(db)
    return {
        "state": held["state"],
        "clearRemains": not held["encrypted"],
        "total": held["total"],
        "done": held["done"],
        "left": held["left"],
        "secondsLeft": held["secondsLeft"],
        "stuck": held["stuckCount"],
        "damaged": len(held["damaged"]),
        "pausedBy": held["pausedBy"],
        "sealedSince": held["since"],
    }


# --------------------------------------------------------------------------- #
# The loop of the API process                                                 #
# --------------------------------------------------------------------------- #
_started = False


def tell_environment() -> bool:
    """Tell the administrators, once, that the keys of this server are in its environment and how to
    move them. Says whether it did."""
    from .core.db import SessionLocal

    held = [name for name in (SECRET, STORE, "DB_PASSWORD") if keys.source(name) == keys.ENVIRONMENT]
    if not held:
        return False
    with SessionLocal() as db:
        doc = read(db)
        if doc.get("environmentTold"):
            return False
        told = _tell_admins(
            db,
            "keys.environment",
            "The keys of this server are in the environment of its containers (the .env file): whoever can inspect a "
            "container reads them. deploy/secrets.sh move puts them in files that only the containers which need "
            "them are given. Nothing changes until you run it; Settings → Keys says where each key is.",
        )
        if not told:
            # A server nobody has an account on yet: said once there is somebody to say it to.
            db.rollback()
            return False
        doc["environmentTold"] = _iso(time.time())
        _write(db, doc)
        db.commit()
    return True


def _loop() -> None:
    time.sleep(8)  # let the server start
    last_slow = 0.0
    while True:
        wait = 20.0
        try:
            doc = store_seal.convert_pass()
            if doc.get("state") == store_seal.CONVERTING and float(doc.get("retryAt") or 0) < time.time():
                wait = 1.0
            if store_seal.rewrap_needed(doc or {}) and store_seal.rewrap_pass().get("state") == "running":
                wait = 1.0
            if secret_pass().get("state") == "running":
                wait = 5.0
            if time.monotonic() - last_slow > 60 and store_seal._acquire():
                last_slow = time.monotonic()
                store_seal._note_disk()
                note_seen()
                tell_environment()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("A pass of the keys and of the encryption of the store failed")
        time.sleep(wait)


def _let_go() -> None:
    """At a clean stop, give the lease back: the process that starts next does not wait two minutes
    for it to run out before it goes on with a conversion or a change of key (a restart is part of
    every change of key)."""
    from .backups import runner
    from .core.db import SessionLocal

    try:
        with SessionLocal() as db:
            runner.release(db, store_seal.HOLDER, store_seal.LEASE)
    except Exception:  # noqa: BLE001 - stopping anyway; the lease runs out by itself
        pass


def start() -> None:
    """Start the loop of the API process (once): the conversion of the store, the changes of keys."""
    global _started
    if _started or not store.local():
        return
    _started = True
    atexit.register(_let_go)
    threading.Thread(target=_loop, name="nik-keys", daemon=True).start()


# --------------------------------------------------------------------------- #
# What deploy/secrets.sh asks the running server                              #
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    """``python -m app.key_rotation new-key | status NAME | requested NAME | audit-carry | audit-unchecked``.

    ``new-key`` prints a new key on standard output and nothing else: the
    script that asks pipes it into the place keys live. ``status`` prints one
    word (``idle``, ``running``, ``failed``, ``verified``) and, on the next
    lines, what a person wants to know. ``requested`` exits 0 when an
    administrator asked for the change on the screen. ``audit-carry`` prints the
    earlier audit keys that would leave with ``SECRET_KEY_PREVIOUS`` (secrets,
    one a line, as ``AUDIT_KEY_PREVIOUS`` takes them); ``audit-unchecked`` how
    many entries of the audit log this server cannot check for want of their key.
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="python -m app.key_rotation")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("new-key")
    commands.add_parser("status").add_argument("name", choices=ROTATED)
    commands.add_parser("requested").add_argument("name", choices=ASKED)
    commands.add_parser("audit-carry")
    commands.add_parser("audit-unchecked")
    args = parser.parse_args(argv)
    if args.command == "new-key":
        sys.stdout.write(random_source.token_hex(32) + "\n")
        return 0
    from .core.db import SessionLocal

    with SessionLocal() as db:
        if args.command == "audit-carry":
            # Secrets, one a line, for the script that pipes them where the keys are kept.
            for text in audit_keys_to_carry(db):
                sys.stdout.write(text + "\n")
            return 0
        if args.command == "audit-unchecked":
            print(audit_signed(db)["cannotBeChecked"])
            return 0
        if args.command == "requested":
            asked = requested(db, args.name)
            if asked is None:
                return 1
            print(f"asked for by {asked['by']} at {asked['at']}")
            return 0
        rotation = _rotation(read(db), store_seal.read(db), args.name)
    print(rotation["state"])
    if rotation["state"] != "idle":
        # Nothing is counted before the first pass of the server; then how far it is.
        print(
            f"{rotation.get('done', 0)} of {rotation['total']} under the new key"
            if rotation.get("total")
            else "the server has not counted yet"
        )
        for entry in rotation.get("failed") or []:
            print(f"failed: {entry.get('name')}: {entry.get('reason')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
