"""Indicators found by themselves in what an incident was made of.

When an incident comes in, its fields and its context are read and what is an
indicator there (``recognise.py``) becomes one of the incident, with a source
that says it was found and where: ``found:context.ext.sentinelone.threat.url``.
The path is the one the Context tab shows and a playbook writes.

**The doors.** Every way an incident is made ends with ``scan``: a fetch
(``fetch.create_incident``, which is the Mail connector's door too), the API
and a person (``routers/incidents.create_incident``), a playbook
(``nik.create-incident``). What a connector writes later to an incident that
was read once (a mirror update: ``context.apply`` and ``fields.update`` with a
``connector:`` source) is read again by ``after_update``. What a playbook or a
command writes to the context is **not** read: a playbook that wants
indicators of a value asks for them (``nik.make-indicators``), and nothing a
run writes can start the run again through here.

**One reading for one update.** A mirror's read writes field after field,
then the context, then the comments that came: inside ``together`` all of it
is read once, at the end, and only when something changed. What the other
side *said* (a comment a mirror brought, a reply a mailbox mirror took in as
a line of the War Room) is read with it, under the path ``warroom.mirror``:
it is in neither the fields nor the context. Reading writes no field of the
incident, so nothing it finds is ever sent to the other side.

It is part of the transaction that makes or updates the incident: no thread, no
queue, nothing a restart can lose. It is bounded instead: 5,000 strings and
2 MB of an incident are read, and what was not is said.

**It must not flood.** A setting (row 80; *Settings, Indicators found*) says
whether incidents are read at all (on by default), which types are kept,
that what the recogniser marks is left out (private and reserved addresses;
names kept for documentation, schema hosts, the organisation's own domains and
the IOC allowlist), which paths are never read, and how many indicators an
incident may be given this way. Past that number nothing more is kept and the
War Room says how many were not. An instance of a connector can be told
apart from the setting: on, off, or as the setting says.

**One line, not one per indicator.** A reading that found something leaves one
line in the War Room ("12 indicators found: 5 domains, 4 URLs, 3 hashes; 40
left out as private or benign") and one entry in the audit log.

**A playbook can wait for it.** A reading that kept something new writes one
``indicators.found`` event, in its own transaction, with the incident, the
door, how many of each type and the first hundred of them. It cannot feed
itself: what a run writes to the context starts no reading; an incident a run
makes is read, and its event names the run, which its own playbook never
starts on; and a reading that finds nothing new, which is every reading of the
same values, writes no event at all. What can still go round is a playbook
that makes the *other system* say something new each time (a comment with new
addresses, read by the mirror): each turn needs values the incident does not
hold yet, and stops for good at the limit of the setting, besides the
playbook's own runs per hour.

**A person's no is remembered.** Removing a found indicator from its incident
keeps the row, marked: the value is not found again at the next update.

**Look-ups.** Finding an indicator asks nothing of any source. The automatic
look-ups (off until an administrator turns them on, per type) leave out the
indicators an incident holds only because they were found, unless the setting
says otherwise (``lookUps``): a source's quota is not spent, and no value is
sent out, for something nobody chose. A person's "Check now" and a playbook
ask as they always did, under the rule of the look-ups and the data guard.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import recognise
from .core import audit, clock
from .core.models import Connection, FoundIndicator, FoundScan, Incident, IocEntry, Setting
from .core.security import now_iso
from .iocs import TYPES

SETTINGS_ID = 80
SOURCE = "found:"
CAP_DEFAULT = 500
CAP_MAX = 1000
STRINGS_MAX = 5000  # strings of one incident that are read
STRING_MAX = 20_000  # characters of one string
BYTES_MAX = 2_000_000  # characters of one incident, all strings together
SKIP_MAX = 100
PATH_MAX = 400
SAID_MAX = 200  # things the other side said that one reading takes
# Where something the other side said was read: a line of the War Room a mirror brought.
SAID_PATH = "warroom.mirror"
# The mark, on a session, of an update that is read once when it is whole (``together``).
_HELD = "indicators_found.together"
DOORS = ("fetch", "api", "hand", "playbook", "mirror", "asked")

# Keys that are noise by their nature. An entry with no dot is the name of a key, wherever it is;
# one with dots is a whole path, without the numbers of a list. ``*`` stands for anything.
SKIP_DEFAULT = (
    # Nik's own address of the incident, where it came from (the id of an instance is 32 hex
    # characters), and the other system's address of its ticket or alert.
    "incident.id",
    "incident.url",
    "incident.source_*",
    "incident.mirror_*",
    "context.Ticket.URL",
    "context.Alert.URL",
    # Links to a console, and the address a document gives for its own schema.
    "console*",
    "*consoleurl",
    "permalink",
    "*link",
    "*href",
    "self",
    "$schema",
    "xmlns*",
    # Identifiers: 32 hex characters are an agent's id far more often than an MD5.
    "*id",
    "*uuid",
    "*guid",
    "*token",
    "*signature",
    # Versions: four numbers with dots are an agent's version (23.4.2.14) as often as an address.
    "*version",
    "*build",
)
DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "types": list(TYPES),
    "leaveOutPrivate": True,
    "leaveOutBenign": True,
    "cap": CAP_DEFAULT,
    "skip": list(SKIP_DEFAULT),
    "lookUps": False,
    "instances": {},
}
_BARE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NOUNS = {
    "ip": ("address", "addresses"),
    "domain": ("domain", "domains"),
    "url": ("URL", "URLs"),
    "email": ("e-mail address", "e-mail addresses"),
    "hash": ("hash", "hashes"),
}


class FoundError(ValueError):
    """What is wrong with a setting, as a sentence for whoever sent it."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# --------------------------------------------------------------------------- #
# The setting                                                                 #
# --------------------------------------------------------------------------- #
def config(db: OrmSession) -> dict[str, Any]:
    """The setting, with what was never set filled from the defaults."""
    row = db.get(Setting, SETTINGS_ID)
    held = row.doc if row is not None and isinstance(row.doc, dict) else {}
    out = {key: held.get(key, value) for key, value in DEFAULTS.items()}
    out["types"] = [kind for kind in TYPES if kind in (out["types"] or [])]
    out["skip"] = [str(entry) for entry in out["skip"] or []]
    out["instances"] = {str(key): bool(value) for key, value in (out["instances"] or {}).items()}
    return out


def clean(body: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """The setting as it is stored, from what was sent: a key left out keeps what it had.
    Raises ``FoundError``."""
    out = dict(current)
    for name in ("enabled", "leaveOutPrivate", "leaveOutBenign", "lookUps"):
        if body.get(name) is not None:
            if not isinstance(body[name], bool):
                raise FoundError(f'"{name}" is true or false')
            out[name] = body[name]
    if body.get("types") is not None:
        wanted = body["types"]
        if not isinstance(wanted, list) or any(kind not in TYPES for kind in wanted):
            raise FoundError("The types are among: " + ", ".join(TYPES))
        out["types"] = [kind for kind in TYPES if kind in wanted]
    if body.get("cap") is not None:
        cap = body["cap"]
        if isinstance(cap, bool) or not isinstance(cap, int) or not 1 <= cap <= CAP_MAX:
            raise FoundError(f"An incident is given between 1 and {CAP_MAX} indicators this way")
        out["cap"] = cap
    if body.get("skip") is not None:
        skip = body["skip"]
        if not isinstance(skip, list) or len(skip) > SKIP_MAX:
            raise FoundError(f"The paths that are not read are a list of {SKIP_MAX} at most")
        kept: list[str] = []
        for entry in skip:
            text = str(entry or "").strip()
            if not text:
                continue
            if len(text) > 200 or any(char.isspace() for char in text):
                raise FoundError(f'"{text[:60]}" is not a path: a key or a path with dots, * for anything, no spaces')
            if text not in kept:
                kept.append(text)
        out["skip"] = kept
    return out


def save(db: OrmSession, doc: dict[str, Any]) -> None:
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
    else:
        row.doc = doc
        flag_modified(row, "doc")


def set_instance(db: OrmSession, connection: Connection, enabled: bool | None) -> dict[str, Any]:
    """Tell one instance apart from the setting (the caller commits): on, off, or None for as the
    setting says. Instances that are gone are dropped from what is kept."""
    current = config(db)
    there = set(db.scalars(select(Connection.id)))
    instances = {key: value for key, value in current["instances"].items() if key in there}
    if enabled is None:
        instances.pop(connection.id, None)
    else:
        instances[connection.id] = bool(enabled)
    current["instances"] = instances
    save(db, current)
    return current


def on_for(cfg: dict[str, Any], incident: Incident) -> bool:
    """Whether the incidents of where this one came from are read: its instance's word when it
    has one, the setting's otherwise."""
    said = cfg["instances"].get(incident.source_connection_id or "")
    return cfg["enabled"] if said is None else said


# --------------------------------------------------------------------------- #
# Reading an incident                                                         #
# --------------------------------------------------------------------------- #
def _step(key: Any) -> str:
    """A step of a path as an expression writes it: ``.name``, ``["a key"]`` or ``[0]``."""
    if isinstance(key, int):
        return f"[{key}]"
    if _BARE.fullmatch(key):
        return f".{key}"
    quoted = key.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return f'["{quoted}"]'


def path_of(root: str, keys: tuple) -> str:
    """``context.Ticket[0].Number`` from its steps: the path a playbook writes."""
    return root + "".join(_step(key) for key in keys)


def _skipped(root: str, keys: tuple, skip: list[str]) -> bool:
    names = [str(key) for key in keys if not isinstance(key, int)]
    if not names:
        return False
    last = names[-1].lower()
    whole = ".".join([root, *names]).lower()
    for entry in skip:
        pattern = entry.lower()
        if fnmatch.fnmatchcase(whole if "." in pattern else last, pattern):
            return True
    return False


def strings(material: dict[str, Any], skip: list[str]) -> Iterator[tuple[str, str]]:
    """``(path, text)`` for every string of an incident that is read, in the order they are
    kept when there are too many: the common schema of the context, the fields, ``ext``, then
    what the other side said in this update."""
    context = material.get("context") if isinstance(material.get("context"), dict) else {}
    fields = material.get("incident") if isinstance(material.get("incident"), dict) else {}
    parts = [("context", (key,), value) for key, value in context.items() if key != "ext"]
    parts += [("incident", (key,), value) for key, value in fields.items()]
    parts += [("context", ("ext",), context["ext"])] if "ext" in context else []
    stack = list(reversed(parts))
    while stack:
        root, keys, value = stack.pop()
        if isinstance(value, str):
            if value and not _skipped(root, keys, skip):
                yield path_of(root, keys), value
        elif isinstance(value, dict):
            if not _skipped(root, keys, skip):
                stack.extend((root, (*keys, str(key)), item) for key, item in reversed(list(value.items())))
        elif isinstance(value, list):
            if not _skipped(root, keys, skip):
                stack.extend((root, (*keys, index), item) for index, item in reversed(list(enumerate(value))))
    for text in material.get("said") or []:
        if isinstance(text, str) and text:
            yield SAID_PATH, text


def known_of(db: OrmSession) -> recognise.Known:
    """What the organisation says of itself: its own domains and its IOC allowlist."""
    from .iocs import Allowlist
    from .routers.settings import read_settings

    shared = read_settings(db)
    mail = shared.get("mail") if isinstance(shared.get("mail"), dict) else {}
    domains = frozenset(str(d).lower().strip(".") for d in (mail.get("orgDomains") or []) if str(d).strip("."))
    return recognise.Known(own_domains=domains, allowlisted=Allowlist(shared.get("iocAllowlist") or []).matches)


def read(material: dict[str, Any], cfg: dict[str, Any], known: recognise.Known) -> dict[str, Any]:
    """What a reading of an incident's fields and context gives, before anything is kept:
    ``{found: [(Found, path)], leftOut: {mark: n}, unread: n}``. Pure: nothing is written."""
    wanted = set(cfg["types"])
    found: dict[tuple[str, str], tuple[recognise.Found, str]] = {}
    left: dict[tuple[str, str], str] = {}
    unread = count = size = 0
    for path, text in strings(material, cfg["skip"]):
        count += 1
        size += min(len(text), STRING_MAX)
        if count > STRINGS_MAX or size > BYTES_MAX:
            unread += 1
            continue
        for item in recognise.find(text[:STRING_MAX], known):
            key = (item.type, item.value)
            if item.type not in wanted or key in found:
                continue
            marks = set(item.marks)
            why = (
                "private"
                if cfg["leaveOutPrivate"] and "private" in marks
                else "benign"
                if cfg["leaveOutBenign"] and marks & {"benign", "own", "allowlisted"}
                else ""
            )
            if why:
                left.setdefault(key, why)
            else:
                found[key] = (item, path[:PATH_MAX])
    counts: dict[str, int] = {}
    for key, why in left.items():
        if key not in found:
            counts[why] = counts.get(why, 0) + 1
    return {"found": list(found.values()), "leftOut": counts, "unread": unread}


def material_of(db: OrmSession, incident: Incident) -> dict[str, Any]:
    """The fields and the context of an incident, as the Context tab shows them."""
    from . import context as incident_context
    from . import fields as registry

    return {"incident": registry.read(db, incident), "context": incident_context.read(db, incident.id)}


def _plural(kind: str, count: int) -> str:
    one, many = _NOUNS[kind]
    return f"{count} {one if count == 1 else many}"


def sentence(summary: dict[str, Any]) -> str:
    """What a reading found, in the one line the War Room keeps."""
    new = summary.get("new", 0)
    by_type = summary.get("byType") or {}
    groups = {
        "domain": by_type.get("domain", 0),
        "url": by_type.get("url", 0),
        "ip": by_type.get("ip", 0),
        "email": by_type.get("email", 0),
        "hash": sum(by_type.get(kind, 0) for kind in ("md5", "sha1", "sha256")),
    }
    parts = [_plural(kind, count) for kind, count in groups.items() if count]
    text = f"{new} indicator{'' if new == 1 else 's'} found" + (": " + ", ".join(parts) if parts else "")
    left = summary.get("leftOut") or {}
    if sum(left.values()):
        reasons = [name for name in ("private", "benign") if left.get(name)]
        text += f"; {sum(left.values())} left out as {' or '.join(reasons)}"
    if summary.get("over"):
        text += (
            f"; {summary['over']} more were not kept: an incident is given {summary.get('cap', CAP_DEFAULT)} "
            "at most this way (Settings, Indicators found)"
        )
    if summary.get("unread"):
        text += f"; {summary['unread']} values of the incident were not read: it holds too many"
    return text + "."


def scan(
    db: OrmSession, incident: Incident, door: str, *, asked: bool = False, said: list[str] | None = None
) -> dict[str, Any] | None:
    """Read an incident for indicators and keep the new ones (the caller commits). Returns what
    came of it, or None when incidents from where this one came are not read. ``asked``: a
    person asked for this incident, whatever the setting says of the others. ``said``: what the
    other side said in the update that is read (comments, a reply), read after the rest."""
    cfg = config(db)
    if not asked and not on_for(cfg, incident):
        return None
    db.flush()  # the session does not flush by itself: what the door just wrote is read below
    material = material_of(db, incident)
    material["said"] = list(said or [])[:SAID_MAX]
    result = read(material, cfg, known_of(db))
    rows = {
        (row.type, row.value): row
        for row in db.scalars(select(FoundIndicator).where(FoundIndicator.incident_id == incident.id))
    }
    kept = sum(1 for row in rows.values() if row.removed_at is None)
    # What the incident holds already, from what was analysed for it or from a person: nothing to add.
    held = {
        (kind, value)
        for kind, value, sources in db.execute(
            select(IocEntry.type, IocEntry.value, IocEntry.sources).where(IocEntry.incident_id == incident.id)
        )
        if any(not str(source).startswith(SOURCE) for source in sources or [])
    }
    stamp = now_iso()
    by_type: dict[str, int] = {}
    fresh: list[dict[str, str]] = []
    new = over = removed = 0
    for item, path in result["found"]:
        key = (item.type, item.value)
        row = rows.get(key)
        if row is not None:
            removed += 1 if row.removed_at is not None else 0
            continue
        if key in held:
            continue
        if kept >= cfg["cap"]:
            over += 1
            continue
        db.add(
            FoundIndicator(
                incident_id=incident.id, type=item.type, value=item.value, path=path, door=door, found_at=stamp
            )
        )
        kept += 1
        new += 1
        by_type[item.type] = by_type.get(item.type, 0) + 1
        fresh.append({"type": item.type, "value": item.value, "path": path})
    summary = {
        "new": new,
        "kept": kept,
        "byType": by_type,
        "leftOut": result["leftOut"],
        "over": over,
        "removed": removed,
        "unread": result["unread"],
        "cap": cfg["cap"],
    }
    state = db.get(FoundScan, incident.id)
    before = state.summary if state is not None and isinstance(state.summary, dict) else {}
    if state is None:
        db.add(FoundScan(incident_id=incident.id, at=stamp, door=door, summary=summary))
    else:
        state.at, state.door, state.summary = stamp, door, summary
        flag_modified(state, "summary")
    # One line for a reading that changed something: new indicators, or more left over the limit.
    if new or over > int(before.get("over") or 0):
        from . import war_room

        db.flush()
        war_room.add(db, incident.id, "system", {"text": sentence(summary), "found": summary}, "nik")
    if new:
        from .iocs import reindex_incident

        db.flush()
        reindex_incident(db, incident)
        audit.record(db, "nik", "ioc.found", f"Found {new} indicators in the incident ({door})", incident)
        # One event for a reading that kept something new, written with it: the playbooks that wait
        # for it start once (``automation/triggers.py``).
        from .automation import triggers

        triggers.indicators_found(db, incident, door, fresh, kept)
    db.flush()
    return summary


def after_update(db: OrmSession, incident: Incident, source: str, said: list[str] | None = None) -> None:
    """What a connector wrote to an incident that was read once is read again (a mirror update).
    An incident that was never read is left alone: it is being made, and its door reads it when
    it is whole, or it came in before incidents were read at all. ``said``: what the other side
    said with it. Inside ``together`` nothing is read yet: the update is noted, and read whole."""
    if not str(source or "").startswith("connector:"):
        return
    held = db.info.get(_HELD)
    if held is not None and held["incident"] == incident.id:
        held["changed"] = True
        held["said"] += list(said or [])
        return
    if db.get(FoundScan, incident.id) is None:
        return
    scan(db, incident, "mirror", said=said)


@contextmanager
def together(db: OrmSession, incident: Incident) -> Iterator[None]:
    """One update of an incident by a connector, made of several writes (a mirror's read: its
    fields one by one, its context, its comments): the incident is read once when the block ends,
    and only when a write changed something. So an update leaves one line in the War Room, not one
    for each part. An update that fails is not read: its transaction is rolled back."""
    if db.info.get(_HELD) is not None:
        yield  # an update inside another: the outer one reads
        return
    held = db.info[_HELD] = {"incident": incident.id, "changed": False, "said": []}
    try:
        yield
    except BaseException:
        db.info.pop(_HELD, None)
        raise
    db.info.pop(_HELD, None)
    if held["changed"] and db.get(FoundScan, incident.id) is not None:
        scan(db, incident, "mirror", said=held["said"])


# --------------------------------------------------------------------------- #
# What an incident was given, and a person's no                               #
# --------------------------------------------------------------------------- #
def _ms(text: str) -> int | None:
    at = clock.stamp(text)
    return int(at * 1000) if at else None


def add_to(db: OrmSession, incident_id: str, items: dict[tuple[str, str], dict[str, Any]], limit: int) -> None:
    """Add the found indicators of an incident to what its document gives, for the index
    (``iocs.reindex_incident``): the same shape, the source ``found:<path>``."""
    wanted = select(FoundIndicator).where(
        FoundIndicator.incident_id == incident_id, FoundIndicator.removed_at.is_(None)
    )
    for row in db.scalars(wanted):
        key = (row.type, row.value)
        item = items.get(key)
        if item is None:
            if len(items) >= limit:
                continue
            item = items[key] = {"sources": set(), "count": 0, "first": None, "last": None}
        item["sources"].add(f"{SOURCE}{row.path}")
        item["count"] += 1
        when = _ms(row.found_at)
        if when is not None and item["first"] is None:
            item["first"] = item["last"] = when


def out(row: FoundIndicator) -> dict[str, Any]:
    return {
        "type": row.type,
        "value": row.value,
        "path": row.path,
        "door": row.door,
        "foundAt": row.found_at,
        "removedAt": row.removed_at,
        "removedBy": row.removed_by,
    }


def listing(db: OrmSession, incident: Incident) -> dict[str, Any]:
    """What the incident was given by itself, what a person removed of it, and the last reading."""
    rows = db.scalars(
        select(FoundIndicator)
        .where(FoundIndicator.incident_id == incident.id)
        .order_by(FoundIndicator.found_at, FoundIndicator.type, FoundIndicator.value)
    ).all()
    state = db.get(FoundScan, incident.id)
    cfg = config(db)
    return {
        "found": [out(row) for row in rows if row.removed_at is None],
        "removed": [out(row) for row in rows if row.removed_at is not None],
        "scan": {"at": state.at, "door": state.door, **(state.summary or {})} if state is not None else None,
        "on": on_for(cfg, incident),
    }


def remove(db: OrmSession, incident: Incident, kind: str, value: str, actor: str) -> bool:
    """Take a found indicator off its incident and remember it (the caller commits). False when
    the incident was not given it."""
    row = db.get(FoundIndicator, (incident.id, kind, value))
    if row is None or row.removed_at is not None:
        return False
    row.removed_at, row.removed_by = now_iso(), actor[:200]
    db.flush()
    from .iocs import MAX_PER_INCIDENT, reindex_incident

    # An indicator the incident holds for this alone leaves its index by itself: with hundreds of
    # them on one incident, building the whole index again for each one removed is what would
    # make removing many slow. One that something else gives too, or an index that is full (the
    # place freed goes to one that was left out), is built again.
    entry = db.get(IocEntry, (incident.id, kind, value))
    indexed = db.scalar(select(func.count()).select_from(IocEntry).where(IocEntry.incident_id == incident.id)) or 0
    alone = entry is not None and all(str(source).startswith(SOURCE) for source in entry.sources or [])
    if alone and indexed < MAX_PER_INCIDENT:
        db.delete(entry)
    else:
        reindex_incident(db, incident, alerts=False)
    audit.record(
        db,
        actor,
        "ioc.found_removed",
        f"Removed the found indicator {kind} {value[:200]}",
        incident,
        target=value[:200],
    )
    return True


def restore(db: OrmSession, incident: Incident, kind: str, value: str, actor: str) -> bool:
    """Give back a found indicator a person had removed (the caller commits)."""
    row = db.get(FoundIndicator, (incident.id, kind, value))
    if row is None or row.removed_at is None:
        return False
    row.removed_at = row.removed_by = None
    db.flush()
    from .iocs import reindex_incident

    reindex_incident(db, incident)
    audit.record(
        db,
        actor,
        "ioc.found_restored",
        f"Put back the found indicator {kind} {value[:200]}",
        incident,
        target=value[:200],
    )
    return True


def forget(db: OrmSession, incident_id: str) -> None:
    """Drop what was found for an incident that is deleted."""
    db.execute(delete(FoundIndicator).where(FoundIndicator.incident_id == incident_id))
    db.execute(delete(FoundScan).where(FoundScan.incident_id == incident_id))


def only_found(sources: list[str]) -> bool:
    """Whether every place an indicator was seen in is a finding: nobody chose it."""
    return bool(sources) and all(str(source).startswith(SOURCE) for source in sources)
