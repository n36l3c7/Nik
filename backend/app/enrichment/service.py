"""Threat-intelligence look-ups: what may be sent, who is asked, and what is kept.

**Who is asked.** A look-up of an indicator is the reputation command of a
source's connector, run on an instance of it (``sources.py``): there is no
other way out. A source takes part when its connector is installed and one of
its instances is on; its keys, their limits and the answers it keeps are the
instance's.

**What is never sent**, whoever asks (an analyst's "Check now", a playbook or
the background worker):

- private, loopback, link-local and other non-public addresses, internal
  names (no dot, ``.local``, ``.lan``, ``.internal``, ``.corp``,
  ``.home.arpa``…) and URLs on them;
- values on the IOC allowlist (Settings -> IOC allowlist);
- values seen in an incident whose report is classified **TLP:RED**, and
  values or lists an analyst marked TLP:RED.

This is the rule of the look-ups and it is checked here, before a command is
chosen: no setting loosens it.

**What is held.** A value that passes that rule is judged by the data guard
(``automation/guard.py``) as well, once, for all the sources together: it
holds a value that carries an e-mail address, a name under the organisation's
own domains or a private address, or an allowlisted name, until an admin
opens that class. A look-up a playbook makes is judged against the classes
opened for that playbook; every other (an analyst's "Check now", a check in
bulk, the automatic look-ups) against the classes opened for the look-ups
made outside playbooks, a setting of its own that starts with nothing opened
(``held``). The two do not mix. A held look-up asks no source at all; it is
not an error and it is not stored: the value is judged again each time, so
it is asked when the class is opened, or when the allowlist or the
organisation's domains change what the value is.

**Automatic look-ups** (Settings -> Threat intelligence) are off until an
analyst turns them on, per type: IP addresses, URLs and domains, file
hashes. The worker (``worker.py``) checks each new indicator once with
every source that is on and takes its type. E-mail addresses are never sent.
An indicator incidents hold only because it was found in them as they came
in (``indicators_found.py``) is left out of the automatic look-ups unless
the setting of the finding says to ask about those too.

**How long an answer stands**: a number of days set per type (IP addresses
30, URLs and domains 30, hashes 180 by default). Past it the answer is
*expired*: it is asked again (by the worker for the types it handles, or
when someone opens the indicator), unless "refresh expired answers" is
turned off; then it is kept, marked as expired, until someone checks again.
The last ten answers of each source stay in a history.

**Overall verdict**: a weighted score, see ``overall``.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..automation import guard
from ..core.models import (
    Enrichment,
    EnrichmentHistory,
    Incident,
    IocCheck,
    IocEntry,
    IocList,
    IocListItem,
    IocRecord,
)
from ..core.security import now_iso
from ..iocs import Allowlist, normalize
from . import sources as src
from .sources import HASHES, Source

VERDICT_ORDER = ("malicious", "suspicious", "harmless", "unknown")
LOOKUP_TYPES = ("ip", "domain", "url", *HASHES)
ERROR_RETRY = timedelta(hours=1)
RUNNING_STALE = timedelta(minutes=10)
INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home", ".home.arpa", ".localdomain")

RETENTION_GROUPS = ("ip", "url", "hash")  # url covers domains, hash the three digests

# The classes of the data guard the value of an indicator can carry, with what each is there. The
# others are of things an indicator is not (a subject, a file, the text of a message), and TLP:RED
# is never offered: the rule of the look-ups keeps it in.
GUARD_CLASSES: dict[str, str] = {
    "email_address": "In an indicator: a link that carries the address of the person it was sent to.",
    "private_value": (
        "In an indicator: a domain under your own domains or a link on one, and a link that carries a "
        "private address. A private address or an internal name by itself is never sent."
    ),
    "allowlisted": (
        "In an indicator: a link that names a domain or an address of the allowlist, a redirect to your "
        "own site for example. An indicator that is itself on the allowlist is never sent."
    ),
}

DEFAULTS: dict[str, Any] = {
    # Automatic lookups per type (off until an analyst turns them on).
    "auto": {"ip": False, "url": False, "hash": False},
    # How long an answer stands, in days, per type. A hash's reputation
    # changes slowly; an address or a URL changes hands.
    "retentionDays": {"ip": 30, "url": 30, "hash": 180},
    # Ask again when an answer is past its retention (else it is kept and
    # shown as expired until someone checks again).
    "refreshExpired": True,
    # The classes of the data guard opened for the look-ups made outside playbooks (``GUARD_CLASSES``).
    # It is not saved with the others: opening one has a route of its own, behind a double check.
    "guardOpen": [],
}


def config(shared: dict[str, Any]) -> dict[str, Any]:
    """The ``enrichment`` settings with every default filled in. Which sources are asked is not a
    setting any more: a source is on when an instance of its connector is."""
    raw = shared.get("enrichment") if isinstance(shared.get("enrichment"), dict) else {}
    auto = {**DEFAULTS["auto"], **(raw.get("auto") or {})}
    retention = dict(DEFAULTS["retentionDays"])
    for group, days in (raw.get("retentionDays") or {}).items():
        try:
            if group in retention:
                retention[group] = min(730, max(1, int(days)))
        except (TypeError, ValueError):
            pass
    opened = raw.get("guardOpen") if isinstance(raw.get("guardOpen"), list) else []
    return {
        "auto": {k: bool(v) for k, v in auto.items() if k in DEFAULTS["auto"]},
        "retentionDays": retention,
        "refreshExpired": bool(raw.get("refreshExpired", DEFAULTS["refreshExpired"])),
        "guardOpen": [name for name in GUARD_CLASSES if name in opened],
    }


def retention_group(kind: str) -> str:
    return "ip" if kind == "ip" else "hash" if kind in HASHES else "url"


def retention(cfg: dict[str, Any], kind: str) -> timedelta:
    return timedelta(days=cfg["retentionDays"][retention_group(kind)])


def auto_types(cfg: dict[str, Any]) -> set[str]:
    types: set[str] = set()
    if cfg["auto"].get("ip"):
        types.add("ip")
    if cfg["auto"].get("url"):
        types |= {"url", "domain"}
    if cfg["auto"].get("hash"):
        types |= set(HASHES)
    return types


def asked(db: OrmSession, kind: str | None = None) -> list[Source]:
    """The sources that are on (for a type of indicator, when one is given), by name."""
    return [source for source in src.sources(db) if source.on and (kind is None or source.supports(kind))]


# --------------------------------------------------------------------------- #
# What may be sent                                                            #
# --------------------------------------------------------------------------- #
def internal_host(host: str) -> str | None:
    host = host.lower().strip("[]").rstrip(".")
    try:
        if not ipaddress.ip_address(host).is_global:
            return "a private or reserved address"
        return None
    except ValueError:
        pass
    if "." not in host or host.endswith(INTERNAL_SUFFIXES):
        return "an internal name"
    return None


def red_incidents(db: OrmSession) -> set[str]:
    """Incidents whose report is classified TLP:RED."""
    rows = db.execute(select(Incident.id, Incident.doc).where(cast(Incident.doc, String).like('%"tlp": "red"%'))).all()
    return {
        incident_id
        for incident_id, doc in rows
        if isinstance(doc, dict) and isinstance(doc.get("report"), dict) and doc["report"].get("tlp") == "red"
    }


def blocked(db: OrmSession, kind: str, value: str, allowlist: Allowlist, red: set[str] | None = None) -> str | None:
    """Why the value must not leave Nik, or None."""
    if kind not in LOOKUP_TYPES:
        return "this type is never sent to external services"
    if kind == "ip":
        reason = internal_host(value)
    elif kind == "domain":
        reason = internal_host(value)
    elif kind == "url":
        from urllib.parse import urlsplit

        try:
            host = urlsplit(value).hostname or ""
        except ValueError:
            host = ""
        reason = internal_host(host) if host else "a URL without a host"
    else:
        reason = None
    if reason:
        return f"{reason} is never sent outside"
    if allowlist.matches(kind, value):
        return "it is on the IOC allowlist"
    red = red_incidents(db) if red is None else red
    if red:
        holders = set(db.scalars(select(IocEntry.incident_id).where(IocEntry.type == kind, IocEntry.value == value)))
        if holders & red:
            return "it appears in a TLP:RED incident"
    if db is not None and _classified_red(db, kind, value):
        return "it is classified TLP:RED"
    return None


def _classified_red(db: OrmSession, kind: str, value: str) -> bool:
    """An analyst marked the indicator, or a list that holds it, TLP:RED."""
    record = db.get(IocRecord, (kind, value))
    if record is not None and record.tlp == "red":
        return True
    return (
        db.scalar(
            select(IocListItem.list_id)
            .join(IocList, IocList.id == IocListItem.list_id)
            .where(IocListItem.type == kind, IocListItem.value == value, IocList.tlp == "red")
            .limit(1)
        )
        is not None
    )


# --------------------------------------------------------------------------- #
# What is held                                                                #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Judge:
    """What the data guard needs to judge the look-ups made outside playbooks: the classes opened for
    them, the organisation's own domains and its allowlist. Read once for a pass over many values."""

    opened: frozenset
    context: guard.Context


def judge(shared: dict[str, Any]) -> Judge:
    return Judge(opened=frozenset(config(shared)["guardOpen"]), context=guard.context_of(shared))


def held(kind: str, value: str, judged: Judge) -> dict[str, Any] | None:
    """What the data guard holds of a value a look-up outside a playbook would send, or None when it
    may leave: ``{classes: [{id, label}], reason}``. The value has no playbook behind it and so no
    class by where it came from: it is judged by what it carries, as the guard reads any text."""
    if kind in HASHES:
        return None  # a digest carries nothing but itself
    decision = guard.check(value, frozenset(), judged.opened, judged.context)
    if decision.allowed:
        return None
    names = [name for name in guard.CLASSES if name in decision.held]
    classes = [{"id": name, "label": guard.CLASSES[name]["label"]} for name in names]
    return {
        "classes": classes,
        "reason": (
            f"Held back: {', '.join(item['label'].lower() for item in classes)}. A look-up may not send them: "
            "an administrator can open them in Settings, Threat intelligence"
        ),
    }


def held_note(count: int) -> str:
    """What a check in bulk says of the indicators it did not ask about because the guard holds them."""
    return f"{count} held back by the data guard: not asked." if count else ""


def guard_classes(shared: dict[str, Any]) -> list[dict[str, Any]]:
    """The classes an admin can open for the look-ups made outside playbooks, as Settings shows them:
    what each is in the words of the guard, what it is in an indicator, and whether it is open."""
    opened = config(shared)["guardOpen"]
    return [
        {
            "id": name,
            "label": guard.CLASSES[name]["label"],
            "warning": guard.CLASSES[name]["warning"],
            "example": example,
            "open": name in opened,
        }
        for name, example in GUARD_CLASSES.items()
    ]


# --------------------------------------------------------------------------- #
# The answers that are stored                                                 #
# --------------------------------------------------------------------------- #
def _age(row: Enrichment) -> timedelta:
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(row.checked_at.replace("Z", "+00:00"))
    except ValueError:
        return timedelta.max


def expired(row: Enrichment, cfg: dict[str, Any]) -> bool:
    """An answer older than the retention of its type."""
    return row.status == "done" and _age(row) >= retention(cfg, row.type)


def fresh(row: Enrichment | None, cfg: dict[str, Any]) -> bool:
    """Nothing to ask: the answer stands (or, with "refresh expired" off,
    exists at all), a lookup is running, or an error is too recent to retry."""
    if row is None:
        return False
    if row.status == "done":
        return not cfg["refreshExpired"] or not expired(row, cfg)
    if row.status == "running":
        return _age(row) < RUNNING_STALE
    return _age(row) < ERROR_RETRY


def as_dict(
    row: Enrichment,
    cfg: dict[str, Any] | None = None,
    names: dict[str, str] | None = None,
    counted: dict[str, tuple[int, bool]] | None = None,
) -> dict[str, Any]:
    data = row.data or {}
    # An answer stored before 6.5 has the details in the shape of that time: its verdict, line and
    # link stand, and the details come with the next check.
    current = COMMAND in data
    return {
        "provider": row.provider,
        "label": (names or {}).get(row.provider, row.provider),
        "weight": (counted or {}).get(row.provider, (1, False))[0],
        "status": row.status,
        "verdict": row.verdict,
        "summary": row.summary,
        "link": row.link,
        "data": data if current else {},
        "before65": row.status == "done" and not current,
        "error": row.error,
        "checkedAt": row.checked_at,
        "expired": bool(cfg) and expired(row, cfg),
        "hasRaw": row.raw is not None,
    }


def results(db: OrmSession, kind: str, value: str, cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Each source's latest answer, with its earlier verdicts (newest first), by the name of the source."""
    rows = db.scalars(select(Enrichment).where(Enrichment.type == kind, Enrichment.value == value)).all()
    history: dict[str, list[dict[str, Any]]] = {}
    for past in db.scalars(
        select(EnrichmentHistory)
        .where(EnrichmentHistory.type == kind, EnrichmentHistory.value == value)
        .order_by(EnrichmentHistory.checked_at.desc())
    ):
        history.setdefault(past.provider, []).append(
            {"verdict": past.verdict, "summary": past.summary, "checkedAt": past.checked_at}
        )
    names, counted = src.labels(db), src.weights(db)
    found = [{**as_dict(row, cfg, names, counted), "history": history.get(row.provider, [])} for row in rows]
    return sorted(found, key=lambda item: (item["label"].lower(), item["provider"]))


# What a verdict is worth in the overall score.
# Nik's own analysis of the value (the scan of a URL, the file with that
# hash) among the sources of its reputation: see ``analysis_links``.
logger = logging.getLogger("nik.enrichment")
NIK, NIK_WEIGHT = "nik", 3
VERDICT_VALUE = {"malicious": 1.0, "suspicious": 0.5, "harmless": 0.0, "unknown": 0.0}
MALICIOUS_SCORE, SUSPICIOUS_SCORE = 50, 20


def overall(
    answers: Iterable[tuple[str, str]], counted: dict[str, tuple[int, bool]] | None = None
) -> dict[str, Any] | None:
    """The indicator's overall reputation from ``(source id, verdict)`` of the sources that answered:
    a score from 0 to 100, each source's verdict counted by its weight. ``counted`` says how each
    source counts, ``{id: (weight, informational)}``, as its connector declares it (``lookups`` of the
    file: 1 to 3, 1 when it says nothing; ``sources.weights``).

    - **malicious**: score 50 or more, and at least one source says malicious;
    - **suspicious**: score 20 or more, or any source says malicious;
    - **harmless**: nobody flags it and somebody vouches for it;
    - **unknown** otherwise.
    """
    answers = list(answers)
    if not answers:
        return None
    counted = counted or {}
    counts = {v: 0 for v in VERDICT_ORDER}
    weight = points = 0.0
    taken = 0
    for source_id, verdict in answers:
        own, facts = counted.get(source_id, (1, False))
        # Facts, not a judgement: counted only when they flag the value. So is
        # Nik's own analysis of the value (NIK), which has the highest weight.
        informational = source_id == NIK or facts
        if informational and verdict not in ("malicious", "suspicious"):
            continue
        taken += 1
        w = NIK_WEIGHT if source_id == NIK else own
        weight += w
        points += w * VERDICT_VALUE.get(verdict, 0.0)
        counts[verdict if verdict in counts else "unknown"] += 1
    score = round(100 * points / weight) if weight else 0
    flagged = counts["malicious"] + counts["suspicious"]
    if score >= MALICIOUS_SCORE and counts["malicious"]:
        verdict = "malicious"
    elif score >= SUSPICIOUS_SCORE or counts["malicious"]:
        verdict = "suspicious"
    elif not flagged and counts["harmless"]:
        verdict = "harmless"
    else:
        verdict = "unknown"
    if not taken:
        return None
    return {"verdict": verdict, "score": score, "flagged": flagged, "checked": taken, "counts": counts}


def summaries(db: OrmSession, pairs: Iterable[tuple[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
    """``(type, value) -> {verdict, score, flagged, checked, counts}`` from the stored answers."""
    wanted = set(pairs)
    values = sorted({v for _, v in wanted})
    answers: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for start in range(0, len(values), 500):
        chunk = values[start : start + 500]
        for row in db.execute(
            select(Enrichment.type, Enrichment.value, Enrichment.provider, Enrichment.verdict).where(
                Enrichment.value.in_(chunk), Enrichment.status == "done"
            )
        ):
            if (row.type, row.value) in wanted:
                answers.setdefault((row.type, row.value), []).append((row.provider, row.verdict))
    from .. import analysis_links

    for pair, verdict in analysis_links.verdicts(db, wanted).items():
        answers.setdefault(pair, []).append((NIK, verdict))
    counted = src.weights(db) if answers else {}
    summed = {key: overall(found, counted) for key, found in answers.items()}
    return {key: value for key, value in summed.items() if value is not None}


# --------------------------------------------------------------------------- #
# Lookups                                                                     #
# --------------------------------------------------------------------------- #
HISTORY_KEPT = 10
RAW_MAX_BYTES = 1_500_000
# What the indicator's page is given of an answer (``data``): the outputs of the command, without the
# three every source gives (verdict, summary, link), a long list cut and a very large value left out.
# The whole of it is ``raw``, for the JSON download.
COMMAND = "_command"  # "virustotal.get-ip-report": which command answered; says the shape of the details
LIST_SHOWN = 100
VALUE_MAX_BYTES = 60_000


def details(source: Source, kind: str, outputs: dict[str, Any]) -> dict[str, Any]:
    """The outputs of a reputation command as the page of an indicator gets them: nothing of a vendor is
    known here, so nothing is renamed; the page shapes what it shows (``domain/sourceDetails.js``)."""
    command = source.commands.get(src.command_kind(kind), "")
    kept: dict[str, Any] = {COMMAND: f"{source.id}.{command}"}
    if source.instance is not None:
        kept["_instance"] = source.instance.name
    cut: dict[str, int] = {}
    left_out: list[str] = []
    for name, value in outputs.items():
        if name in ("verdict", "summary", "link") or name.startswith("_") or value in (None, "", [], {}):
            continue
        if isinstance(value, list) and len(value) > LIST_SHOWN:
            cut[name] = len(value)
            value = value[:LIST_SHOWN]
        if isinstance(value, (dict, list)):
            try:
                size = len(json.dumps(value, default=str))
            except (TypeError, ValueError):
                size = VALUE_MAX_BYTES + 1
            if size > VALUE_MAX_BYTES:
                left_out.append(name)
                continue
        kept[name] = value
    if cut:
        kept["_cut"] = cut
    if left_out:
        kept["_left_out"] = left_out
    return kept


def _link(value: Any) -> str:
    """The page of the source about the indicator: an address of the web, or nothing."""
    text = str(value or "").strip()
    return text[:1000] if text.lower().startswith(("https://", "http://")) else ""


def lookup_one(
    db: OrmSession,
    source: Source,
    kind: str,
    value: str,
    *,
    again: bool = False,
    playbook: Any | None = None,
) -> tuple[Enrichment, str]:
    """Ask one source now and store its answer (or the error). Returns the row and the outcome:
    ``ok``, ``wait`` (every key of the instance is used up: nothing was asked and the row is as it
    was) or ``error``. An answer that replaces an earlier one goes to the history."""
    row = db.get(Enrichment, (kind, value, source.id))
    before = _verdict_of(db, kind, value)
    created = row is None
    if row is None:
        row = Enrichment(type=kind, value=value, provider=source.id, data={}, checked_at=now_iso())
        db.add(row)
    # An answer being asked for again still counts until the new one is in.
    was = (row.status, row.checked_at)
    was_done = row.status == "done"
    row.status, row.checked_at = "running", now_iso()
    db.commit()
    outcome = "ok"
    try:
        outputs = src.ask(db, source, kind, value, playbook=playbook, again=again)
        row.status, row.error = "done", None
        row.verdict = src.verdict_of(outputs)
        row.summary = str(outputs.get("summary") or "")[:500]
        row.link = _link(outputs.get("link"))
        row.data = details(source, kind, outputs)
        row.raw = _bounded(outputs)
        flag_modified(row, "data")
        flag_modified(row, "raw")
    except src.Unavailable:
        if created:
            db.delete(row)
        else:
            row.status, row.checked_at = was
        db.commit()
        return row, "wait"
    except src.Failed as error:
        outcome = "error"
        row.status, row.error = "error", error.message[:500]
    except Exception as exc:  # noqa: BLE001 - a malformed answer must not stop the others
        outcome = "error"
        row.status, row.error = "error", f"unexpected answer: {exc}"[:500]
    row.checked_at = now_iso()
    if row.status == "done":
        _remember(db, row)
        _announce_verdict(db, kind, value, before)
    elif was_done:
        # The source did not answer this time: what it said before is no longer counted.
        _announce_verdict(db, kind, value, before)
    db.commit()
    return row, outcome


def _verdict_of(db: OrmSession, kind: str, value: str) -> str:
    """The indicator's overall verdict from what is stored ("" when nobody answered)."""
    summary = summaries(db, [(kind, value)]).get((kind, value))
    return summary["verdict"] if summary else ""


def _announce_verdict(db: OrmSession, kind: str, value: str, before: str) -> None:
    """Tell the playbooks when the overall verdict of an indicator changed (in the caller's
    transaction). A first answer that says nothing ("unknown") is not a change."""
    db.flush()
    after = _verdict_of(db, kind, value)
    if after == before or (not before and after in ("", "unknown")):
        return
    from ..automation import triggers

    answered = db.scalars(
        select(Enrichment.provider).where(
            Enrichment.type == kind, Enrichment.value == value, Enrichment.status == "done"
        )
    ).all()
    try:
        triggers.verdict_changed(db, kind, value, before, after, list(answered))
    except Exception:  # noqa: BLE001 - a lookup must not fail because of what listens to it
        logger.exception("The change of verdict of %s %s was not announced", kind, value)


def _bounded(raw: Any) -> Any:
    """The whole answer of the command, unless it is too large to keep."""
    if raw is None:
        return None
    try:
        size = len(json.dumps(raw, default=str))
    except (TypeError, ValueError):
        return None
    return raw if size <= RAW_MAX_BYTES else {"truncated": True, "bytes": size}


def _remember(db: OrmSession, row: Enrichment) -> None:
    """Add the answer to the indicator's history and keep the last few."""
    db.add(
        EnrichmentHistory(
            id=uuid.uuid4().hex,
            type=row.type,
            value=row.value,
            provider=row.provider,
            verdict=row.verdict,
            summary=row.summary,
            checked_at=row.checked_at,
        )
    )
    db.flush()
    past = db.scalars(
        select(EnrichmentHistory)
        .where(
            EnrichmentHistory.type == row.type,
            EnrichmentHistory.value == row.value,
            EnrichmentHistory.provider == row.provider,
        )
        .order_by(EnrichmentHistory.checked_at.desc(), EnrichmentHistory.id)
    ).all()
    for old in past[HISTORY_KEPT:]:
        db.delete(old)


def _later(seconds: float) -> str:
    """Why a source was not asked: when a key of its instance is free again."""
    if seconds == float("inf"):
        return "no instance that is on"
    if seconds < 90:
        return f"every key is used up: retry in {int(seconds) + 1} s"
    return f"every key is used up: the first is back in {max(1, round(seconds / 60))} min"


def ask(
    db: OrmSession,
    source: Source,
    kind: str,
    value: str,
    max_wait: float = 0.0,
    *,
    again: bool = False,
    playbook: Any | None = None,
    automatic: bool = True,
) -> str | None:
    """One look-up. Returns None when the source was asked (its row says what it answered), else why
    it was not: every key of its instance is waiting for a limit."""
    seconds = src.wait(db, source, automatic=automatic)
    if seconds > max_wait:
        return _later(seconds)
    if seconds:
        time.sleep(seconds)
    _, outcome = lookup_one(db, source, kind, value, again=again, playbook=playbook)
    if outcome == "wait":
        return _later(src.wait(db, source, automatic=automatic) or 60.0)
    return None


def check_now(
    db: OrmSession,
    kind: str,
    value: str,
    shared: dict[str, Any],
    force: bool = False,
    *,
    playbook: Any | None = None,
) -> dict[str, Any]:
    """An analyst's "Check now" (or a playbook's): every source that is on for the type, waiting
    briefly for a limit but skipping a source whose keys are all used up. ``force`` asks also the
    sources whose answer still stands, and past the answers their instances keep.

    Without a ``playbook`` the data guard is asked first (``held``): a held value asks no source, and
    ``held`` of what is returned says by which classes. A playbook's look-up was judged by the guard
    of the playbook before it came here."""
    cfg = config(shared)
    why = held(kind, value, judge(shared)) if playbook is None else None
    if why:
        return {"results": results(db, kind, value, cfg), "skipped": [], "held": why}
    skipped = []
    for source in asked(db, kind):
        if not force and fresh(db.get(Enrichment, (kind, value, source.id)), cfg):
            continue
        reason = ask(db, source, kind, value, max_wait=3.0, again=force, playbook=playbook, automatic=False)
        if reason:
            skipped.append({"provider": source.id, "label": source.label, "reason": reason})
    return {"results": results(db, kind, value, cfg), "skipped": skipped, "held": None}


def normalized(kind: str, value: str) -> str | None:
    return normalize(kind, value)


def _hash_from_files(sources: list[str]) -> bool:
    """MD5/SHA-1 of a stored sample or attachment: its SHA-256 is checked instead."""
    return bool(sources) and all(s.startswith(("sample:", "mail:")) for s in sources)


def run_cycle(db: OrmSession, shared: dict[str, Any], budget_seconds: float = 45.0, max_calls: int = 200) -> int:
    """One pass of the automatic lookups; returns the number of requests made."""
    cfg = config(shared)
    types = auto_types(cfg)
    if not types:
        return 0
    on = [source for source in asked(db) if any(source.supports(t) for t in types)]
    if not on:
        return 0
    allowlist = Allowlist(shared.get("iocAllowlist") or [])
    judged = judge(shared)
    red = red_incidents(db)
    rows = db.execute(
        select(IocEntry.type, IocEntry.value, IocEntry.incident_id, IocEntry.sources)
        .join(Incident, Incident.id == IocEntry.incident_id)
        .where(IocEntry.type.in_(sorted(types)))
        .order_by(Incident.updated_at.desc())
        .limit(20_000)
    ).all()
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    for kind, value, incident_id, seen_in in rows:
        item = candidates.setdefault((kind, value), {"incidents": set(), "sources": []})
        item["incidents"].add(incident_id)
        item["sources"] += list(seen_in or [])

    cached: dict[tuple[str, str], dict[str, Enrichment]] = {}
    for row in db.scalars(select(Enrichment).where(Enrichment.type.in_(sorted(types)))):
        cached.setdefault((row.type, row.value), {})[row.provider] = row
    # What incidents hold only because it was found in them as they came in is asked about when
    # the setting of the finding says so, and not before: nobody chose those values.
    from .. import indicators_found

    found_too = indicators_found.config(db)["lookUps"]

    # The work: (source, type, value) not answered yet, newest incidents first.
    jobs: list[tuple[Source, str, str]] = []
    for (kind, value), item in candidates.items():
        if item["incidents"] & red:
            continue
        if kind in ("md5", "sha1") and _hash_from_files(item["sources"]):
            continue
        if not found_too and indicators_found.only_found(item["sources"]):
            continue
        if blocked(db, kind, value, allowlist, red=set()):  # TLP:RED handled above
            continue
        # Held by the data guard: judged again at every pass, at no request, so it is asked the
        # pass after its class is opened and never before.
        if held(kind, value, judged):
            continue
        known = cached.get((kind, value), {})
        jobs += [(s, kind, value) for s in on if s.supports(kind) and not fresh(known.get(s.id), cfg)]

    started, calls = time.monotonic(), 0
    while jobs and calls < max_calls:
        remaining = budget_seconds - (time.monotonic() - started)
        if remaining <= 0:
            break
        waits = {source.id: src.wait(db, source) for source in {job[0].id: job[0] for job in jobs}.values()}
        # A source whose keys are not back within this pass is left for the next.
        jobs = [job for job in jobs if waits[job[0].id] <= remaining]
        ready = next((job for job in jobs if waits[job[0].id] == 0), None)
        if ready is None:
            if not jobs:
                break
            time.sleep(min(waits[job[0].id] for job in jobs))
            continue
        jobs.remove(ready)
        source, kind, value = ready
        ask(db, source, kind, value)
        calls += 1
    return calls


# --------------------------------------------------------------------------- #
# Bulk checks                                                                 #
# --------------------------------------------------------------------------- #
MAX_CHECK_ITEMS = 10_000


def plan_check(
    db: OrmSession, pairs: Iterable[tuple[str, str]], shared: dict[str, Any], force: bool = False
) -> dict[str, Any]:
    """What a bulk check would ask: per indicator the sources to ask, and
    per source how many requests against what its instance may still make today.
    ``neverSent`` counts what the rule of the look-ups keeps in, ``held`` what the data guard holds
    for the look-ups made outside playbooks: neither is asked about."""
    from ..automation import instance_keys

    cfg = config(shared)
    allowlist = Allowlist(shared.get("iocAllowlist") or [])
    red = red_incidents(db)
    judged = judge(shared)
    on = asked(db)
    wanted = list(dict.fromkeys(pairs))[:MAX_CHECK_ITEMS]
    cached: dict[tuple[str, str], dict[str, Enrichment]] = {}
    if not force and wanted:
        values = sorted({v for _, v in wanted})
        for start in range(0, len(values), 500):
            for row in db.scalars(select(Enrichment).where(Enrichment.value.in_(values[start : start + 500]))):
                cached.setdefault((row.type, row.value), {})[row.provider] = row
    pending, never, kept_in, reused = [], 0, 0, 0
    need: dict[str, int] = {}
    for kind, value in wanted:
        if blocked(db, kind, value, allowlist, red=red):
            never += 1
            continue
        if held(kind, value, judged):
            kept_in += 1
            continue
        known = cached.get((kind, value), {})
        ask_ids = [s.id for s in on if s.supports(kind) and (force or not fresh(known.get(s.id), cfg))]
        if not ask_ids:
            reused += 1
            continue
        pending.append([kind, value, ask_ids])
        for source_id in ask_ids:
            need[source_id] = need.get(source_id, 0) + 1
    listed, seconds = [], 0.0
    for source in on:
        count = need.get(source.id, 0)
        if not count:
            continue
        left = src.left_today(db, source)
        today = count if left is None else min(count, left)
        keys = max(1, src.keys_count(source))
        per_minute = instance_keys.policy_of(source.instance)["perMinute"]
        # With a limit a minute the keys set the pace; without one, about a request a second.
        seconds = max(seconds, today * 60 / (per_minute * keys) if per_minute else float(today))
        listed.append(
            {
                "provider": source.id,
                "label": source.label,
                "keys": keys,
                "needed": count,
                "leftToday": left,
                "today": today,
                "later": count - today,
            }
        )
    return {
        "total": len(wanted),
        "toAsk": len(pending),
        "reused": reused,
        "neverSent": never,
        "held": kept_in,
        "seconds": int(seconds),
        "sources": listed,
        "pending": pending,
        "items": [[k, v] for k, v in wanted],
    }


def start_check(
    db: OrmSession, plan: dict[str, Any], label: str, actor: str, *, of_list: IocList | None = None
) -> IocCheck:
    """Queue a bulk check (the caller commits). ``of_list`` says it is of a whole watch list: its
    history is written when the check ends (ioc_history.py)."""
    now = now_iso()
    row = IocCheck(
        id=uuid.uuid4().hex,
        label=label[:200],
        status="running" if plan["pending"] else "done",
        total=plan["toAsk"],
        done=0,
        message=held_note(plan.get("held", 0)),
        pending=plan["pending"],
        items=plan["items"],
        created_at=now,
        created_by=actor,
        updated_at=now,
    )
    db.add(row)
    if of_list is not None:
        from .. import ioc_history

        ioc_history.begin(db, row, of_list)
        if row.status == "done":  # every source had answered already: the check is over as it starts
            db.flush()
            ioc_history.finish(db, row)
    return row


def check_progress(db: OrmSession, row: IocCheck) -> dict[str, Any]:
    done = [tuple(item) for item in row.items or []]
    left = {(k, v) for k, v, _ in row.pending or []}
    found = summaries(db, (pair for pair in done if pair not in left)) if done else {}
    verdicts: dict[str, int] = {}
    for summary in found.values():
        if summary:
            verdicts[summary["verdict"]] = verdicts.get(summary["verdict"], 0) + 1
    return {
        "id": row.id,
        "label": row.label,
        "status": row.status,
        "total": row.total,
        "done": row.done,
        "message": row.message,
        "verdicts": verdicts,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "updatedAt": row.updated_at,
    }


def run_checks(db: OrmSession, shared: dict[str, Any], budget_seconds: float = 60.0, max_calls: int = 300) -> int:
    """Work through the bulk checks, oldest first; returns the requests made.

    A check whose remaining sources have all used up their keys is left
    ``waiting`` with a message that says so: it goes on when a key is free again.

    The data guard is asked again as a check goes on: what it holds now is not asked about, whatever
    was planned (a class may have been closed since), and the message of the check counts it."""
    started, calls = time.monotonic(), 0
    active = db.scalars(
        select(IocCheck).where(IocCheck.status.in_(("running", "waiting"))).order_by(IocCheck.created_at)
    ).all()
    if not active:
        return 0
    by_id = {source.id: source for source in asked(db)}
    judged = judge(shared)
    allowlist = Allowlist(shared.get("iocAllowlist") or [])
    red = red_incidents(db)
    for check in active:
        held_now = {(k, v) for k, v in (tuple(item[:2]) for item in check.items or []) if held(k, v, judged)}
        # What the rule of the look-ups keeps in was never the guard's to hold: it is not counted as held.
        note = held_note(sum(1 for k, v in held_now if not blocked(db, k, v, allowlist, red=red)))
        pending = [[k, v, list(ids)] for k, v, ids in check.pending or [] if (k, v) not in held_now]
        # A source that is off now (or that does not exist any more) is not waited for.
        for item in pending:
            item[2] = [source_id for source_id in item[2] if source_id in by_id]
        while calls < max_calls:
            remaining = budget_seconds - (time.monotonic() - started)
            jobs = [(by_id[source_id], item) for item in pending for source_id in item[2]]
            if not jobs or remaining <= 0:
                break
            waits = {source_id: src.wait(db, by_id[source_id]) for source_id in {job[0].id for job in jobs}}
            ready = next((job for job in jobs if waits[job[0].id] == 0), None)
            if ready is None:
                soonest = min(waits.values())
                if soonest > remaining:
                    break
                time.sleep(soonest)
                continue
            source, item = ready
            reason = ask(db, source, item[0], item[1])
            calls += 1
            if reason is None:
                item[2].remove(source.id)
        finished = [item for item in pending if not item[2]]
        pending = [item for item in pending if item[2]]
        check.done = check.total - len(pending)
        check.pending = pending
        flag_modified(check, "pending")
        if not pending:
            check.status, check.message = "done", note
            from .. import ioc_history

            ioc_history.finish(db, check)
        else:
            waiting = {source_id for item in pending for source_id in item[2]}
            spent = sorted(by_id[source_id].label for source_id in waiting if src.wait(db, by_id[source_id]) > 0)
            if len(spent) == len(waiting):
                check.status = "waiting"
                check.message = (
                    f"{', '.join(spent)}: every key is used up. It goes on by itself when one is free again. {note}"
                ).strip()
            else:
                check.status, check.message = "running", note
        if finished or check.status != "running":
            check.updated_at = now_iso()
        db.commit()
        if budget_seconds - (time.monotonic() - started) <= 0 or calls >= max_calls:
            break
    return calls
