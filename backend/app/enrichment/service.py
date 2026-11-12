"""Threat-intelligence lookups: what may be sent, to whom, how often, and the cache.

**What is never sent**, whoever asks (an analyst's "Check now" or the
background worker):

- private, loopback, link-local and other non-public addresses, internal
  names (no dot, ``.local``, ``.lan``, ``.internal``, ``.corp``,
  ``.home.arpa``…) and URLs on them;
- values on the IOC allowlist (Settings -> IOC allowlist);
- values seen in an incident whose report is classified **TLP:RED**.

**Automatic lookups** (Settings -> Threat intelligence) are off until an
analyst turns them on, per type: IP addresses, URLs and domains, file
hashes. The worker (``worker.py``) checks each new indicator once with
every enabled provider that takes its type. E-mail addresses are never sent.

**Retention**: an answer stands for a number of days set per type (IP
addresses 30, URLs and domains 30, hashes 180 by default). Past it the
answer is *expired*: it is asked again (by the worker for the types it
handles, or when someone opens the indicator), unless "refresh expired
answers" is turned off; then it is kept, marked as expired, until someone
checks again. The last ten answers of each provider stay in a history.

**Overall verdict**: a weighted score, see ``overall``.

**Rate limits** follow each provider's free tier (``providers.Provider``):
a minimum interval between two requests and a daily quota, per API process
and **per key**. A provider can have several keys: requests go round them
(the one used longest ago first), and a key that answers 429 waits an hour
while the others carry on. A key the provider refuses waits ten minutes;
refused three times in a row it is marked rejected, shown in Settings and
left out until an admin replaces it.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core import vault
from ..core.models import (
    Enrichment,
    EnrichmentHistory,
    Incident,
    IntegrationKey,
    IocCheck,
    IocEntry,
    IocList,
    IocListItem,
    IocRecord,
)
from ..core.security import now_iso
from ..iocs import Allowlist, normalize
from .providers import BY_ID, HASHES, PROVIDERS, Provider, ProviderError

VERDICT_ORDER = ("malicious", "suspicious", "harmless", "unknown")
LOOKUP_TYPES = ("ip", "domain", "url", *HASHES)
ERROR_RETRY = timedelta(hours=1)
RUNNING_STALE = timedelta(minutes=10)
INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home", ".home.arpa", ".localdomain")

RETENTION_GROUPS = ("ip", "url", "hash")  # url covers domains, hash the three digests
VT_ENGINES = ("flagged", "all")

DEFAULTS: dict[str, Any] = {
    # Automatic lookups per type (off until an analyst turns them on).
    "auto": {"ip": False, "url": False, "hash": False},
    # How long an answer stands, in days, per type. A hash's reputation
    # changes slowly; an address or a URL changes hands.
    "retentionDays": {"ip": 30, "url": 30, "hash": 180},
    # Ask again when an answer is past its retention (else it is kept and
    # shown as expired until someone checks again).
    "refreshExpired": True,
    # VirusTotal: the engines listed (those that flag the value, or all) and
    # the sections that take one more request each from the quota.
    "virustotal": {"engines": "flagged", "relations": False, "comments": False},
    # Providers the analysts allow (a provider also needs its key, if any).
    "providers": {p.id: True for p in PROVIDERS},
}


def config(shared: dict[str, Any]) -> dict[str, Any]:
    """The ``enrichment`` settings with every default filled in."""
    raw = shared.get("enrichment") if isinstance(shared.get("enrichment"), dict) else {}
    auto = {**DEFAULTS["auto"], **(raw.get("auto") or {})}
    providers = {**DEFAULTS["providers"], **(raw.get("providers") or {})}
    retention = dict(DEFAULTS["retentionDays"])
    for group, days in (raw.get("retentionDays") or {}).items():
        try:
            if group in retention:
                retention[group] = min(730, max(1, int(days)))
        except (TypeError, ValueError):
            pass
    vt = {**DEFAULTS["virustotal"], **(raw.get("virustotal") if isinstance(raw.get("virustotal"), dict) else {})}
    return {
        "auto": {k: bool(v) for k, v in auto.items()},
        "retentionDays": retention,
        "refreshExpired": bool(raw.get("refreshExpired", DEFAULTS["refreshExpired"])),
        "virustotal": {
            "engines": vt["engines"] if vt["engines"] in VT_ENGINES else "flagged",
            "relations": bool(vt["relations"]),
            "comments": bool(vt["comments"]),
        },
        "providers": {k: bool(v) for k, v in providers.items()},
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


# --------------------------------------------------------------------------- #
# Keys                                                                        #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Key:
    """A provider's API key that can be used now (readable, not rejected)."""

    id: str
    secret: str


Keys = dict[str, list[Key]]


def keys(db: OrmSession) -> Keys:
    """The usable keys of each provider, oldest first."""
    out: Keys = {}
    for row in db.scalars(select(IntegrationKey).order_by(IntegrationKey.updated_at, IntegrationKey.id)):
        secret = vault.decrypt(row.secret) if row.status == "ok" else None
        if secret:
            out.setdefault(row.provider, []).append(Key(row.id, secret))
    return out


def usable(provider: Provider, cfg: dict[str, Any], all_keys: Keys) -> bool:
    if not cfg["providers"].get(provider.id, True):
        return False
    if provider.key == "required":
        return bool(all_keys.get(provider.id))
    return True


def slots(provider: Provider, all_keys: Keys) -> list[Key | None]:
    """What a request to the provider can be made with: each of its keys, or
    no key at all for a provider that takes none (or works without)."""
    own = list(all_keys.get(provider.id, [])) if provider.key != "none" else []
    return own or ([None] if provider.key != "required" else [])


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
# Rate limits (per API process)                                               #
# --------------------------------------------------------------------------- #
def _slot(provider: Provider, key: Key | None) -> str:
    return f"{provider.id}:{key.id if key else ''}"


class _Limiter:
    """The free-tier limits, counted per key: each key of a provider has its
    own interval, daily quota and back-off."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.next_at: dict[str, float] = {}
        self.day: dict[str, tuple[str, int]] = {}
        self.cooldown: dict[str, float] = {}
        self.used_at: dict[str, float] = {}

    def wait_for(self, provider: Provider, key: Key | None = None) -> float:
        """Seconds before the key may be used (inf: its daily quota is spent)."""
        slot = _slot(provider, key)
        now = time.monotonic()
        with self.lock:
            if self.cooldown.get(slot, 0) > now:
                return self.cooldown[slot] - now
            today = datetime.now(timezone.utc).date().isoformat()
            day, used = self.day.get(slot, (today, 0))
            if day == today and provider.daily and used >= provider.daily:
                return float("inf")
            return max(0.0, self.next_at.get(slot, 0) - now)

    def take(self, provider: Provider, key: Key | None = None) -> None:
        slot = _slot(provider, key)
        now = time.monotonic()
        with self.lock:
            self.next_at[slot] = now + provider.interval
            self.used_at[slot] = now
            today = datetime.now(timezone.utc).date().isoformat()
            day, used = self.day.get(slot, (today, 0))
            self.day[slot] = (today, used + 1 if day == today else 1)

    def charge(self, provider: Provider, key: Key | None, extra: int) -> None:
        """A lookup that took more than one request: count the others too."""
        if extra <= 0:
            return
        slot = _slot(provider, key)
        with self.lock:
            self.next_at[slot] = self.next_at.get(slot, time.monotonic()) + provider.interval * extra
            day, used = self.day.get(slot, (datetime.now(timezone.utc).date().isoformat(), 0))
            self.day[slot] = (day, used + extra)

    def back_off(self, provider: Provider, key: Key | None = None, seconds: float = 3600) -> None:
        with self.lock:
            self.cooldown[_slot(provider, key)] = time.monotonic() + seconds

    def pick(self, provider: Provider, candidates: list[Key | None]) -> tuple[float, Key | None]:
        """The key to use next and how long to wait for it: the one free
        soonest and, among those free now, the one used longest ago, so the
        requests go round the keys."""
        if not candidates:
            return float("inf"), None
        with self.lock:
            last = {id(c): self.used_at.get(_slot(provider, c), 0.0) for c in candidates}
        waits = [(self.wait_for(provider, c), last[id(c)], index, c) for index, c in enumerate(candidates)]
        wait, _, _, chosen = min(waits, key=lambda w: w[:3])
        return wait, chosen

    def reset(self) -> None:
        with self.lock:
            self.next_at.clear()
            self.day.clear()
            self.cooldown.clear()
            self.used_at.clear()


limiter = _Limiter()


# --------------------------------------------------------------------------- #
# Cache                                                                       #
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


def as_dict(row: Enrichment, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    provider = BY_ID.get(row.provider)
    return {
        "provider": row.provider,
        "label": provider.label if provider else row.provider,
        "weight": provider.weight if provider else 1,
        "status": row.status,
        "verdict": row.verdict,
        "summary": row.summary,
        "link": row.link,
        "data": row.data or {},
        "error": row.error,
        "checkedAt": row.checked_at,
        "expired": bool(cfg) and expired(row, cfg),
        "hasRaw": row.raw is not None,
    }


def results(db: OrmSession, kind: str, value: str, cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Each provider's latest answer, with its earlier verdicts (newest first)."""
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
    order = {p.id: i for i, p in enumerate(PROVIDERS)}
    return [
        {**as_dict(r, cfg), "history": history.get(r.provider, [])}
        for r in sorted(rows, key=lambda r: order.get(r.provider, 99))
    ]


# What a verdict is worth in the overall score.
# Nik's own analysis of the value (the scan of a URL, the file with that
# hash) among the sources of its reputation: see ``analysis_links``.
NIK, NIK_WEIGHT = "nik", 3
VERDICT_VALUE = {"malicious": 1.0, "suspicious": 0.5, "harmless": 0.0, "unknown": 0.0}
MALICIOUS_SCORE, SUSPICIOUS_SCORE = 50, 20


def overall(answers: Iterable[tuple[str, str]]) -> dict[str, Any] | None:
    """The indicator's overall reputation from ``(provider id, verdict)`` of
    the providers that answered: a score from 0 to 100, each provider's
    verdict counted by its weight (VirusTotal, abuse.ch and Safe Browsing 3;
    AbuseIPDB, GreyNoise and urlscan 2; OTX and InternetDB 1).

    - **malicious**: score 50 or more, and at least one provider says malicious;
    - **suspicious**: score 20 or more, or any provider says malicious;
    - **harmless**: nobody flags it and somebody vouches for it;
    - **unknown** otherwise.
    """
    answers = list(answers)
    if not answers:
        return None
    counts = {v: 0 for v in VERDICT_ORDER}
    weight = points = 0.0
    counted = 0
    for provider_id, verdict in answers:
        provider = BY_ID.get(provider_id)
        # Facts, not a judgement: counted only when they flag the value. So is
        # Nik's own analysis of the value (NIK), which has the highest weight.
        informational = provider_id == NIK or (provider is not None and provider.informational)
        if informational and verdict not in ("malicious", "suspicious"):
            continue
        counted += 1
        w = NIK_WEIGHT if provider_id == NIK else provider.weight if provider else 1
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
    if not counted:
        return None
    return {"verdict": verdict, "score": score, "flagged": flagged, "checked": counted, "counts": counts}


def summaries(db: OrmSession, pairs: Iterable[tuple[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
    """``(type, value) -> {verdict, score, flagged, checked, counts}`` from the cache."""
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
    summed = {key: overall(found) for key, found in answers.items()}
    return {key: value for key, value in summed.items() if value is not None}


# --------------------------------------------------------------------------- #
# Lookups                                                                     #
# --------------------------------------------------------------------------- #
HISTORY_KEPT = 10
RAW_MAX_BYTES = 1_500_000
KEY_REFUSALS = 3  # refusals in a row before a key is marked rejected
KEY_REFUSED_WAIT = 600  # seconds a refused key waits before it is tried again


def lookup_one(
    db: OrmSession, provider: Provider, kind: str, value: str, key: Key | None, options: dict | None = None
) -> tuple[Enrichment, str]:
    """Ask one provider now, with one key, and store its answer (or the
    error). Returns the row and the outcome: ``ok``, ``rate``, ``auth`` or
    ``error``. An answer that replaces an earlier one goes to the history."""
    row = db.get(Enrichment, (kind, value, provider.id))
    if row is None:
        row = Enrichment(type=kind, value=value, provider=provider.id, data={}, checked_at=now_iso())
        db.add(row)
    row.status, row.checked_at = "running", now_iso()
    db.commit()
    limiter.take(provider, key)
    outcome = "ok"
    try:
        answer = provider.lookup(kind, value, key.secret if key else None, options)
        limiter.charge(provider, key, int(answer.get("calls", 1)) - 1)
        row.status, row.error = "done", None
        row.verdict = answer["verdict"]
        row.summary = answer["summary"][:500]
        row.link = answer.get("link", "")[:1000]
        row.data = answer.get("data") or {}
        row.raw = _bounded(answer.get("raw"))
        flag_modified(row, "data")
        flag_modified(row, "raw")
        _accepted(db, key)
    except ProviderError as exc:
        outcome = exc.kind if exc.kind in ("rate", "auth") else "error"
        if exc.kind == "rate":
            limiter.back_off(provider, key)
        elif exc.kind == "auth":
            _refused(db, provider, key, str(exc))
        row.status, row.error = "error", str(exc)[:500]
    except Exception as exc:  # noqa: BLE001 - a malformed answer must not stop the others
        outcome = "error"
        row.status, row.error = "error", f"unexpected answer: {exc}"[:500]
    row.checked_at = now_iso()
    if row.status == "done":
        _remember(db, row)
    db.commit()
    return row, outcome


def _bounded(raw: Any) -> Any:
    """The provider's answer, unless it is too large to keep."""
    if raw is None:
        return None
    try:
        size = len(json.dumps(raw))
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


def _accepted(db: OrmSession, key: Key | None) -> None:
    stored = db.get(IntegrationKey, key.id) if key else None
    if stored is not None and stored.failures:
        stored.failures, stored.error = 0, None


def _refused(db: OrmSession, provider: Provider, key: Key | None, message: str) -> None:
    """A refusal can be a passing fault of the provider: the key waits ten
    minutes and is tried again. Refused ``KEY_REFUSALS`` times in a row, it is
    taken out of the rotation and shown as rejected in Settings. Without a
    key the provider waits six hours."""
    if key is None:
        limiter.back_off(provider, None, 6 * 3600)
        return
    limiter.back_off(provider, key, KEY_REFUSED_WAIT)
    stored = db.get(IntegrationKey, key.id)
    if stored is None:
        return
    stored.failures = (stored.failures or 0) + 1
    stored.error = message[:300]
    if stored.failures >= KEY_REFUSALS:
        stored.status = "rejected"


def ask(
    db: OrmSession,
    provider: Provider,
    kind: str,
    value: str,
    all_keys: Keys,
    max_wait: float = 0.0,
    options: dict | None = None,
) -> str | None:
    """One lookup, moving to the provider's next key when one is rate-limited
    or refused. Returns None when it was asked, else why it was not."""
    candidates = slots(provider, all_keys)
    while candidates:
        wait, key = limiter.pick(provider, candidates)
        if wait > max_wait:
            return "daily quota used" if wait == float("inf") else f"rate limit: retry in {int(wait) + 1} s"
        if wait:
            time.sleep(wait)
        _, outcome = lookup_one(db, provider, kind, value, key, options)
        if outcome not in ("rate", "auth"):
            return None
        candidates = [c for c in candidates if c is not key]
        if outcome == "auth" and key is not None:
            all_keys[provider.id] = [k for k in all_keys.get(provider.id, []) if k.id != key.id]
    return None  # every key was tried: the stored row says what the last one answered


def wait(provider: Provider, all_keys: Keys) -> float:
    """Seconds before the provider can be asked with any of its keys."""
    return limiter.pick(provider, slots(provider, all_keys))[0]


def check_now(db: OrmSession, kind: str, value: str, shared: dict[str, Any], force: bool = False) -> dict[str, Any]:
    """An analyst's "Check now": every usable provider for the type, waiting
    briefly for an interval but skipping a provider whose keys are all
    waiting for their rate limit or quota."""
    cfg = config(shared)
    all_keys = keys(db)
    skipped = []
    for provider in PROVIDERS:
        if not provider.supports(kind) or not usable(provider, cfg, all_keys):
            continue
        if not force and fresh(db.get(Enrichment, (kind, value, provider.id)), cfg):
            continue
        reason = ask(db, provider, kind, value, all_keys, max_wait=3.0, options=cfg.get(provider.id))
        if reason:
            skipped.append({"provider": provider.id, "label": provider.label, "reason": reason})
    return {"results": results(db, kind, value, cfg), "skipped": skipped}


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
    all_keys = keys(db)
    providers = [p for p in PROVIDERS if usable(p, cfg, all_keys) and any(p.supports(t) for t in types)]
    if not providers:
        return 0
    allowlist = Allowlist(shared.get("iocAllowlist") or [])
    red = red_incidents(db)
    rows = db.execute(
        select(IocEntry.type, IocEntry.value, IocEntry.incident_id, IocEntry.sources)
        .join(Incident, Incident.id == IocEntry.incident_id)
        .where(IocEntry.type.in_(sorted(types)))
        .order_by(Incident.updated_at.desc())
        .limit(20_000)
    ).all()
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    for kind, value, incident_id, sources in rows:
        item = candidates.setdefault((kind, value), {"incidents": set(), "sources": []})
        item["incidents"].add(incident_id)
        item["sources"] += list(sources or [])

    cached: dict[tuple[str, str], dict[str, Enrichment]] = {}
    for row in db.scalars(select(Enrichment).where(Enrichment.type.in_(sorted(types)))):
        cached.setdefault((row.type, row.value), {})[row.provider] = row

    # The work: (provider, type, value) not in the cache, newest incidents first.
    jobs: list[tuple[Provider, str, str]] = []
    for (kind, value), item in candidates.items():
        if item["incidents"] & red:
            continue
        if kind in ("md5", "sha1") and _hash_from_files(item["sources"]):
            continue
        if blocked(db, kind, value, allowlist, red=set()):  # TLP:RED handled above
            continue
        known = cached.get((kind, value), {})
        jobs += [(p, kind, value) for p in providers if p.supports(kind) and not fresh(known.get(p.id), cfg)]

    started, calls = time.monotonic(), 0
    while jobs and calls < max_calls:
        remaining = budget_seconds - (time.monotonic() - started)
        if remaining <= 0:
            break
        waits = {p.id: wait(p, all_keys) for p in {job[0] for job in jobs}}
        jobs = [job for job in jobs if waits[job[0].id] != float("inf")]
        ready = next((job for job in jobs if waits[job[0].id] == 0), None)
        if ready is None:
            if not jobs:
                break
            soonest = min(waits[job[0].id] for job in jobs)
            if soonest > remaining:
                break
            time.sleep(soonest)
            continue
        jobs.remove(ready)
        provider, kind, value = ready
        ask(db, provider, kind, value, all_keys, options=cfg.get(provider.id))
        calls += 1
    return calls


# --------------------------------------------------------------------------- #
# Bulk checks                                                                 #
# --------------------------------------------------------------------------- #
MAX_CHECK_ITEMS = 10_000


def _left_today(provider: Provider, all_keys: Keys) -> int | None:
    """Requests the provider's keys can still make today; None: no stated limit."""
    if not provider.daily:
        return None
    today = datetime.now(timezone.utc).date().isoformat()
    left = 0
    with limiter.lock:
        for key in slots(provider, all_keys):
            day, used = limiter.day.get(_slot(provider, key), (today, 0))
            left += max(0, provider.daily - (used if day == today else 0))
    return left


def plan_check(
    db: OrmSession, pairs: Iterable[tuple[str, str]], shared: dict[str, Any], force: bool = False
) -> dict[str, Any]:
    """What a bulk check would ask: per indicator the providers to ask, and
    per provider how many requests against what is left today."""
    cfg = config(shared)
    all_keys = keys(db)
    allowlist = Allowlist(shared.get("iocAllowlist") or [])
    red = red_incidents(db)
    providers = [p for p in PROVIDERS if usable(p, cfg, all_keys)]
    wanted = list(dict.fromkeys(pairs))[:MAX_CHECK_ITEMS]
    cached: dict[tuple[str, str], dict[str, Enrichment]] = {}
    if not force and wanted:
        values = sorted({v for _, v in wanted})
        for start in range(0, len(values), 500):
            for row in db.scalars(select(Enrichment).where(Enrichment.value.in_(values[start : start + 500]))):
                cached.setdefault((row.type, row.value), {})[row.provider] = row
    pending, never, reused = [], 0, 0
    need: dict[str, int] = {}
    for kind, value in wanted:
        if blocked(db, kind, value, allowlist, red=red):
            never += 1
            continue
        known = cached.get((kind, value), {})
        ask_ids = [p.id for p in providers if p.supports(kind) and (force or not fresh(known.get(p.id), cfg))]
        if not ask_ids:
            reused += 1
            continue
        pending.append([kind, value, ask_ids])
        for provider_id in ask_ids:
            need[provider_id] = need.get(provider_id, 0) + 1
    sources, seconds = [], 0.0
    for provider in providers:
        count = need.get(provider.id, 0)
        if not count:
            continue
        left = _left_today(provider, all_keys)
        today = count if left is None else min(count, left)
        key_count = max(1, len(slots(provider, all_keys)))
        seconds = max(seconds, today * provider.interval / key_count)
        sources.append(
            {
                "provider": provider.id,
                "label": provider.label,
                "keys": len(all_keys.get(provider.id, [])),
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
        "seconds": int(seconds),
        "sources": sources,
        "pending": pending,
        "items": [[k, v] for k, v in wanted],
    }


def start_check(db: OrmSession, plan: dict[str, Any], label: str, actor: str) -> IocCheck:
    now = now_iso()
    row = IocCheck(
        id=uuid.uuid4().hex,
        label=label[:200],
        status="running" if plan["pending"] else "done",
        total=plan["toAsk"],
        done=0,
        message="",
        pending=plan["pending"],
        items=plan["items"],
        created_at=now,
        created_by=actor,
        updated_at=now,
    )
    db.add(row)
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

    A check whose remaining sources have all used their quota is left
    ``waiting`` with a message that says so: it goes on when one resets."""
    cfg = config(shared)
    all_keys = keys(db)
    started, calls = time.monotonic(), 0
    active = db.scalars(
        select(IocCheck).where(IocCheck.status.in_(("running", "waiting"))).order_by(IocCheck.created_at)
    ).all()
    for check in active:
        pending = [[k, v, list(ids)] for k, v, ids in check.pending or []]
        # A provider switched off or left without keys is not waited for.
        live = {p.id for p in PROVIDERS if usable(p, cfg, all_keys)}
        for item in pending:
            item[2] = [pid for pid in item[2] if pid in live]
        while calls < max_calls:
            remaining = budget_seconds - (time.monotonic() - started)
            jobs = [(BY_ID[pid], item) for item in pending for pid in item[2]]
            if not jobs or remaining <= 0:
                break
            waits = {p.id: wait(p, all_keys) for p in {job[0] for job in jobs}}
            ready = next((job for job in jobs if waits[job[0].id] == 0), None)
            if ready is None:
                soonest = min(waits.values())
                if soonest == float("inf") or soonest > remaining:
                    break
                time.sleep(soonest)
                continue
            provider, item = ready
            reason = ask(db, provider, item[0], item[1], all_keys, options=cfg.get(provider.id))
            calls += 1
            if reason is None or not reason.startswith(("daily quota", "rate limit")):
                item[2].remove(provider.id)
        finished = [item for item in pending if not item[2]]
        pending = [item for item in pending if item[2]]
        check.done = check.total - len(pending)
        check.pending = pending
        flag_modified(check, "pending")
        if not pending:
            check.status, check.message = "done", ""
        else:
            waiting = {pid for item in pending for pid in item[2]}
            spent = sorted(BY_ID[pid].label for pid in waiting if wait(BY_ID[pid], all_keys) == float("inf"))
            if len(spent) == len(waiting):
                check.status = "waiting"
                check.message = f"{', '.join(spent)}: daily quota used. It goes on by itself when the quota resets."
            else:
                check.status, check.message = "running", ""
        if finished or check.status != "running":
            check.updated_at = now_iso()
        db.commit()
        if budget_seconds - (time.monotonic() - started) <= 0 or calls >= max_calls:
            break
    return calls
