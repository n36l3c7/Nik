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
every enabled provider that takes its type, and again when the cached answer
is older than the cache period (24 h by default). E-mail addresses are never
sent.

**Rate limits** follow each provider's free tier (``providers.Provider``):
a minimum interval between two requests and a daily quota, per API process.
A provider that answers 429 waits an hour; one that refuses its key is
reported in Settings and skipped until the key changes.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session as OrmSession

from .. import vault
from ..iocs import Allowlist, normalize
from ..models import Enrichment, Incident, IntegrationKey, IocEntry
from ..security import now_iso
from .providers import BY_ID, HASHES, PROVIDERS, Provider, ProviderError

VERDICT_ORDER = ("malicious", "suspicious", "harmless", "unknown")
LOOKUP_TYPES = ("ip", "domain", "url", *HASHES)
ERROR_RETRY = timedelta(hours=1)
RUNNING_STALE = timedelta(minutes=10)
INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home", ".home.arpa", ".localdomain")

DEFAULTS: dict[str, Any] = {
    # Automatic lookups per type (off until an analyst turns them on).
    "auto": {"ip": False, "url": False, "hash": False},
    "ttlHours": 24,
    # Providers the analysts allow (a provider also needs its key, if any).
    "providers": {p.id: True for p in PROVIDERS},
}


def config(shared: dict[str, Any]) -> dict[str, Any]:
    """The ``enrichment`` settings with every default filled in."""
    raw = shared.get("enrichment") if isinstance(shared.get("enrichment"), dict) else {}
    auto = {**DEFAULTS["auto"], **(raw.get("auto") or {})}
    providers = {**DEFAULTS["providers"], **(raw.get("providers") or {})}
    try:
        ttl = min(720, max(1, int(raw.get("ttlHours", DEFAULTS["ttlHours"]))))
    except (TypeError, ValueError):
        ttl = DEFAULTS["ttlHours"]
    return {
        "auto": {k: bool(v) for k, v in auto.items()},
        "ttlHours": ttl,
        "providers": {k: bool(v) for k, v in providers.items()},
    }


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
def keys(db: OrmSession) -> dict[str, str | None]:
    """Decrypted keys by provider (None when unreadable)."""
    return {row.provider: vault.decrypt(row.secret) for row in db.scalars(select(IntegrationKey))}


def usable(provider: Provider, cfg: dict[str, Any], all_keys: dict[str, str | None]) -> bool:
    if not cfg["providers"].get(provider.id, True):
        return False
    if provider.key == "required":
        return bool(all_keys.get(provider.id))
    return True


# --------------------------------------------------------------------------- #
# What may be sent                                                            #
# --------------------------------------------------------------------------- #
def _internal_host(host: str) -> str | None:
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
        reason = _internal_host(value)
    elif kind == "domain":
        reason = _internal_host(value)
    elif kind == "url":
        from urllib.parse import urlsplit

        try:
            host = urlsplit(value).hostname or ""
        except ValueError:
            host = ""
        reason = _internal_host(host) if host else "a URL without a host"
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
    return None


# --------------------------------------------------------------------------- #
# Rate limits (per API process)                                               #
# --------------------------------------------------------------------------- #
class _Limiter:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.next_at: dict[str, float] = {}
        self.day: dict[str, tuple[str, int]] = {}
        self.cooldown: dict[str, float] = {}

    def wait_for(self, provider: Provider) -> float:
        """Seconds before the provider may be called (inf: daily quota spent)."""
        now = time.monotonic()
        with self.lock:
            if self.cooldown.get(provider.id, 0) > now:
                return self.cooldown[provider.id] - now
            today = datetime.now(timezone.utc).date().isoformat()
            day, used = self.day.get(provider.id, (today, 0))
            if day == today and provider.daily and used >= provider.daily:
                return float("inf")
            return max(0.0, self.next_at.get(provider.id, 0) - now)

    def take(self, provider: Provider) -> None:
        now = time.monotonic()
        with self.lock:
            self.next_at[provider.id] = now + provider.interval
            today = datetime.now(timezone.utc).date().isoformat()
            day, used = self.day.get(provider.id, (today, 0))
            self.day[provider.id] = (today, used + 1 if day == today else 1)

    def back_off(self, provider: Provider, seconds: float = 3600) -> None:
        with self.lock:
            self.cooldown[provider.id] = time.monotonic() + seconds

    def reset(self) -> None:
        with self.lock:
            self.next_at.clear()
            self.day.clear()
            self.cooldown.clear()


limiter = _Limiter()


# --------------------------------------------------------------------------- #
# Cache                                                                       #
# --------------------------------------------------------------------------- #
def _age(row: Enrichment) -> timedelta:
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(row.checked_at.replace("Z", "+00:00"))
    except ValueError:
        return timedelta.max


def fresh(row: Enrichment | None, ttl_hours: int) -> bool:
    if row is None:
        return False
    if row.status == "done":
        return _age(row) < timedelta(hours=ttl_hours)
    if row.status == "running":
        return _age(row) < RUNNING_STALE
    return _age(row) < ERROR_RETRY


def as_dict(row: Enrichment) -> dict[str, Any]:
    provider = BY_ID.get(row.provider)
    return {
        "provider": row.provider,
        "label": provider.label if provider else row.provider,
        "status": row.status,
        "verdict": row.verdict,
        "summary": row.summary,
        "link": row.link,
        "data": row.data or {},
        "error": row.error,
        "checkedAt": row.checked_at,
    }


def results(db: OrmSession, kind: str, value: str) -> list[dict[str, Any]]:
    rows = db.scalars(select(Enrichment).where(Enrichment.type == kind, Enrichment.value == value)).all()
    order = {p.id: i for i, p in enumerate(PROVIDERS)}
    return [as_dict(r) for r in sorted(rows, key=lambda r: order.get(r.provider, 99))]


def worst(verdicts: Iterable[str]) -> str | None:
    seen = set(verdicts)
    return next((v for v in VERDICT_ORDER if v in seen), None)


def summaries(db: OrmSession, pairs: Iterable[tuple[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
    """``(type, value) -> {verdict, flagged, checked}`` from the cache."""
    wanted = set(pairs)
    values = sorted({v for _, v in wanted})
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for start in range(0, len(values), 500):
        chunk = values[start : start + 500]
        for row in db.scalars(select(Enrichment).where(Enrichment.value.in_(chunk), Enrichment.status == "done")):
            key = (row.type, row.value)
            if key not in wanted:
                continue
            item = out.setdefault(key, {"verdicts": [], "flagged": 0, "checked": 0})
            item["verdicts"].append(row.verdict)
            item["checked"] += 1
            item["flagged"] += row.verdict in ("malicious", "suspicious")
    return {
        key: {"verdict": worst(item["verdicts"]), "flagged": item["flagged"], "checked": item["checked"]}
        for key, item in out.items()
    }


# --------------------------------------------------------------------------- #
# Lookups                                                                     #
# --------------------------------------------------------------------------- #
def lookup_one(db: OrmSession, provider: Provider, kind: str, value: str, key: str | None) -> Enrichment:
    """Ask one provider now and store its answer (or the error)."""
    row = db.get(Enrichment, (kind, value, provider.id))
    if row is None:
        row = Enrichment(type=kind, value=value, provider=provider.id, data={}, checked_at=now_iso())
        db.add(row)
    row.status, row.checked_at = "running", now_iso()
    db.commit()
    limiter.take(provider)
    try:
        answer = provider.lookup(kind, value, key)
        row.status, row.error = "done", None
        row.verdict = answer["verdict"]
        row.summary = answer["summary"][:500]
        row.link = answer.get("link", "")[:1000]
        row.data = answer.get("data") or {}
    except ProviderError as exc:
        if exc.kind == "rate":
            limiter.back_off(provider)
        elif exc.kind == "auth":
            limiter.back_off(provider, 6 * 3600)
        row.status, row.error = "error", str(exc)[:500]
    except Exception as exc:  # noqa: BLE001 - a malformed answer must not stop the others
        row.status, row.error = "error", f"unexpected answer: {exc}"[:500]
    row.checked_at = now_iso()
    db.commit()
    return row


def check_now(db: OrmSession, kind: str, value: str, shared: dict[str, Any], force: bool = False) -> dict[str, Any]:
    """An analyst's "Check now": every usable provider for the type, waiting
    briefly for an interval but skipping a provider whose quota is spent."""
    cfg = config(shared)
    all_keys = keys(db)
    skipped = []
    for provider in PROVIDERS:
        if not provider.supports(kind) or not usable(provider, cfg, all_keys):
            continue
        if not force and fresh(db.get(Enrichment, (kind, value, provider.id)), cfg["ttlHours"]):
            continue
        wait = limiter.wait_for(provider)
        if wait > 3:
            skipped.append(
                {
                    "provider": provider.id,
                    "label": provider.label,
                    "reason": "daily quota used" if wait == float("inf") else f"rate limit: retry in {int(wait) + 1} s",
                }
            )
            continue
        if wait:
            time.sleep(wait)
        lookup_one(db, provider, kind, value, all_keys.get(provider.id))
    return {"results": results(db, kind, value), "skipped": skipped}


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
        jobs += [
            (p, kind, value) for p in providers if p.supports(kind) and not fresh(known.get(p.id), cfg["ttlHours"])
        ]

    started, calls = time.monotonic(), 0
    while jobs and calls < max_calls:
        remaining = budget_seconds - (time.monotonic() - started)
        if remaining <= 0:
            break
        waits = {p.id: limiter.wait_for(p) for p in {job[0] for job in jobs}}
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
        lookup_one(db, provider, kind, value, all_keys.get(provider.id))
        calls += 1
    return calls
