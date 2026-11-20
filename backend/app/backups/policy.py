"""When a backup is due, and which backups are kept: the rules, with no clock and no disk of their own.

**The schedule** is a list of moments ("slots") in the time zone the
administrator chose: every day at a time, every week on a day at that time,
or every N hours counted from that time of day (02:30 and every 6 hours:
02:30, 08:30, 14:30, 20:30). A backup is *due* when the latest slot has
passed and no backup was started since; one that failed is tried again an
hour later, not at once and not only at the next slot. A slot is *missed*
when it is past by more than the grace and still nothing was started.

**Retention.** A backup is *good* when it was written to its end and passed
its restore test. Kept: the latest ``last`` good ones, and for each of the
latest ``weeks`` weeks that has one, the latest good one of that week. A
backup that is neither written nor tested yet is never touched. Of those
that failed, the latest two are kept while they are newer than the last
good one or less than a week old: they are there to be looked at, not
counted, and they never fill the disk. So the last good backup is never
removed, however many bad ones came after it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

RETRY_AFTER = 3600
MISSED_GRACE = 2 * 3600
FAILED_KEPT = 7 * 86400
BAD_KEPT = 2


def zone(name: str) -> ZoneInfo | timezone:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def known_zone(name: str) -> bool:
    return isinstance(zone(name), ZoneInfo)


def _time_of_day(schedule: dict[str, Any]) -> tuple[int, int]:
    try:
        hour, minute = str(schedule.get("at") or "02:30").split(":")
        return max(0, min(23, int(hour))), max(0, min(59, int(minute)))
    except ValueError:
        return 2, 30


def interval(schedule: dict[str, Any]) -> int:
    """Seconds between two slots."""
    every = schedule.get("every")
    if every == "hours":
        return max(1, min(23, int(schedule.get("hours") or 6))) * 3600
    return 7 * 86400 if every == "week" else 86400


def _slots_around(schedule: dict[str, Any], now: float) -> list[float]:
    """The slots from eight days before ``now`` to eight days after, in order."""
    where = zone(str(schedule.get("timezone") or "UTC"))
    hour, minute = _time_of_day(schedule)
    today = datetime.fromtimestamp(now, where).date()
    every = schedule.get("every")
    found = []
    for offset in range(-8, 9):
        day = today + timedelta(days=offset)
        first = datetime(day.year, day.month, day.day, hour, minute, tzinfo=where)
        if every == "week":
            if day.weekday() == int(schedule.get("weekday") or 0) % 7:
                found.append(first.timestamp())
        elif every == "hours":
            step = interval(schedule)
            # Every moment of the day that is a whole number of steps from the chosen time.
            for index in range(86400 // step + 1):
                moment = first + timedelta(seconds=index * step)
                if moment.date() == day:
                    found.append(moment.timestamp())
            earlier = first - timedelta(seconds=step)
            while earlier.date() == day:
                found.append(earlier.timestamp())
                earlier -= timedelta(seconds=step)
        else:
            found.append(first.timestamp())
    return sorted(set(found))


def latest_slot(schedule: dict[str, Any], now: float) -> float | None:
    """The last moment a backup was meant to start, or None while the schedule is off."""
    if not schedule.get("enabled"):
        return None
    past = [slot for slot in _slots_around(schedule, now) if slot <= now]
    return past[-1] if past else None


def next_slot(schedule: dict[str, Any], now: float) -> float | None:
    if not schedule.get("enabled"):
        return None
    ahead = [slot for slot in _slots_around(schedule, now) if slot > now]
    return ahead[0] if ahead else None


@dataclass(frozen=True)
class Taken:
    """What the rules need to know of one backup."""

    id: str
    at: float  # when it was started
    state: str  # queued | running | done | failed
    verify: str = ""  # "" | queued | running | passed | failed
    kind: str = "full"

    @property
    def good(self) -> bool:
        return self.state == "done" and self.verify == "passed"

    @property
    def bad(self) -> bool:
        return self.state == "failed" or (self.state == "done" and self.verify == "failed")


def due(schedule: dict[str, Any], taken: list[Taken], now: float, since: float = 0.0) -> bool:
    """Whether the schedule asks for a backup now. ``since``: when the schedule was last set
    (a slot that passed before somebody turned the schedule on is not owed)."""
    slot = latest_slot(schedule, now)
    if slot is None or slot < since:
        return False
    full = [backup for backup in taken if backup.kind == "full" and backup.at >= slot]
    if any(backup.state in ("queued", "running") or backup.good for backup in full):
        return False
    if any(backup.state == "done" and backup.verify != "failed" for backup in full):
        return False  # written, its test still to come
    latest = max((backup.at for backup in full), default=None)
    return latest is None or now - latest >= RETRY_AFTER


def missed(schedule: dict[str, Any], taken: list[Taken], now: float, since: float = 0.0) -> float | None:
    """The slot that passed with no backup started, once the grace is over; None otherwise."""
    slot = latest_slot(schedule, now)
    if slot is None or slot < since:
        return None
    grace = min(MISSED_GRACE, interval(schedule) // 2)
    if now - slot < grace:
        return None
    if any(backup.kind == "full" and backup.at >= slot for backup in taken):
        return None
    return slot


def _week(at: float) -> tuple[int, int]:
    year, week, _day = datetime.fromtimestamp(at, timezone.utc).isocalendar()
    return year, week


def retention(taken: list[Taken], now: float, last: int, weeks: int) -> tuple[list[str], list[str]]:
    """Which full backups stay and which go: ``(kept, removed)``, each newest first."""
    full = sorted((backup for backup in taken if backup.kind == "full"), key=lambda backup: backup.at, reverse=True)
    good = [backup for backup in full if backup.good]
    keep = {backup.id for backup in good[: max(1, last)]}
    oldest_week = _week(now - max(0, weeks) * 7 * 86400)
    seen_weeks: set[tuple[int, int]] = set()
    for backup in good:
        week = _week(backup.at)
        if weeks > 0 and week > oldest_week and week not in seen_weeks:
            seen_weeks.add(week)
            keep.add(backup.id)
    newest_good = good[0].at if good else None
    bad_kept = 0
    for backup in full:
        if backup.good:
            continue
        if not backup.bad:
            keep.add(backup.id)  # still being written or tested
        elif bad_kept < BAD_KEPT and (newest_good is None or backup.at > newest_good or now - backup.at < FAILED_KEPT):
            keep.add(backup.id)
            bad_kept += 1
    kept = [backup.id for backup in full if backup.id in keep]
    removed = [backup.id for backup in full if backup.id not in keep]
    return kept, removed


def upgrade_retention(taken: list[Taken], keep: int) -> list[str]:
    """The snapshots taken before upgrades that go: all but the latest ``keep``."""
    snapshots = sorted(
        (backup for backup in taken if backup.kind == "upgrade" and backup.state in ("done", "failed")),
        key=lambda backup: backup.at,
        reverse=True,
    )
    return [backup.id for backup in snapshots[max(1, keep) :]]
