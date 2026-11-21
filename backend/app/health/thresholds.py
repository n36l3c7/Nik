"""The thresholds of the health page: one row of ``settings``, with defaults.

A row of the page is ``fine``, needs ``attention`` or is a ``problem``. For
what is measured, the two limits are here, each a whole number an
administrator can change. ``FIELDS`` gives every threshold its default, the
range it may take and the sentence the screen shows beside it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core.models import Setting

SETTINGS_ID = 44  # 45 is what the watch keeps (watch.py), 46 the token of the metrics (metrics.py)

# name: (default, lowest, highest, what it is)
FIELDS: dict[str, tuple[int, int, int, str]] = {
    "diskAttentionPercent": (80, 1, 99, "A disk needs attention when it is this full, in percent"),
    "diskProblemPercent": (90, 1, 100, "A disk is a problem when it is this full, in percent"),
    "diskFullAttentionDays": (30, 1, 3650, "A disk needs attention when it will be full within this many days"),
    "diskFullProblemDays": (7, 1, 3650, "A disk is a problem when it will be full within this many days"),
    "queueAttentionMinutes": (10, 1, 100000, "A queue needs attention when its oldest item has waited this long"),
    "queueProblemMinutes": (60, 1, 100000, "A queue is a problem when its oldest item has waited this long"),
    "lateAttentionMinutes": (5, 1, 100000, "A schedule or a fetch needs attention when it is this late"),
    "lateProblemMinutes": (60, 1, 100000, "A schedule or a fetch is a problem when it is this late"),
    "heartbeatAttentionSeconds": (60, 15, 86400, "The automation worker needs attention this long after its last sign"),
    "certificateAttentionDays": (30, 1, 3650, "The certificate needs attention this many days before it expires"),
    "certificateProblemDays": (7, 0, 3650, "The certificate is a problem this many days before it expires"),
    "syslogAttentionMinutes": (5, 1, 100000, "The forwarding needs attention when an entry has waited this long"),
    "syslogProblemMinutes": (30, 1, 100000, "The forwarding is a problem when an entry has waited this long"),
    "connectionsAttentionPercent": (80, 1, 100, "The database needs attention at this share of its connections"),
    "connectionsProblemPercent": (95, 1, 100, "The database is a problem at this share of its connections"),
    "transactionAttentionMinutes": (15, 1, 100000, "A transaction that has been open this long needs attention"),
    "clockAttentionSeconds": (5, 1, 86400, "The clocks need attention when they differ by this much"),
    "clockProblemSeconds": (60, 1, 86400, "The clocks are a problem when they differ by this much"),
}  # fmt: skip

# Pairs that must stay in order: attention before problem (or, for days left, the other way round).
_RISING = (
    ("diskAttentionPercent", "diskProblemPercent"),
    ("queueAttentionMinutes", "queueProblemMinutes"),
    ("lateAttentionMinutes", "lateProblemMinutes"),
    ("syslogAttentionMinutes", "syslogProblemMinutes"),
    ("connectionsAttentionPercent", "connectionsProblemPercent"),
    ("clockAttentionSeconds", "clockProblemSeconds"),
)
_FALLING = (
    ("diskFullAttentionDays", "diskFullProblemDays"),
    ("certificateAttentionDays", "certificateProblemDays"),
)


class ThresholdError(ValueError):
    """What was sent cannot be kept: a sentence for the person who sent it."""


def defaults() -> dict[str, int]:
    return {name: field[0] for name, field in FIELDS.items()}


def read(db: OrmSession) -> dict[str, int]:
    row = db.get(Setting, SETTINGS_ID)
    kept = (row.doc if row else None) or {}
    found = defaults()
    for name, (_default, low, high, _what) in FIELDS.items():
        value = kept.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high:
            found[name] = value
    return found


def write(db: OrmSession, sent: Any) -> list[str]:
    """Keep the thresholds that were sent (the caller commits). Returns the names that changed."""
    if not isinstance(sent, dict):
        raise ThresholdError("The thresholds are not readable")
    before = read(db)
    after = dict(before)
    for name, value in sent.items():
        if name not in FIELDS:
            raise ThresholdError(f"Not a threshold: {name}")
        _default, low, high, what = FIELDS[name]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ThresholdError(f"{what}: a whole number from {low} to {high}")
        after[name] = value
    for first, second in _RISING:
        if after[first] > after[second]:
            raise ThresholdError(f"{FIELDS[first][3]}: not more than the value from which it is a problem")
    for first, second in _FALLING:
        if after[first] < after[second]:
            raise ThresholdError(f"{FIELDS[first][3]}: not less than the value from which it is a problem")
    changed = [name for name in FIELDS if after[name] != before[name]]
    if changed:
        row = db.get(Setting, SETTINGS_ID)
        if row is None:
            db.add(Setting(id=SETTINGS_ID, doc=after))
        else:
            row.doc = after
            flag_modified(row, "doc")
    return changed


def out(db: OrmSession) -> list[dict[str, Any]]:
    """Every threshold with its value, its default and its range, in the order of the screen."""
    held = read(db)
    return [
        {"name": name, "value": held[name], "default": default, "min": low, "max": high, "label": what}
        for name, (default, low, high, what) in FIELDS.items()
    ]
