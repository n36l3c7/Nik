"""The numbers of the health page for Prometheus, and the token a scraper presents.

``GET /api/metrics`` answers in the text exposition format. What the health
page measures is written here by hand from its rows (``checks.METRICS``
names every metric and its help); the requests the API served are counted by
``core/observability.py`` with the client library that was already there.

**Names.** Everything starts with ``nik_``, is in base units (bytes,
seconds), and a counter ends in ``_total``. **Labels** only take values from
a small fixed set: the name of a disk, of a queue, of a worker, of a check, a
state, the version. Never an account, an incident, a host or anything a
person typed.

**The token.** The route answers to ``Authorization: Bearer <token>`` and to
nothing else: not to a session cookie, so no page a browser opens can read
it, and not to an API key, which stands for a role. The token is made on the
health page, shown once and kept as its SHA-256 (it is 256 random bits: a
slow hash would protect nothing more). Making a new one replaces the old;
removing it closes the route. ``METRICS_TOKEN`` in the environment, the way
of earlier versions, is still accepted beside it.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core.config import settings
from ..core.models import Setting
from . import checks, thresholds, watch

SETTINGS_ID = 46
PREFIX = "nikm_"


def _held(db: OrmSession) -> dict[str, Any]:
    row = db.get(Setting, SETTINGS_ID)
    return dict((row.doc if row else None) or {})


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token(db: OrmSession, actor: str, now: float | None = None) -> str:
    """Make the scrape token (the caller commits). The one before stops working. Returns it: once."""
    token = PREFIX + secrets.token_urlsafe(32)
    doc = {
        "hash": _digest(token),
        "createdAt": time.time() if now is None else now,
        "createdBy": actor,
        "ending": token[-4:],
    }
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
    else:
        row.doc = doc
        flag_modified(row, "doc")
    return token


def remove_token(db: OrmSession) -> bool:
    row = db.get(Setting, SETTINGS_ID)
    if row is None or not (row.doc or {}).get("hash"):
        return False
    row.doc = {}
    flag_modified(row, "doc")
    return True


def token_out(db: OrmSession) -> dict[str, Any]:
    """Whether a token is set, and what can be said of it without showing it."""
    doc = _held(db)
    made = doc.get("createdAt")
    return {
        "set": bool(doc.get("hash")),
        "createdAt": datetime.fromtimestamp(float(made), timezone.utc).isoformat() if made else None,
        "createdBy": doc.get("createdBy") or "",
        "ending": doc.get("ending") or "",
        "environment": bool(settings.METRICS_TOKEN),
    }


def allowed(db: OrmSession, authorization: str) -> bool:
    """Whether the header of a request carries the scrape token."""
    scheme, _, sent = authorization.partition(" ")
    sent = sent.strip()
    if scheme.lower() != "bearer" or not sent:
        return False
    kept = str(_held(db).get("hash") or "")
    if kept and hmac.compare_digest(_digest(sent), kept):
        return True
    from_env = settings.METRICS_TOKEN
    return bool(from_env) and hmac.compare_digest(sent.encode("utf-8"), from_env.encode("utf-8"))


# --------------------------------------------------------------------------- #
# The text                                                                    #
# --------------------------------------------------------------------------- #
def _label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _number(value: float) -> str:
    value = float(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    return str(int(value)) if value == int(value) and abs(value) < 1e15 else repr(value)


def render(rows: list[dict[str, Any]]) -> str:
    """The metrics of the rows, in the text exposition format: for each name its HELP, its TYPE
    and its samples, the names in the order ``checks.METRICS`` gives them."""
    samples: dict[str, list[tuple[dict[str, str], float]]] = {}
    for row in rows:
        for name, labels, value in row["metrics"]:
            samples.setdefault(name, []).append((labels, value))
    lines: list[str] = []
    for name, (kind, text) in checks.METRICS.items():
        if name not in samples:
            continue
        lines.append(f"# HELP {name} {text}")
        lines.append(f"# TYPE {name} {kind}")
        seen = set()
        for labels, value in samples[name]:
            pairs = ",".join(f'{key}="{_label(labels[key])}"' for key in sorted(labels))
            if pairs in seen:
                continue
            seen.add(pairs)
            lines.append(f"{name}{{{pairs}}} {_number(value)}" if pairs else f"{name} {_number(value)}")
    return "\n".join(lines) + "\n"


def exposition(db: OrmSession, now: float | None = None) -> bytes:
    """Everything ``/api/metrics`` answers."""
    from ..core.observability import request_metrics

    kept = watch._held(db)
    rows = checks.gather(db, thresholds.read(db), kept, now)
    return render(rows).encode("utf-8") + request_metrics()
