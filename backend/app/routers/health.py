"""The health page of the server (administrators), and the token of the metrics.

``GET /api/health`` (``main.py``) stays what a load balancer and the compose
health check ask: cheap, open, and saying nothing but that the process is
up. The details are here, for administrators.

Reading the page is open to an administrator's API key as to a signed-in
administrator: a monitoring script may want it. Changing the thresholds and
making or removing the scrape token need a signed-in administrator.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session as OrmSession

from ..core import audit
from ..core.db import get_db
from ..core.security import Principal, admin_principal, admin_session
from ..health import metrics, thresholds, watch

router = APIRouter(prefix="/health", tags=["health"])


def _page(db: OrmSession) -> dict[str, Any]:
    return {**watch.page(db), "metricsToken": metrics.token_out(db)}


@router.get("/details")
def read_health(_: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every row of the health page (``id``, ``group``, ``label``, ``value``, ``state``: ``fine``,
    ``attention``, ``problem`` or ``unknown``, ``since``, ``detail``, ``link``), how many rows are
    in each state, the thresholds, and whether a scrape token is set."""
    return _page(db)


@router.put("/thresholds")
def write_thresholds(
    body: dict[str, Any] = Body(...), caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)
) -> dict:
    """Change thresholds of the health page (only the names that are sent change)."""
    try:
        changed = thresholds.write(db, body)
    except thresholds.ThresholdError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    if changed:
        held = thresholds.read(db) | {name: body[name] for name in changed}
        audit.record(
            db,
            caller.actor,
            "health.thresholds",
            "Changed the thresholds of the health page: " + ", ".join(f"{name} to {held[name]}" for name in changed),
            target="health",
        )
    db.commit()
    return _page(db)


@router.post("/metrics-token", status_code=201)
def make_metrics_token(caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)) -> dict:
    """Make the token ``/api/metrics`` answers to. It is returned once, here, and never again; the
    one before it stops working."""
    replaced = metrics.token_out(db)["set"]
    token = metrics.new_token(db, caller.actor)
    audit.record(
        db,
        caller.actor,
        "metrics.token",
        "Replaced the scrape token of the metrics" if replaced else "Made a scrape token for the metrics",
        target="metrics",
    )
    db.commit()
    return {"token": token, "metricsToken": metrics.token_out(db)}


@router.delete("/metrics-token")
def remove_metrics_token(caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)) -> dict:
    """Remove the scrape token: ``/api/metrics`` then answers to nobody (unless ``METRICS_TOKEN`` is set)."""
    if metrics.remove_token(db):
        audit.record(db, caller.actor, "metrics.token", "Removed the scrape token of the metrics", target="metrics")
    db.commit()
    return {"metricsToken": metrics.token_out(db)}
