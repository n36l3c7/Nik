"""Network captures: analysis by the packet capture worker, incident references,
and the isolated browser sessions' network logs.

- An uploaded pcap / pcapng is stored, then analysed in the background
  (``run_analysis``): the worker reads it with tshark and sharkd and returns
  the summary (hosts, DNS, HTTP, TLS server names, POSTs, beacons, Expert
  Info, exported objects with their SHA-256).
- An isolated browser session opened from an incident is a capture too: its
  network log is copied from the browser worker after each action
  (``sync``), and when the session ends it is rebuilt as pcapng
  (``pcapng.py``) and analysed like an upload (``finalize``).

The incident keeps a light reference per capture under
``data.network.captures`` (``reference``).
"""

from __future__ import annotations

import hashlib
import logging
import threading
from typing import Any
from urllib.parse import quote

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import previews, vault
from ..config import settings
from ..db import SessionLocal
from ..models import Incident, NetworkCapture
from ..security import now_iso
from . import pcapng, store

logger = logging.getLogger("nik.network")
ANALYSE_TIMEOUT = 3600
RPC_TIMEOUT = 330
HELD_KEPT = 20
_jobs = threading.BoundedSemaphore(2)
_sync_locks: dict[str, threading.Lock] = {}
_sync_guard = threading.Lock()


def configured() -> bool:
    return bool(settings.PCAP_URL)


def _worker(path: str, body: dict[str, Any], timeout: int) -> Any:
    return previews._call(settings.PCAP_URL, "X-Pcap-Token", settings.PCAP_TOKEN, "POST", path, body, timeout)


def _target(row: NetworkCapture) -> dict[str, Any]:
    """What the worker needs to open the capture: its id, path and TLS key log."""
    path = store.find_capture(row.id)
    if path is None:
        raise previews.WorkerError("The capture file is not in the store", 404)
    body: dict[str, Any] = {"id": row.id, "path": store.relative_path(row.id, path.name.split(".", 1)[1])}
    if row.keylog:
        keylog = vault.decrypt(row.keylog)
        if keylog:
            body["keylog"] = keylog
    return body


def rpc(row: NetworkCapture, method: str, params: dict[str, Any]) -> Any:
    return _worker("/rpc", {**_target(row), "method": method, "params": params}, RPC_TIMEOUT)


def close_worker_session(row: NetworkCapture) -> None:
    if configured():
        try:
            _worker("/close", {"id": row.id}, 30)
        except previews.WorkerError:
            logger.info("The packet capture worker could not close capture %s", row.id)


# --------------------------------------------------------------------------- #
# Incident references                                                         #
# --------------------------------------------------------------------------- #
def reference(row: NetworkCapture) -> dict[str, Any]:
    summary = row.summary or {}
    meta = row.meta or {}
    return {
        "id": row.id,
        "kind": row.kind,
        "fileName": row.file_name,
        "size": row.size,
        "sha256": row.sha256,
        "status": row.status,
        "error": row.error,
        "packets": row.packets,
        "first": row.first_ms,
        "last": row.last_ms,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "keylog": bool(row.keylog),
        "label": meta.get("label"),
        "network": meta.get("network"),
        "held": meta.get("held") or [],
        "posts": len(summary.get("posts") or []),
        "beacons": [
            {k: b.get(k) for k in ("destination", "port", "count", "interval", "first")}
            for b in (summary.get("beacons") or [])[:10]
        ],
        "objects": len(summary.get("objects") or []),
    }


def _refs(doc: dict[str, Any]) -> list[dict[str, Any]]:
    network = doc.setdefault("data", {}).setdefault("network", {})
    if not isinstance(network, dict):
        network = doc["data"]["network"] = {}
    refs = network.get("captures")
    if not isinstance(refs, list):
        refs = network["captures"] = []
    return refs


def save_reference(db: OrmSession, row: NetworkCapture, remove: bool = False) -> None:
    """Add, refresh or remove the capture's reference in its incident, then reindex the indicators."""
    from ..iocs import reindex_incident
    from ..routers.incidents import _sync_columns

    incident = db.get(Incident, row.incident_id)
    if incident is None:
        return
    doc = dict(incident.doc or {})
    refs = [r for r in _refs(doc) if r.get("id") != row.id]
    if not remove:
        current = next((r for r in _refs(doc) if r.get("id") == row.id), None)
        position = _refs(doc).index(current) if current else len(refs)
        refs.insert(position, reference(row))
    doc["data"]["network"]["captures"] = refs
    doc["updatedAt"] = now_iso()
    incident.doc = doc
    flag_modified(incident, "doc")
    _sync_columns(incident)
    db.flush()
    reindex_incident(db, incident)


# --------------------------------------------------------------------------- #
# Analysis                                                                    #
# --------------------------------------------------------------------------- #
def _apply_summary(row: NetworkCapture, result: dict[str, Any]) -> None:
    row.summary = result
    row.packets = int(result.get("packets") or 0)
    row.first_ms = int(result["first"] * 1000) if result.get("first") else None
    row.last_ms = int(result["last"] * 1000) if result.get("last") else None
    row.status, row.error = "ready", None
    flag_modified(row, "summary")


def run_analysis(capture_id: str) -> None:
    """Background task: analyse a stored capture and refresh its incident."""
    with _jobs, SessionLocal() as db:
        row = db.get(NetworkCapture, capture_id)
        if row is None:
            return
        try:
            target = _target(row)
            close_worker_session(row)  # a new key log or file: reopen it
            _apply_summary(row, _worker("/analyze", target, ANALYSE_TIMEOUT))
        except previews.WorkerError as exc:
            row.status, row.error = "error", str(exc)[:500]
        save_reference(db, row)
        db.commit()


def queue_analysis(db: OrmSession, row: NetworkCapture, background_tasks) -> None:
    """Analyse now in the background, or keep the capture stored when no worker is configured."""
    row.status = "indexing" if configured() else "stored"
    row.error = None if configured() else "The packet capture worker is not configured (PCAP_URL)."
    save_reference(db, row)
    db.commit()
    if configured():
        background_tasks.add_task(run_analysis, row.id)


# --------------------------------------------------------------------------- #
# Isolated browser sessions                                                   #
# --------------------------------------------------------------------------- #
def _lock(capture_id: str) -> threading.Lock:
    with _sync_guard:
        return _sync_locks.setdefault(capture_id, threading.Lock())


def sync(db: OrmSession, row: NetworkCapture) -> dict[str, Any]:
    """Copy what changed in the session's network log from the browser worker.

    Returns ``{"closed": bool, "gone": bool}``: the session ended in the worker,
    or the worker no longer has it at all.
    """
    if row.kind != "browser" or row.status != "live" or not previews.browser_configured():
        return {"closed": row.status != "live", "gone": False}
    with _lock(row.id):
        db.refresh(row)
        meta = dict(row.meta or {})
        query = f"owner={quote(meta.get('owner') or '')}&since={int(meta.get('cursor') or 0)}&bodies=1"
        try:
            result = previews._browser("GET", f"/sessions/{row.id}/network?{query}")
        except previews.WorkerError as exc:
            if exc.status == 404:
                return {"closed": True, "gone": True}
            raise
        entries = result.get("entries") or []
        store.append_log(row.id, entries)
        held = {h["id"]: h for h in meta.get("held") or []}
        for entry in entries:
            if entry.get("state") == "held" and len(held) < HELD_KEPT:
                held[entry["id"]] = {
                    "id": entry["id"],
                    "method": entry.get("method"),
                    "url": (entry.get("url") or "")[:500],
                    "time": entry.get("startedAt"),
                }
        meta.update(cursor=int(result.get("cursor") or 0), counts=result.get("counts") or {})
        meta["held"] = sorted(held.values(), key=lambda h: h.get("time") or 0)
        row.meta = meta
        flag_modified(row, "meta")
        db.commit()
        return {"closed": bool(result.get("closed")), "gone": False}


def finalize(db: OrmSession, row: NetworkCapture, background_tasks) -> None:
    """The session ended: rebuild its log as pcapng and analyse it."""
    if row.kind != "browser" or row.status != "live":
        return
    data = pcapng.build(store.read_log(row.id))
    store.write_capture(row.id, "pcapng", [data])
    row.size, row.sha256 = len(data), hashlib.sha256(data).hexdigest()
    row.meta = {**(row.meta or {}), "closedAt": now_iso()}
    flag_modified(row, "meta")
    queue_analysis(db, row, background_tasks)


def refresh_live(db: OrmSession, row: NetworkCapture, background_tasks) -> None:
    """A live session the worker closed (idle, lifetime) is finalized when next seen."""
    if row.kind == "browser" and row.status == "live":
        try:
            state = sync(db, row)
        except previews.WorkerError:
            return
        if state["closed"]:
            finalize(db, row, background_tasks)


def remove_capture(db: OrmSession, row: NetworkCapture, update_incident: bool = True) -> None:
    close_worker_session(row)
    if row.kind == "browser" and row.status == "live" and previews.browser_configured():
        try:
            previews._browser("DELETE", f"/sessions/{row.id}?owner={quote((row.meta or {}).get('owner') or '')}")
        except previews.WorkerError:
            logger.info("Browser session %s was already closed", row.id)
    if update_incident:
        save_reference(db, row, remove=True)
    store.remove(row.id)
    db.delete(row)
