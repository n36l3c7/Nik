"""The processes and the logons of the host evidence of an incident (7.0), and the graph of lateral movement.

The parsers of the forensics worker give, with the records of a file, the processes that started and the logons
that were made (``evidence/processes.py``); the processes are linked into trees, and the process-chain rules
run over them (``evidence/chains.py``). Here the screens page through them (``evidence/trees.py``,
``evidence/lateral.py``). Everything is read-only and by incident; an archived incident holds none, and answers
with empty lists.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as OrmSession

from ..core.db import get_db
from ..core.models import Incident
from ..core.security import Principal, reader_principal
from ..evidence import browse, lateral, trees

router = APIRouter(prefix="/incidents/{incident_id}/evidence", tags=["incidents/evidence"])


def _incident(db: OrmSession, incident_id: str) -> Incident:
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _listed(values: list[str] | None, name: str) -> list[str]:
    """A filter given once as ``a,b`` or several times: the list of its values."""
    found = [part.strip() for value in values or [] for part in value.split(",") if part.strip()]
    if len(found) > 20:
        raise HTTPException(status_code=400, detail=f"{name} is 20 values at most")
    return found


def _numbers(values: list[str] | None, name: str) -> list[int]:
    found = _listed(values, name)
    if not all(item.isdigit() and len(item) <= 3 for item in found):
        raise HTTPException(status_code=400, detail=f"{name} is whole numbers")
    return [int(item) for item in found]


# --------------------------------------------------------------------------- #
# Processes                                                                   #
# --------------------------------------------------------------------------- #
@router.get("/processes")
def list_processes(
    incident_id: str,
    host: str = Query(default="", max_length=255),
    q: str = Query(default="", max_length=200),
    user: str = Query(default="", max_length=255),
    image: str = Query(default="", max_length=1000),
    level: int | None = Query(default=None, ge=1, le=5),
    parentId: int | None = Query(default=None),  # noqa: N803
    roots: bool = False,
    sourceId: str = Query(default="", max_length=32),  # noqa: N803
    from_: int | None = Query(default=None, alias="from"),
    to: int | None = None,
    order: str = Query(default="time", max_length=10),
    limit: int = Query(default=100, ge=1, le=trees.LIMIT_MAX),
    cursor: str = Query(default="", max_length=200),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """One page of the processes the evidence of the incident shows started, in time order (``order`` is ``time``
    or ``-time``; one with no start time comes last). Each item says its ``id``, ``recordId`` (the record of its
    creation), ``host``, ``pid``, ``ppid``, ``image`` and ``name`` (its file name), ``commandLine``, ``user``,
    ``integrity``, ``startTs`` and ``endTs`` (ms, when the log says), ``level`` (1 to 5, the highest process-chain
    rule that matched it), ``parentId`` (the process that started it when the evidence holds it), ``parent`` (the
    image and command line the log named, when the parent is not in the evidence), ``children`` (how many
    processes it started) and ``detections`` (how many rules matched its record). Filters: ``host``, ``q``
    (a part of the image or the command line), ``user``, ``image`` (a file name, or a whole path), ``level``
    (at least), ``parentId``, ``roots`` (only the processes whose parent is not in the evidence),
    ``sourceId``, ``from`` and ``to`` (the start time). ``next`` is the cursor of the following page, null at the
    end; ``count`` is made on the first page (up to 100001)."""
    _incident(db, incident_id)
    f = {
        "host": host,
        "q": q,
        "user": user,
        "image": image,
        "level": level,
        "parentId": parentId,
        "roots": roots,
        "sourceId": sourceId,
        "from": from_,
        "to": to,
    }
    try:
        return trees.processes(db, incident_id, f, order, limit, cursor or None)
    except browse.BadQuery as error:
        raise HTTPException(status_code=400, detail=str(error)) from None


@router.get("/processes/hosts")
def list_process_hosts(
    incident_id: str,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """The hosts the incident holds processes of, the busiest first: ``host``, ``processes``, ``firstTs`` and
    ``lastTs`` (when the first and the last started), ``roots`` (processes whose parent is not in the evidence),
    ``detections`` (processes a chain rule matched) and ``level`` (the highest of them). At most 1000 hosts
    (``cut`` says there are more)."""
    _incident(db, incident_id)
    return trees.hosts(db, incident_id)


@router.get("/processes/{process_id}/tree")
def get_process_tree(
    incident_id: str,
    process_id: int,
    up: int = Query(default=trees.UP_DEFAULT, ge=0, le=trees.UP_MAX),
    down: int = Query(default=trees.DOWN_DEFAULT, ge=0, le=trees.DOWN_MAX),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """The tree around one process (``process_id`` is the ``id`` of an item of the list): ``node`` (the process),
    ``ancestors`` (from the root down to its parent; ``up`` of them at most), ``ghost`` (the parent the log named
    for the top of them, when the evidence does not hold it) and ``descendants`` (in tree order, each with its
    ``depth`` below the process, ``down`` levels and 500 processes at most). ``cut`` is true when the walk
    stopped before the end of either side; ``caps`` says the limits."""
    _incident(db, incident_id)
    answer = trees.tree(db, incident_id, process_id, up, down)
    if answer is None:
        raise HTTPException(status_code=404, detail="Process not found")
    return answer


# --------------------------------------------------------------------------- #
# Logons                                                                      #
# --------------------------------------------------------------------------- #
@router.get("/logons")
def list_logons(
    incident_id: str,
    host: str = Query(default="", max_length=255),
    user: str = Query(default="", max_length=255),
    sourceIp: str = Query(default="", max_length=64),  # noqa: N803
    sourceHost: str = Query(default="", max_length=255),  # noqa: N803
    sourceId: str = Query(default="", max_length=32),  # noqa: N803
    logonType: list[str] | None = Query(default=None),  # noqa: N803
    outcome: list[str] | None = Query(default=None),
    q: str = Query(default="", max_length=200),
    from_: int | None = Query(default=None, alias="from"),
    to: int | None = None,
    order: str = Query(default="time", max_length=10),
    limit: int = Query(default=100, ge=1, le=lateral.LIMIT_MAX),
    cursor: str = Query(default="", max_length=200),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """One page of the logons and attempts the evidence shows, in time order (``order`` is ``time`` or ``-time``).
    Each item says its ``id``, ``recordId``, ``ts``, ``host`` (the machine that recorded it), ``sourceHost`` and
    ``sourceIp`` (where it came from), ``user``, ``domain``, ``logonType`` (the Windows number, or null),
    ``logonId``, ``outcome`` (``success``, ``failure``, ``logoff``, ``explicit`` or ``privileged``), ``method`` and
    ``status`` (what a failure said). Filters: ``host``, ``user``, ``sourceIp``, ``sourceHost``, ``sourceId``,
    ``logonType`` and ``outcome`` (each once as ``a,b`` or several times), ``q`` (a part of the user, the host,
    the source or the domain), ``from`` and ``to``. ``next`` is the cursor of the following page; ``count`` is made
    on the first page (up to 100001)."""
    _incident(db, incident_id)
    outcomes = _listed(outcome, "outcome")
    if any(item not in lateral.OUTCOMES for item in outcomes):
        raise HTTPException(status_code=400, detail="outcome is one of " + ", ".join(lateral.OUTCOMES))
    f: dict[str, Any] = {
        "host": host,
        "user": user,
        "sourceIp": sourceIp,
        "sourceHost": sourceHost,
        "sourceId": sourceId,
        "logonType": _numbers(logonType, "logonType"),
        "outcome": outcomes,
        "q": q,
        "from": from_,
        "to": to,
    }
    try:
        return lateral.logons(db, incident_id, f, order, limit, cursor or None)
    except browse.BadQuery as error:
        raise HTTPException(status_code=400, detail=str(error)) from None


@router.get("/logons/graph")
def get_logon_graph(
    incident_id: str,
    from_: int | None = Query(default=None, alias="from"),
    to: int | None = None,
    logonType: list[str] | None = Query(default=None),  # noqa: N803
    outcome: list[str] | None = Query(default=None),
    user: str = Query(default="", max_length=255),
    minCount: int = Query(default=0, ge=0, le=1_000_000),  # noqa: N803
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """The lateral movement the logons show, made by the database: ``nodes`` (``id``, ``kind`` ``host`` or
    ``address``, ``label``, ``logonsIn``, ``logonsOut``, ``failed``, ``inEvidence``: the incident holds a file, a
    process or a logon of that host) and ``edges`` (``from``, ``to``, ``count``, ``failed``, ``users`` (the five
    that came most), ``types`` (the logon types), ``firstTs``, ``lastTs``). An edge goes from where a logon came
    (its source host, else its source address) to the host that recorded it; a local logon makes none. Node ids
    are ``host:<name>`` or ``address:<address>`` in lower case, the same in every call. At most 300 nodes and 1500
    edges, the busiest kept; ``cut`` is true when others were left out. Filters: ``from``, ``to``, ``logonType``,
    ``outcome`` (only ``success``, ``failure`` and ``explicit`` make edges: another asked alone gives none),
    ``user``, ``minCount`` (the fewest logons of an edge)."""
    _incident(db, incident_id)
    outcomes = _listed(outcome, "outcome")
    if any(item not in lateral.OUTCOMES for item in outcomes):
        raise HTTPException(status_code=400, detail="outcome is one of " + ", ".join(lateral.OUTCOMES))
    f: dict[str, Any] = {
        "from": from_,
        "to": to,
        "logonType": _numbers(logonType, "logonType"),
        "outcome": outcomes,
        "user": user,
        "minCount": minCount,
    }
    return lateral.graph(db, incident_id, f)
