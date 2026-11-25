"""What the screens of processes read (7.0): a page of processes, the tree around one, the hosts that have some.

A host can hold two million processes, so nothing here loads a host: the list is paged by key (``paging.py``),
the tree is walked up one parent at a time and down one level at a time, with caps that the answer says, and the
counts of children and detections are asked of the database for the rows of a page only.

An item is a process with what it says of itself: ``parentId`` is the process that started it when the
evidence holds it, else ``parent`` has the image and command line the log named (a ghost parent: shown, not a
row). ``children`` counts the processes linked to it as their parent, ``detections`` the rules that matched
its record (the rules of one record and the process-chain rules together).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import EvidenceDetection, EvidenceProcess
from . import paging
from .browse import COUNT_CAP, _like

LIMIT_MAX = 500
UP_MAX, UP_DEFAULT = 64, 32
DOWN_MAX, DOWN_DEFAULT = 20, 6
NODES_MAX = 500  # descendants one tree gives
HOSTS_MAX = 1000
IN_MAX = 500


def name_of(image: str) -> str:
    """The file name of an image, whichever separator its system uses."""
    return image.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _counts(db: OrmSession, rows: list[EvidenceProcess]) -> tuple[dict[int, int], dict[int, int]]:
    """Children and detections of the rows given: ``({id: children}, {id: detections})``."""
    p, d = EvidenceProcess, EvidenceDetection
    children: dict[int, int] = {}
    detections: dict[int, int] = {}
    ids = [row.id for row in rows]
    records = [row.record_id for row in rows if row.record_id is not None]
    for start in range(0, len(ids), IN_MAX):
        found = db.execute(
            select(p.parent_id, func.count()).where(p.parent_id.in_(ids[start : start + IN_MAX])).group_by(p.parent_id)
        )
        children.update(found.all())
    by_record: dict[int, int] = {}
    for start in range(0, len(records), IN_MAX):
        found = db.execute(
            select(d.record_id, func.count())
            .where(d.record_id.in_(records[start : start + IN_MAX]))
            .group_by(d.record_id)
        )
        by_record.update(found.all())
    for row in rows:
        if row.record_id in by_record:
            detections[row.id] = by_record[row.record_id]
    return children, detections


def item_of(row: EvidenceProcess, children: int = 0, detections: int = 0) -> dict[str, Any]:
    """A process as the screens show it."""
    ghost = None
    if row.parent_id is None and (row.parent_image or row.parent_command_line):
        ghost = {"image": row.parent_image, "commandLine": row.parent_command_line}
    return {
        "id": row.id,
        "recordId": row.record_id,
        "sourceId": row.source_id,
        "host": row.host,
        "pid": row.pid,
        "ppid": row.ppid,
        "guid": row.guid,
        "image": row.image,
        "name": name_of(row.image),
        "commandLine": row.command_line,
        "user": row.username,
        "logonId": row.logon_id,
        "integrity": row.integrity,
        "hashes": row.hashes or {},
        "startTs": row.start_ts,
        "endTs": row.end_ts,
        "level": row.level,
        "parentId": row.parent_id,
        "parent": ghost,
        "children": children,
        "detections": detections,
    }


def _items(db: OrmSession, rows: list[EvidenceProcess]) -> list[dict[str, Any]]:
    children, detections = _counts(db, rows)
    return [item_of(row, children.get(row.id, 0), detections.get(row.id, 0)) for row in rows]


def _filters(incident_id: str, f: dict[str, Any]) -> list[Any]:
    p = EvidenceProcess
    where: list[Any] = [p.incident_id == incident_id]
    for name, column in (("host", p.host), ("user", p.username), ("sourceId", p.source_id)):
        if f.get(name) not in (None, ""):
            where.append(column == f[name])
    if f.get("parentId") is not None:
        where.append(p.parent_id == f["parentId"])
    if f.get("roots"):
        where.append(p.parent_id.is_(None))
    if f.get("level") is not None:
        where.append(p.level >= f["level"])
    if f.get("from") is not None:
        where.append(p.start_ts >= f["from"])
    if f.get("to") is not None:
        where.append(p.start_ts <= f["to"])
    if f.get("image"):
        # A name (``powershell.exe``) is any path that ends with it; a path is that image.
        wanted = str(f["image"]).lower()
        if "/" in wanted or "\\" in wanted:
            where.append(func.lower(p.image) == wanted)
        else:
            tail = _like(wanted)[1:-1]
            where.append(
                or_(
                    func.lower(p.image) == wanted,
                    func.lower(p.image).like("%\\\\" + tail, escape="\\"),
                    func.lower(p.image).like("%/" + tail, escape="\\"),
                )
            )
    if f.get("q"):
        like = _like(f["q"])
        where.append(or_(p.image.ilike(like, escape="\\"), p.command_line.ilike(like, escape="\\")))
    return where


def processes(
    db: OrmSession, incident_id: str, f: dict[str, Any], order: str, limit: int, cursor: str | None
) -> dict[str, Any]:
    """One page of processes: ``{"processes", "next", "count", "countCapped"}`` (the count on the first page)."""
    paging.check(order)
    p = EvidenceProcess
    where = _filters(incident_id, f)
    tag = paging.tag_of("p", order)
    query = select(p).where(*where)
    if cursor:
        query = query.where(paging.after(p.start_ts, p.id, order, *paging.decode(tag, cursor)))
    rows = list(db.scalars(query.order_by(*paging.sort(p.start_ts, p.id, order)).limit(limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]
    answer: dict[str, Any] = {
        "processes": _items(db, rows),
        "next": paging.encode(tag, rows[-1].start_ts, rows[-1].id) if more and rows else None,
        "count": None,
        "countCapped": False,
    }
    if not cursor:
        counted = select(p.id).where(*where).limit(COUNT_CAP).subquery()
        total = db.scalar(select(func.count()).select_from(counted)) or 0
        answer["count"], answer["countCapped"] = total, total >= COUNT_CAP
    return answer


def tree(db: OrmSession, incident_id: str, process_id: int, up: int, down: int) -> dict[str, Any] | None:
    """The ancestors of a process (root first, at most ``up``) and its descendants (at most ``down`` levels and
    ``NODES_MAX`` processes, in tree order, each with its ``depth`` below the process). ``cut`` says that either
    stopped the walk; ``ghost`` is the parent the log named for the top of the ancestors, when the evidence
    does not hold it."""
    p = EvidenceProcess
    root = db.get(p, process_id)
    if root is None or root.incident_id != incident_id:
        return None
    up, down = max(0, min(up, UP_MAX)), max(0, min(down, DOWN_MAX))
    above: list[EvidenceProcess] = []
    seen = {root.id}
    top, cut_up = root, False
    while top.parent_id is not None:
        if len(above) >= up:
            cut_up = True
            break
        parent = db.get(p, top.parent_id)
        if parent is None or parent.id in seen or parent.incident_id != incident_id:
            break
        seen.add(parent.id)
        above.append(parent)
        top = parent
    above.reverse()
    ghost = None
    if top.parent_id is None and (top.parent_image or top.parent_command_line):
        ghost = {"image": top.parent_image, "commandLine": top.parent_command_line}
    below: dict[int, list[EvidenceProcess]] = {}
    nodes = 0
    cut_down = False
    frontier = [root.id]
    for _level in range(down):
        if not frontier:
            break
        found: list[EvidenceProcess] = []
        for start in range(0, len(frontier), IN_MAX):
            found.extend(
                db.scalars(
                    select(p)
                    .where(p.incident_id == incident_id, p.parent_id.in_(frontier[start : start + IN_MAX]))
                    .order_by(p.start_ts.is_(None), p.start_ts, p.id)
                    .limit(NODES_MAX - nodes + 1)
                )
            )
        if nodes + len(found) > NODES_MAX:
            cut_down = True
            found = found[: NODES_MAX - nodes]
        kept: list[EvidenceProcess] = []
        for row in found:
            if row.id in seen:
                continue
            seen.add(row.id)
            below.setdefault(row.parent_id, []).append(row)
            kept.append(row)
        nodes += len(kept)
        frontier = [row.id for row in kept]
        if cut_down:
            break
    ordered: list[tuple[int, EvidenceProcess]] = []
    stack = [(1, row) for row in reversed(below.get(root.id, []))]
    while stack:
        depth, row = stack.pop()
        ordered.append((depth, row))
        stack.extend((depth + 1, kid) for kid in reversed(below.get(row.id, [])))
    items = {item["id"]: item for item in _items(db, [*above, root, *(row for _depth, row in ordered)])}
    # A process with children that were not walked (the last level, or the cap on nodes) says the tree is cut.
    if not cut_down:
        cut_down = any(items[row.id]["children"] and row.id not in below for _depth, row in ordered) or bool(
            items[root.id]["children"] and root.id not in below
        )
    return {
        "node": items[root.id],
        "ancestors": [items[row.id] for row in above],
        "ghost": ghost,
        "descendants": [{**items[row.id], "depth": depth} for depth, row in ordered],
        "cut": bool(cut_up or cut_down),
        "caps": {"up": up, "down": down, "nodes": NODES_MAX},
    }


def hosts(db: OrmSession, incident_id: str) -> dict[str, Any]:
    """The hosts with processes: how many, when the first and the last started, how many have no known parent
    and how many a chain rule matched. The busiest first; at most ``HOSTS_MAX`` (``cut`` says there are more)."""
    p = EvidenceProcess
    count = func.count()
    found = db.execute(
        select(
            p.host,
            count,
            func.min(p.start_ts),
            func.max(p.start_ts),
            func.sum(case((p.parent_id.is_(None), 1), else_=0)),
            func.count(p.level),
            func.max(p.level),
        )
        .where(p.incident_id == incident_id)
        .group_by(p.host)
        .order_by(count.desc(), p.host)
        .limit(HOSTS_MAX + 1)
    ).all()
    return {
        "hosts": [
            {
                "host": host,
                "processes": n,
                "firstTs": first,
                "lastTs": last,
                "roots": int(roots or 0),
                "detections": int(flagged or 0),
                "level": level,
            }
            for host, n, first, last, roots, flagged, level in found[:HOSTS_MAX]
        ],
        "cut": len(found) > HOSTS_MAX,
    }
