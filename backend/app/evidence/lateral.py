"""The logons of host evidence and the graph of lateral movement they make (7.0).

A row of ``evidence_logons`` is a logon, or an attempt, that a log recorded on ``host``: who (``username``), how
(``logon_type``, ``method``), from where (``source_host``, else ``source_ip``) and with what outcome. The list
is paged by key (``paging.py``), like the records.

**The graph** is made by the database, by aggregation: the logons are never loaded. An edge goes from where a
logon came (the source host, else the source address) to the host that recorded it, and counts the logons of
the outcomes ``success``, ``failure`` and ``explicit`` (a logoff and a privilege assignment come from nowhere).
A logon with no source, from the machine itself (``-``, ``::1``, ``127.0.0.1``, ``0.0.0.0``) or from the host
it is of, is local and makes no edge. The busiest edges are kept, at most ``EDGES_MAX``, on at most
``NODES_MAX`` nodes, and ``cut`` says when others were left out. A node id is ``host:<name>`` or
``address:<address>`` in lower case, the same in every call, so a screen can keep what it drew. The name of a
host is its short name, the part before the first dot, unless it is an address: ``WKS-1.corp.example`` and
``wks-1`` are one node, labelled with the longest spelling the logons have. An address and a name are never
merged: nothing in the logs proves they are the same machine. The counts of a
node are those of the edges that are shown. ``inEvidence`` is true for a host the incident holds a file, a
process or a logon of.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import and_, case, func, literal_column, or_, select
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.sql.expression import FunctionElement

from ..core.models import EvidenceLogon, EvidenceProcess, EvidenceSource
from . import paging
from .browse import COUNT_CAP, _like

LIMIT_MAX = 500
NODES_MAX = 300
EDGES_MAX = 1500
EDGES_SCANNED = 20_000  # the busiest edges the choice of the shown ones is made among
USERS_SHOWN = 5
OUTCOMES = ("success", "failure", "logoff", "explicit", "privileged")
EDGE_OUTCOMES = ("success", "failure", "explicit")
LOCAL = ("-", "::1", "127.0.0.1", "0.0.0.0", "::", "localhost")  # noqa: S104 - addresses a logon names, not binds
IN_MAX = 300


class _head(FunctionElement):  # noqa: N801 - a SQL function: the text before the first dot
    inherit_cache = True
    name = "head"


@compiles(_head)
def _head_default(element: Any, compiler: Any, **kw: Any) -> str:
    return f"split_part({compiler.process(element.clauses, **kw)}, '.', 1)"


@compiles(_head, "sqlite")
def _head_sqlite(element: Any, compiler: Any, **kw: Any) -> str:
    text = compiler.process(element.clauses, **kw)
    return f"(CASE WHEN instr({text}, '.') > 0 THEN substr({text}, 1, instr({text}, '.') - 1) ELSE {text} END)"


def short_id(name: str | None) -> str:
    """The id of a host: its name in lower case up to the first dot; an address stays whole."""
    text = (name or "").strip().lower()
    if ":" in text or re.fullmatch(r"[0-9.]*\.[0-9.]*", text):
        return text
    return text.split(".", 1)[0]


def _host_id(column: Any) -> Any:
    """``short_id`` of a column, in SQL: the same rule (an address has a colon, or only digits and dots)."""
    text = func.lower(func.trim(column))
    bare = text
    for digit in "0123456789":
        bare = func.replace(bare, literal_column(f"'{digit}'"), literal_column("''"))
    dots = func.replace(bare, literal_column("'.'"), literal_column("''"))
    dotted = text.contains(literal_column("'.'"), autoescape=False)
    address = or_(text.contains(literal_column("':'"), autoescape=False), and_(dotted, dots == literal_column("''")))
    return case((address, text), else_=_head(text))


def item_of(row: EvidenceLogon) -> dict[str, Any]:
    return {
        "id": row.id,
        "recordId": row.record_id,
        "sourceId": row.source_id,
        "ts": row.ts,
        "host": row.host,
        "sourceHost": row.source_host,
        "sourceIp": row.source_ip,
        "user": row.username,
        "domain": row.domain,
        "logonType": row.logon_type,
        "logonId": row.logon_id,
        "outcome": row.outcome,
        "method": row.method,
        "status": row.status,
        "targetHost": row.target_host,
    }


def _filters(incident_id: str, f: dict[str, Any]) -> list[Any]:
    g = EvidenceLogon
    where: list[Any] = [g.incident_id == incident_id]
    for name, column in (
        ("user", g.username),
        ("sourceIp", g.source_ip),
        ("sourceId", g.source_id),
    ):
        if f.get(name) not in (None, ""):
            where.append(column == f[name])
    # A host is asked by its short name, in any case: the graph's nodes name a machine that way.
    for name, column in (("host", g.host), ("sourceHost", g.source_host)):
        if f.get(name) not in (None, ""):
            where.append(_host_id(column) == short_id(f[name]))
    if f.get("logonType"):
        where.append(g.logon_type.in_(f["logonType"]))
    if f.get("outcome"):
        where.append(g.outcome.in_(f["outcome"]))
    if f.get("from") is not None:
        where.append(g.ts >= f["from"])
    if f.get("to") is not None:
        where.append(g.ts <= f["to"])
    if f.get("q"):
        like = _like(f["q"])
        where.append(
            or_(
                *(
                    column.ilike(like, escape="\\")
                    for column in (g.username, g.host, g.source_host, g.source_ip, g.domain)
                )
            )
        )
    return where


def logons(
    db: OrmSession, incident_id: str, f: dict[str, Any], order: str, limit: int, cursor: str | None
) -> dict[str, Any]:
    """One page of logons: ``{"logons", "next", "count", "countCapped"}`` (the count on the first page)."""
    paging.check(order)
    g = EvidenceLogon
    where = _filters(incident_id, f)
    tag = paging.tag_of("l", order)
    query = select(g).where(*where)
    if cursor:
        query = query.where(paging.after(g.ts, g.id, order, *paging.decode(tag, cursor)))
    rows = list(db.scalars(query.order_by(*paging.sort(g.ts, g.id, order)).limit(limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]
    answer: dict[str, Any] = {
        "logons": [item_of(row) for row in rows],
        "next": paging.encode(tag, rows[-1].ts, rows[-1].id) if more and rows else None,
        "count": None,
        "countCapped": False,
    }
    if not cursor:
        counted = select(g.id).where(*where).limit(COUNT_CAP).subquery()
        total = db.scalar(select(func.count()).select_from(counted)) or 0
        answer["count"], answer["countCapped"] = total, total >= COUNT_CAP
    return answer


# --------------------------------------------------------------------------- #
# The graph                                                                   #
# --------------------------------------------------------------------------- #
def _origin() -> tuple[Any, Any, Any]:
    """The columns that say where a logon came from: its kind (``host`` or ``address``), its name in lower
    case, and its name as the log spelled it."""
    g = EvidenceLogon
    # The literals are written into the SQL, not bound: an expression that is selected and grouped by must read
    # the same in both places (PostgreSQL refuses two bound values for it).
    named = func.trim(g.source_host) != literal_column("''")
    own = _explicit_target()
    kind = case((own, literal_column("'host'")), (named, literal_column("'host'")), else_=literal_column("'address'"))
    name = case(
        (own, _host_id(g.host)),
        (named, _host_id(g.source_host)),
        else_=func.lower(func.trim(g.source_ip)),
    )
    label = case((own, g.host), (named, func.trim(g.source_host)), else_=func.trim(g.source_ip))
    return kind, name, label


def _explicit_target() -> Any:
    """True for an explicit-credentials logon (4648) that names the server it went to: its edge goes from the
    host that logged it TO that server."""
    g = EvidenceLogon
    return and_(g.outcome == literal_column("'explicit'"), func.trim(g.target_host) != literal_column("''"))


def _reached() -> tuple[Any, Any]:
    """The host a logon reached (lower case, and as spelled): the host of the log, or the target of an explicit one."""
    g = EvidenceLogon
    own = _explicit_target()
    return (
        case((own, _host_id(g.target_host)), else_=_host_id(g.host)),
        case((own, func.trim(g.target_host)), else_=g.host),
    )


def _edge_filters(incident_id: str, f: dict[str, Any]) -> list[Any]:
    g = EvidenceLogon
    _kind, name, _label = _origin()
    reached, _spelled = _reached()
    address = func.lower(func.trim(g.source_ip))
    where = [
        g.incident_id == incident_id,
        g.outcome.in_(EDGE_OUTCOMES),
        # Somewhere to come from: a source host, or an address that is not the machine's own (or an explicit logon
        # that names the server it went to); and not the host itself.
        or_(func.trim(g.source_host) != "", and_(address != "", address.not_in(LOCAL)), _explicit_target()),
        name != reached,
    ]
    if f.get("user"):
        where.append(g.username == f["user"])
    if f.get("logonType"):
        where.append(g.logon_type.in_(f["logonType"]))
    if f.get("outcome"):
        where.append(g.outcome.in_([item for item in f["outcome"] if item in EDGE_OUTCOMES] or ["-"]))
    if f.get("from") is not None:
        where.append(g.ts >= f["from"])
    if f.get("to") is not None:
        where.append(g.ts <= f["to"])
    return where


def graph(db: OrmSession, incident_id: str, f: dict[str, Any]) -> dict[str, Any]:
    """``{"nodes", "edges", "cut", "caps"}``: see the module's text. ``f`` keeps ``from``, ``to``, ``logonType``
    (a list), ``outcome`` (a list), ``user`` and ``minCount`` (the fewest logons an edge has)."""
    g = EvidenceLogon
    kind, name, label = _origin()
    where = _edge_filters(incident_id, f)
    target, spelled = _reached()
    failed = func.sum(case((g.outcome == "failure", 1), else_=0))
    count = func.count()
    having = [count >= int(f["minCount"])] if f.get("minCount") else []
    grouped = (
        select(kind.label("kind"), name.label("name"), target.label("target"))
        .where(*where)
        .group_by(kind, name, target)
        .having(*having)
        .subquery()
    )
    total = db.scalar(select(func.count()).select_from(grouped)) or 0
    found = db.execute(
        select(
            kind,
            name,
            target,
            count,
            failed,
            func.min(g.ts),
            func.max(g.ts),
            func.min(label),
            func.min(spelled),
        )
        .where(*where)
        .group_by(kind, name, target)
        .having(*having)
        .order_by(count.desc(), failed.desc(), name, target)
        .limit(EDGES_SCANNED)
    ).all()
    # The busiest edges whose nodes fit.
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for origin_kind, origin, to, n, bad, first, last, origin_label, to_label in found:
        if len(edges) >= EDGES_MAX:
            break
        from_id = f"{origin_kind}:{origin}"
        to_id = f"host:{to}"
        room = (from_id not in nodes) + (to_id not in nodes)
        if len(nodes) + room > NODES_MAX:
            continue
        for node_id, node_kind, text in ((from_id, origin_kind, origin_label), (to_id, "host", to_label)):
            nodes.setdefault(
                node_id,
                {
                    "id": node_id,
                    "kind": node_kind,
                    "label": text,
                    "logonsIn": 0,
                    "logonsOut": 0,
                    "failed": 0,
                    "inEvidence": False,
                },
            )
        bad = int(bad or 0)
        nodes[from_id]["logonsOut"] += n
        nodes[from_id]["failed"] += bad
        nodes[to_id]["logonsIn"] += n
        nodes[to_id]["failed"] += bad
        edges.append(
            {
                "from": from_id,
                "to": to_id,
                "count": n,
                "failed": bad,
                "users": [],
                "types": [],
                "firstTs": first,
                "lastTs": last,
            }
        )
    if edges:
        _describe(db, where, kind, name, target, edges, nodes)
        _labels(db, incident_id, nodes)
        _evidence(db, incident_id, nodes)
    return {
        "nodes": sorted(nodes.values(), key=lambda node: (-(node["logonsIn"] + node["logonsOut"]), node["id"])),
        "edges": edges,
        "cut": total > len(edges),
        "caps": {"nodes": NODES_MAX, "edges": EDGES_MAX},
    }


def _describe(
    db: OrmSession, where: list[Any], kind: Any, name: Any, target: Any, edges: list[dict[str, Any]], nodes: dict
) -> None:
    """The users that came most and the logon types of each edge shown (asked for the nodes shown only)."""
    g = EvidenceLogon
    origins = sorted({node["id"].split(":", 1)[1] for node in nodes.values()})
    targets = sorted({node["id"][5:] for node in nodes.values() if node["kind"] == "host"})
    by_edge = {(edge["from"], edge["to"]): edge for edge in edges}
    for start in range(0, len(origins), IN_MAX):
        part = origins[start : start + IN_MAX]
        for tstart in range(0, len(targets), IN_MAX):
            ranked = (
                select(
                    kind.label("kind"),
                    name.label("name"),
                    target.label("target"),
                    g.username.label("user"),
                    func.count().label("n"),
                    func.row_number()
                    .over(partition_by=(kind, name, target), order_by=(func.count().desc(), g.username))
                    .label("rank"),
                )
                .where(*where, name.in_(part), target.in_(targets[tstart : tstart + IN_MAX]))
                .group_by(kind, name, target, g.username)
                .subquery()
            )
            for origin_kind, origin, to, user, _n, _rank in db.execute(
                select(ranked).where(ranked.c.rank <= USERS_SHOWN).order_by(ranked.c.rank)
            ):
                edge = by_edge.get((f"{origin_kind}:{origin}", f"host:{to}"))
                if edge is not None and user and user not in edge["users"]:
                    edge["users"].append(user)
            kinds = db.execute(
                select(kind, name, target, g.logon_type)
                .where(*where, name.in_(part), target.in_(targets[tstart : tstart + IN_MAX]), g.logon_type.is_not(None))
                .group_by(kind, name, target, g.logon_type)
            )
            for origin_kind, origin, to, logon_type in kinds:
                edge = by_edge.get((f"{origin_kind}:{origin}", f"host:{to}"))
                if edge is not None:
                    edge["types"].append(logon_type)
    for edge in edges:
        edge["types"] = sorted(set(edge["types"]))


def _labels(db: OrmSession, incident_id: str, nodes: dict[str, dict[str, Any]]) -> None:
    """A host node is labelled with the longest spelling its logons have (``WKS-1.corp.example`` over ``WKS-1``)."""
    g = EvidenceLogon
    longest: dict[str, str] = {}
    for column in (g.host, g.source_host, g.target_host):
        # The names of a column are few, whatever its rows.
        for held in db.scalars(select(column).where(g.incident_id == incident_id).distinct()):
            text = (held or "").strip()
            node_id = f"host:{short_id(text)}"
            node = nodes.get(node_id)
            if text and node and node["kind"] == "host" and len(text) > len(longest.get(node_id, "")):
                longest[node_id] = text
    for node_id, text in longest.items():
        nodes[node_id]["label"] = text


def _evidence(db: OrmSession, incident_id: str, nodes: dict[str, dict[str, Any]]) -> None:
    """Mark the nodes that are hosts the incident holds a file, a process or a logon of."""
    names = sorted({node["id"][5:] for node in nodes.values() if node["kind"] == "host"})
    if not names:
        return
    wanted = set(names)
    here: set[str] = set()
    for column, table in (
        (EvidenceSource.host, EvidenceSource),
        (EvidenceProcess.host, EvidenceProcess),
        (EvidenceLogon.host, EvidenceLogon),
    ):
        # The hosts of a table are few, whatever its rows: asked as they are, compared by their short id here.
        here.update(
            short_id(held)
            for held in db.scalars(select(column).where(table.incident_id == incident_id).distinct())
            if held
        )
    here &= wanted
    for node_id, node in nodes.items():
        if node["kind"] == "host" and node_id[5:] in here:
            node["inEvidence"] = True
