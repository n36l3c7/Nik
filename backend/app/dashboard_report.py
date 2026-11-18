"""A dashboard as a document: what each widget answers, worked out on the server.

The page of a dashboard asks ``/api/query/aggregate`` for each widget; this
module asks the same questions in one go, **as the person who wants the
report**, and writes the answers as the incident report is written (same
style sheet, every value escaped, nothing fetched by the renderer). A chart
becomes its table, with a bar beside each figure; a widget the person may not
ask says so and shows nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import query as ql
from .core.models import Dashboard
from .query import aggregate as agg
from .report import _CSS, _table, esc

# The date each entity is counted on when a widget names none.
TIME_FIELD = {
    "incidents": "created",
    "artifacts": "created",
    "indicators": "firstSeen",
    "tasks": "created",
    "runs": "started",
    "approvals": "asked",
    "audit": "at",
}
RANGES = {"24h": "the last 24 hours", "7d": "the last 7 days", "30d": "the last 30 days", "90d": "the last 90 days",
          "1y": "the last year", "all": "all time"}  # fmt: skip
_EXTRA_CSS = """
.widget { break-inside: avoid; margin-bottom: 6px; }
.figure { font-size: 20pt; font-weight: bold; margin: 2px 0; }
.bar { display: inline-block; height: 7px; background: #3987e5; vertical-align: middle; min-width: 1px; }
td.num, th.num { text-align: right; white-space: nowrap; }
"""


def both(first: str, second: str) -> str:
    first, second = (first or "").strip(), (second or "").strip()
    if not first or not second:
        return first or second
    return f"({first}) ({second})"


def widget_query(widget: dict, row: Dashboard) -> str:
    """The query of a widget, narrowed by the filter of its dashboard when it is of the same entity."""
    options = widget.get("options") or {}
    narrowed = row.filter_query if row.filter_entity == widget.get("entity") and not options.get("ignoreFilter") else ""
    return both(str(widget.get("query") or ""), narrowed)


def duration(seconds: Any) -> str:
    if seconds is None:
        return "—"
    left = int(round(abs(float(seconds))))
    if left < 60:
        return f"{left}s"
    parts: list[str] = []
    for name, size in (("d", 86400), ("h", 3600), ("m", 60)):
        count, left = divmod(left, size)
        if count or parts:
            parts.append(f"{count}{name}")
        if len(parts) == 2:
            break
    return " ".join(part for index, part in enumerate(parts) if index == 0 or not part.startswith("0"))


def written(value: Any, widget: dict) -> str:
    """A figure as it is read: a duration for a measure of time, a size, or a number."""
    if value is None:
        return "—"
    chosen = (widget.get("options") or {}).get("format")
    measure = str(widget.get("measure") or "")
    timed = "duration(" in measure or ":timeTo" in measure
    if chosen == "duration" or (chosen is None and timed):
        return duration(value)
    if chosen == "bytes":
        number = float(value)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(number) < 1024 or unit == "TB":
                return f"{number:.0f} {unit}" if unit == "B" or number >= 10 else f"{number:.1f} {unit}"
            number /= 1024
    if chosen == "percent":
        return f"{float(value):g}%"
    number = float(value)
    return f"{int(number):,}" if number.is_integer() else f"{number:,.2f}"


def _rows(
    db: OrmSession, widget: dict, query: str, principal: Any, source: Callable[[], Iterable[dict]] | None
) -> tuple[list[str], list[list[Any]], int]:
    """The rows of a table widget: its columns, the first rows, how many there are."""
    entity = ql.entity_of(widget["entity"])
    options = widget.get("options") or {}
    specs = [spec for spec in (entity.field(name) for name in options.get("columns") or []) if spec is not None]
    specs = specs or [entity.fields[0]]
    limit = int(options.get("limit") or 10)
    if entity.model is None:
        keep = ql.rows(entity.name, query, principal)
        kept = [row for row in (source() if source is not None else ()) if keep(row)]
        shown = [[spec.getter(row) if spec.getter else None for spec in specs] for row in kept[:limit]]
        return [spec.name for spec in specs], shown, len(kept)
    specs = [spec for spec in specs if spec.column is not None] or [entity.fields[0]]
    conditions = ql.sql(entity.name, query, principal)
    ql.statement_timeout(db)
    newest = entity.field(TIME_FIELD.get(entity.name, "")) or specs[0]
    found = db.execute(
        select(*(spec.column.label(f"c{index}") for index, spec in enumerate(specs)))
        .select_from(entity.model)
        .where(*conditions)
        .order_by(newest.column.desc())
        .limit(limit)
    ).all()
    from sqlalchemy import func

    total = db.scalar(select(func.count()).select_from(entity.model).where(*conditions)) or 0
    return [spec.name for spec in specs], [list(row) for row in found], int(total)


def answers(
    db: OrmSession,
    row: Dashboard,
    principal: Any,
    time_range: str | None = None,
    *,
    now: datetime | None = None,
    source: Callable[[], Iterable[dict]] | None = None,
) -> list[dict[str, Any]]:
    """Each widget with what it answers to this person: ``{widget, result | rows | note}``."""
    from .dashboards import ASKING

    chosen = (time_range or row.time_range or "all").lower()
    out: list[dict[str, Any]] = []
    for widget in sorted(row.layout or [], key=lambda item: (item.get("y", 0), item.get("x", 0))):
        kind = widget.get("type")
        if kind == "text":
            out.append({"widget": widget, "text": str((widget.get("options") or {}).get("text") or "")})
            continue
        if kind not in ASKING:
            out.append({"widget": widget, "note": "Shown in Nik only: it is read as the page is opened."})
            continue
        options = widget.get("options") or {}
        query = widget_query(widget, row)
        within = None if options.get("ignoreRange") or chosen == "all" else chosen
        field = options.get("timeField") or TIME_FIELD.get(widget["entity"])
        try:
            if kind == "table":
                if within:
                    span = agg.time_range(within, now or datetime.now(timezone.utc))
                    query = agg._within(query, field, *span)
                columns, rows, total = _rows(db, widget, query, principal, source)
                out.append({"widget": widget, "columns": columns, "rows": rows, "total": total})
                continue
            result = agg.run(
                db,
                widget["entity"],
                query,
                principal,
                group_by=widget.get("groupBy") or [],
                measure=widget.get("measure") or "count",
                time_field=field if within else None,
                time_range_=within,
                compare="previous" if within and options.get("compare") else None,
                limit=500 if kind in ("trend", "stacked_bar") else int(options.get("limit") or 10),
                now=now,
                source=source,
            )
            out.append({"widget": widget, "result": result})
        except ql.QueryForbidden:
            out.append({"widget": widget, "note": "Your roles do not let you see this."})
        except ql.QueryError as error:
            out.append({"widget": widget, "note": f"This could not be asked: {error.message}"})
    return out


def _cell(value: Any) -> str:
    if value is None or value == "":
        return '<span class="muted">—</span>'
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return esc(", ".join(str(item) for item in value))
    text = str(value)
    if len(text) >= 19 and text[4:5] == "-" and text[10:11] == "T":
        text = text[:16].replace("T", " ")
    return esc(text)


def _answer_html(answer: dict[str, Any]) -> str:
    widget = answer["widget"]
    if "text" in answer:
        from .report import _paragraphs

        return _paragraphs(answer["text"])
    if "note" in answer:
        return f'<p class="muted">{esc(answer["note"])}</p>'
    if "rows" in answer:
        shown = len(answer["rows"])
        table = _table([esc(name) for name in answer["columns"]], [[_cell(v) for v in row] for row in answer["rows"]])
        more = f'<p class="muted">The first {shown} of {answer["total"]:,}.</p>' if answer["total"] > shown else ""
        return (table if shown else '<p class="muted">Nothing to show.</p>') + more
    result = answer["result"]
    groups = result["columns"][:-1]
    if not groups:
        figure = f'<p class="figure">{esc(written(result["total"], widget))}</p>'
        target = (widget.get("options") or {}).get("target")
        if widget.get("type") == "gauge" and target:
            figure += f'<p class="muted">Against a target of {esc(written(target, widget))}.</p>'
        if result.get("previous"):
            before = result["previous"]["total"]
            figure += f'<p class="muted">The period before: {esc(written(before, widget))}.</p>'
        return figure
    values = [row[-1] for row in result["rows"] if isinstance(row[-1], (int, float))]
    largest = max(values, default=0) or 1
    rows = []
    for row in result["rows"]:
        share = max(0.0, float(row[-1] or 0)) / largest * 100
        keys = [esc(key) if key not in ("", None) else '<span class="muted">(none)</span>' for key in row[:-1]]
        rows.append([*keys, esc(written(row[-1], widget)), f'<span class="bar" style="width:{share:.1f}%"></span>'])
    if not rows:
        return '<p class="muted">Nothing to show.</p>'
    names = [esc(f"{group['name']} by {group['bucket']}" if group["bucket"] else group["name"]) for group in groups]
    table = _table([*names, esc(result["columns"][-1]["name"]), ""], rows)
    notes = ""
    if result.get("more"):
        notes += f'<p class="muted">And {result["more"]} more.</p>'
    if result.get("truncated"):
        notes += f'<p class="muted">Worked out from the first {agg.MAX_ROWS:,} rows that match.</p>'
    return table + notes


def build_html(
    row: Dashboard, found: list[dict[str, Any]], *, time_range: str, generated_by: str, generated_at: str, org: str = ""
) -> str:
    """The dashboard as one HTML document, ready to be shown or made a PDF."""
    period = RANGES.get(time_range, f"the last {time_range}")
    parts = []
    for answer in found:
        widget = answer["widget"]
        title = widget.get("title") or str(widget.get("type") or "").replace("_", " ").capitalize()
        asked = ""
        if widget.get("entity"):
            query = widget_query(widget, row)
            asked = (
                f'<p class="sub">{esc(widget["entity"])}' + (f": <code>{esc(query)}</code>" if query else "") + "</p>"
            )
        parts.append(f'<section class="widget"><h2>{esc(title)}</h2>{asked}{_answer_html(answer)}</section>')
    description = f'<p class="sub">{esc(row.description)}</p>' if row.description else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>{esc(row.name)}</title><style>{_CSS}{_EXTRA_CSS}</style></head><body>"
        f'<span class="org">{esc(org)}</span>'
        f'<header class="cover"><div class="who"><h1 class="incident-name">{esc(row.name)}</h1>{description}'
        f'<p class="sub">Dashboard · {esc(period)} · as seen by {esc(generated_by)} · {esc(generated_at[:16])} UTC</p>'
        "</div></header>" + "".join(parts) + "</body></html>"
    )
