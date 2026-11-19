"""Incident types: the fields of a kind of incident, its page, how it is closed.

A type lists the custom fields its incidents have (each ``required`` or
``required_on_close``), arranges the Summary in sections (its **layout**),
orders the tabs of the page, and says with which reasons an incident of it is
closed. Seven ship; ``Unclassified`` is the type of every incident that was
given no other, so that nothing that exists changes.

    layout = {"sections": [{"id", "title", "key": bool, "columns": 1|2, "fields": [names]}],
              "tabs": [ids in order], "hidden": [ids],
              "grid": [{"id", "kind", "x", "y", "w", "h", "title"?, "section"?, "text"?, "buttons"?,
                        "dashboard"?, "widget"?, "field"?}],
              "pages": [{"id", "name", "grid": [...]}],
              "close": {"sections": [ids]},
              "quick": [{"kind", "section"?, "text"?}]}

The first section flagged ``key`` is the side panel of the incident page. A
type without a layout gets a generated one: its fields, in order.

``grid`` (5.3) is the Summary itself, arranged like a dashboard on twelve
columns: each widget is of a kind (``GRID_KINDS``), and a ``section`` widget
shows one of the sections. A layout without a grid, which is every layout made
before 5.3, is drawn by the page with a grid made from its sections, in their
order: nothing is converted in the database, and nothing has to be.

Since 6.2 a type has **pages** of its own beside the Summary: each a name and
a grid, shown as a tab of the incident (``page:<id>`` in ``tabs`` and
``hidden``). ``close`` names the sections the form of closing shows, in order,
and ``quick`` the blocks of the quick view, the panel a row of the incident
list opens. A layout that has none of the three is drawn as it always was.

A widget of **script buttons** (``buttons``) replaced the playbook buttons of
5.3: the kind ``playbooks`` no longer exists, and a stored widget of it is
left out when a layout is read and when one is saved (``without_gone``).
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from . import fields as registry
from .core.models import Field, Incident, IncidentType, Playbook
from .core.permissions import ROLE_PERMISSIONS, SYSTEM_ROLE
from .core.security import now_iso

UNCLASSIFIED = registry.UNCLASSIFIED
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
COLOURS = ("slate", "red", "amber", "emerald", "cyan", "blue", "violet", "pink")
# The tabs of the incident page a layout can order and hide (frontend/src/config/tabs.js). Since 5.3 the
# analysis ones are kinds of evidence inside the Evidence tab, ordered and hidden there; "automation" is
# still read, for the layouts of 4.x, and means nothing: its runs are in the work plan.
TABS = (
    "evidence",
    "summary",
    "timeline",
    "war_room",
    "work_plan",
    "automation",
    "context",
    "iocs",
    "mail",
    "malware",
    "network",
    "urls",
    "endpoint",
    "eventlogs",
    "browser",
    "commands",
)
SECTIONS_MAX, FIELDS_MAX, REASONS_MAX = 20, 100, 30
# The widgets of the Summary (frontend/src/domain/layoutGrid.js): True for a kind that is on a page once.
GRID_KINDS = {
    "facts": True,
    "section": False,
    "stats": True,
    "timeline": True,
    "timers": True,
    "evidence": True,
    "war_room": True,
    "work_plan": True,
    "indicators": True,
    "buttons": False,
    "chart": False,
    "linked": True,
    "note": False,
}
# Kinds there were: a widget of one is dropped without a word, where a kind nobody ever had is refused.
GONE_KINDS = ("playbooks",)
GRID_MAX, GRID_COLUMNS, GRID_HEIGHT, NOTE_MAX, BUTTONS_MAX = 30, 12, 12, 2000, 8
PAGES_MAX, PAGE_PREFIX, QUICK_MAX = 10, "page:", 12
PAGE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
# The blocks of the quick view (frontend/src/domain/quickView.js draws them), one narrow column.
QUICK_KINDS = ("facts", "section", "stats", "timers", "last", "linked", "note")
# A script button: its text, its two colours, the script under it and a template for each argument.
LABEL_MAX, TEMPLATE_MAX, ARGS_MAX = 40, 2000, 30
COLOUR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
SCRIPT_RE = re.compile(r"^[A-Z][A-Za-z0-9]{2,48}$")
ARGUMENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
BUTTON_BACKGROUND, BUTTON_COLOUR = "#21262d", "#e6edf3"
# What the side panel shows of an incident of any type, and the Summary under it.
KEY_FIELDS = ("status", "severity", "owner", "ticket", "occurred", "tlp")
MORE_FIELDS = ("host", "username", "os", "category", "labels", "affected_hosts", "affected_users", "details")
CLOSE_REASONS = ("Resolved", "False positive", "Duplicate", "Not an incident")


class TypeError_(ValueError):
    """What is wrong with a type, as a sentence."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _shipped(
    type_id: str, name: str, colour: str, icon: str, description: str, more: tuple, reasons: tuple = ()
) -> dict:
    return {
        "id": type_id,
        "name": name,
        "colour": colour,
        "icon": icon,
        "description": description,
        "layout": {
            "sections": [
                {"id": "key", "title": "Key facts", "key": True, "columns": 1, "fields": list(KEY_FIELDS)},
                {"id": "about", "title": "What it is about", "key": False, "columns": 2, "fields": list(more)},
            ],
            "tabs": [],
            "hidden": [],
        },
        "closeReasons": list(reasons or CLOSE_REASONS),
    }


SHIPPED = (
    _shipped(
        UNCLASSIFIED,
        "Unclassified",
        "slate",
        "folder",
        "An incident that was given no type: the page as it always was.",
        MORE_FIELDS,
    ),
    _shipped(
        "phishing",
        "Phishing",
        "amber",
        "mail",
        "A deceptive e-mail: who received it, what it led to, who acted on it.",
        ("affected_users", "category", "labels", "details", "related_incidents"),
        ("Resolved", "False positive", "Awareness test", "Duplicate"),
    ),
    _shipped(
        "malware",
        "Malware",
        "red",
        "bug",
        "Malicious code on a host: what ran, where, what it reached.",
        ("host", "username", "os", "affected_hosts", "category", "labels", "details"),
    ),
    _shipped(
        "network-intrusion",
        "Network intrusion",
        "violet",
        "network",
        "Someone inside the network who should not be: how they came in, where they moved.",
        ("affected_hosts", "affected_users", "category", "labels", "details", "related_incidents"),
    ),
    _shipped(
        "data-leak",
        "Data leak",
        "pink",
        "file-warning",
        "Data that left, or may have: what, how much, towards whom.",
        ("affected_users", "affected_hosts", "category", "labels", "details"),
        ("Resolved", "No data left", "False positive", "Duplicate"),
    ),
    _shipped(
        "access-abuse",
        "Access abuse",
        "blue",
        "key",
        "An account used by who should not, or for what it should not.",
        ("username", "affected_users", "affected_hosts", "category", "labels", "details"),
    ),
    _shipped(
        "vulnerability",
        "Vulnerability",
        "cyan",
        "shield-alert",
        "A weakness found before, or after, someone used it.",
        ("affected_hosts", "category", "labels", "due", "details"),
        ("Fixed", "Mitigated", "Risk accepted", "False positive", "Duplicate"),
    ),
)


# --------------------------------------------------------------------------- #
# Checking                                                                    #
# --------------------------------------------------------------------------- #
def _text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def clean_fields(known: dict[str, Field], listed: Any) -> list[dict[str, Any]]:
    """The custom fields of a type: each a field of the registry, once."""
    if listed is None:
        return []
    if not isinstance(listed, list) or len(listed) > FIELDS_MAX:
        raise TypeError_(f"The fields of a type are a list, {FIELDS_MAX} at most")
    cleaned, seen = [], set()
    for item in listed:
        name = item.get("name") if isinstance(item, dict) else item
        field = known.get(str(name or ""))
        if field is None or field.applies_to != "incident":
            raise TypeError_(f'There is no field of incidents called "{name}"')
        if field.system:
            raise TypeError_(f"{field.label} is a system field: every type has it already")
        if field.name in seen:
            raise TypeError_(f"{field.label} is listed twice")
        seen.add(field.name)
        flags = item if isinstance(item, dict) else {}
        cleaned.append(
            {
                "name": field.name,
                "required": bool(flags.get("required")),
                "required_on_close": bool(flags.get("required_on_close", flags.get("requiredOnClose"))),
            }
        )
    return cleaned


def clean_layout(known: dict[str, Field], own: set[str], layout: Any) -> dict[str, Any] | None:
    """A layout whose sections name fields this type has, and whose tabs exist."""
    if layout is None:
        return None
    if not isinstance(layout, dict):
        raise TypeError_("A layout is an object with sections and tabs")
    sections = layout.get("sections") or []
    if not isinstance(sections, list) or len(sections) > SECTIONS_MAX:
        raise TypeError_(f"A layout has {SECTIONS_MAX} sections at most")
    cleaned, ids, placed = [], set(), set()
    for index, section in enumerate(sections):
        if not isinstance(section, dict):
            raise TypeError_("A section is an object with a title and fields")
        section_id = _text(section.get("id"), 32) or f"s{index + 1}"
        if section_id in ids:
            raise TypeError_("Two sections have the same id")
        ids.add(section_id)
        names = section.get("fields") or []
        if not isinstance(names, list) or len(names) > FIELDS_MAX:
            raise TypeError_("The fields of a section are a list of names")
        for name in names:
            field = known.get(str(name))
            if field is None or field.applies_to != "incident":
                raise TypeError_(f'A section names "{name}", which is not a field of incidents')
            if not (field.system or field.all_types or field.name in own):
                raise TypeError_(f"{field.label} is in a section but is not a field of this type: add it to the type")
            if field.name in placed:
                raise TypeError_(f"{field.label} is in two sections")
            placed.add(field.name)
        cleaned.append(
            {
                "id": section_id,
                "title": _text(section.get("title"), 80) or "Section",
                "key": bool(section.get("key")),
                "columns": 2 if section.get("columns") == 2 else 1,
                "fields": [str(name) for name in names],
            }
        )
    if sum(1 for section in cleaned if section["key"]) > 1:
        raise TypeError_("One section at most is the side panel")
    pages = clean_pages(layout.get("pages"), cleaned)
    page_tabs = {PAGE_PREFIX + page["id"] for page in pages}
    tabs = [str(tab) for tab in layout.get("tabs") or []]
    hidden = [str(tab) for tab in layout.get("hidden") or []]
    for tab in (*tabs, *hidden):
        if tab.startswith(PAGE_PREFIX):
            if tab not in page_tabs:
                raise TypeError_(f'The tabs name the page "{tab[len(PAGE_PREFIX) :]}", which this type does not have')
        elif tab not in TABS:
            raise TypeError_(f'There is no tab called "{tab}": ' + ", ".join(TABS))
    if len(set(tabs)) != len(tabs):
        raise TypeError_("A tab is listed twice")
    if "summary" in hidden:
        raise TypeError_("The Summary cannot be hidden: it is where the fields are")
    out: dict[str, Any] = {"sections": cleaned, "tabs": tabs, "hidden": sorted(set(hidden))}
    # The Summary as a grid: kept only when one was arranged.
    grid = clean_grid(layout.get("grid"), cleaned)
    if grid:
        out["grid"] = grid
    # The pages, the close form and the quick view: each kept only when the type has one.
    if pages:
        out["pages"] = pages
    close = clean_close(layout.get("close"), cleaned)
    if close:
        out["close"] = close
    quick = clean_quick(layout.get("quick"), cleaned)
    if quick:
        out["quick"] = quick
    return out


def clean_pages(pages: Any, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The pages a type adds to its incidents: each an id read in addresses, a name and a grid."""
    if pages is None:
        return []
    if not isinstance(pages, list) or len(pages) > PAGES_MAX:
        raise TypeError_(f"A type has {PAGES_MAX} pages of its own at most")
    cleaned: list[dict[str, Any]] = []
    ids: set[str] = set()
    for page in pages:
        if not isinstance(page, dict):
            raise TypeError_("A page is an object with an id, a name and a grid")
        page_id = str(page.get("id") or "")
        if not PAGE_ID_RE.match(page_id):
            raise TypeError_("The id of a page is a lower-case letter, then lower-case letters, digits or dashes")
        if page_id in ids:
            raise TypeError_("Two pages have the same id")
        ids.add(page_id)
        name = _text(page.get("name"), 40)
        if not name:
            raise TypeError_("A page needs a name: it is what its tab is called")
        cleaned.append({"id": page_id, "name": name, "grid": clean_grid(page.get("grid"), sections)})
    return cleaned


def clean_close(close: Any, sections: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The close form: the sections of the layout the form of closing shows, in the order given."""
    if close is None:
        return None
    named = close.get("sections") if isinstance(close, dict) else None
    if not isinstance(named, list) or len(named) > SECTIONS_MAX:
        raise TypeError_("The close form is a list of sections of the type")
    have = {section["id"] for section in sections}
    chosen: list[str] = []
    for item in named:
        section_id = str(item or "")
        if section_id not in have:
            raise TypeError_(f'The close form shows the section "{section_id}", which this layout does not have')
        if section_id in chosen:
            raise TypeError_("A section is in the close form twice")
        chosen.append(section_id)
    return {"sections": chosen} if chosen else None


def clean_quick(quick: Any, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The quick view: blocks one under the other, each of a kind there is. A text is there as
    often as wanted and a section once each (never the side panel: its fields are the details);
    every other kind is there once. It is what ``quickBlocks`` of the page reads."""
    if quick is None:
        return []
    if not isinstance(quick, list) or len(quick) > QUICK_MAX:
        raise TypeError_(f"The quick view has {QUICK_MAX} blocks at most")
    shown = {section["id"] for section in sections if not section["key"]}
    cleaned: list[dict[str, Any]] = []
    seen: set[str] = set()
    for block in quick:
        kind = str(block.get("kind") or "") if isinstance(block, dict) else ""
        if kind not in QUICK_KINDS:
            raise TypeError_(f'There is no block of the kind "{kind}" in a quick view: ' + ", ".join(QUICK_KINDS))
        item: dict[str, Any] = {"kind": kind}
        once = kind
        if kind == "section":
            section_id = str(block.get("section") or "")
            if section_id not in shown:
                raise TypeError_(f'The quick view shows the section "{section_id}", which this layout does not have')
            item["section"] = section_id
            once = f"section:{section_id}"
        elif kind == "note":
            item["text"] = str(block.get("text") or "")[:NOTE_MAX]
            once = ""
        if once and once in seen:
            raise TypeError_(f'The block "{kind}" is in a quick view once' + (" for a section" if ":" in once else ""))
        seen.add(once)
        cleaned.append(item)
    return cleaned


def clean_buttons(buttons: Any) -> list[dict[str, Any]]:
    """The buttons of a widget: what each says, how it is drawn, the script it runs and with what."""
    from .automation import expressions

    if buttons is None:
        return []
    if not isinstance(buttons, list) or len(buttons) > BUTTONS_MAX:
        raise TypeError_(f"A widget has {BUTTONS_MAX} script buttons at most")
    cleaned = []
    for button in buttons:
        if not isinstance(button, dict):
            raise TypeError_("A script button is an object with a text, two colours and a script")
        label = _text(button.get("label"), LABEL_MAX)
        if not label:
            raise TypeError_("A script button needs its text")
        background = str(button.get("background") or BUTTON_BACKGROUND)
        colour = str(button.get("color") or BUTTON_COLOUR)
        if not COLOUR_RE.match(background) or not COLOUR_RE.match(colour):
            raise TypeError_(f'The colours of the button "{label}" are written #rrggbb')
        script = str(button.get("script") or "")
        if script and not SCRIPT_RE.match(script):
            raise TypeError_(f'The button "{label}" names a script that cannot exist: "{script}"')
        given = button.get("args") or {}
        if not isinstance(given, dict) or len(given) > ARGS_MAX:
            raise TypeError_(f'The arguments of the button "{label}" are names with a text each')
        args: dict[str, str] = {}
        for name, template in given.items():
            if not ARGUMENT_RE.match(str(name)):
                raise TypeError_(f'The button "{label}" has an argument that cannot be one: "{name}"')
            text = str(template if template is not None else "")[:TEMPLATE_MAX]
            if not text.strip():
                continue  # left empty: asked when the button is pressed
            try:
                expressions.parse(text)
            except expressions.ExpressionError as error:
                raise TypeError_(f'The button "{label}", argument {name}: {error.message}') from None
            args[str(name)] = text
        cleaned.append(
            {"label": label, "background": background.lower(), "color": colour.lower(), "script": script, "args": args}
        )
    return cleaned


def _whole(value: Any, low: int, high: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
        raise TypeError_(f"{what} of a widget is a whole number")
    if not low <= int(value) <= high:
        raise TypeError_(f"{what} of a widget is between {low} and {high}")
    return int(value)


def clean_grid(grid: Any, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The widgets of a page (the Summary, or a page of the type): each of a kind there is, inside
    the twelve columns, a section widget for a section of this layout that is not the side panel."""
    if grid is None:
        return []
    if not isinstance(grid, list):
        raise TypeError_(f"The page of a type has {GRID_MAX} widgets at most")
    # A widget of a kind that is gone is not counted, and not kept.
    grid = [widget for widget in grid if not (isinstance(widget, dict) and widget.get("kind") in GONE_KINDS)]
    if len(grid) > GRID_MAX:
        raise TypeError_(f"The page of a type has {GRID_MAX} widgets at most")
    shown = {section["id"] for section in sections if not section["key"]}
    cleaned: list[dict[str, Any]] = []
    ids: set[str] = set()
    once: set[str] = set()
    for index, widget in enumerate(grid):
        if not isinstance(widget, dict):
            raise TypeError_("A widget is an object with a kind and a place")
        kind = str(widget.get("kind") or "")
        if kind not in GRID_KINDS:
            raise TypeError_(f'There is no widget of the kind "{kind}": ' + ", ".join(GRID_KINDS))
        if GRID_KINDS[kind] and kind in once:
            raise TypeError_(f'The widget "{kind}" is on a page once')
        once.add(kind)
        widget_id = _text(widget.get("id"), 40) or f"{kind}-{index + 1}"
        if widget_id in ids:
            raise TypeError_("Two widgets have the same id")
        ids.add(widget_id)
        width = _whole(widget.get("w"), 1, GRID_COLUMNS, "The width")
        out: dict[str, Any] = {
            "id": widget_id,
            "kind": kind,
            "x": _whole(widget.get("x"), 0, GRID_COLUMNS - width, "The column"),
            "y": _whole(widget.get("y"), 0, 10_000, "The row"),
            "w": width,
            "h": _whole(widget.get("h"), 1, GRID_HEIGHT, "The height"),
        }
        title = _text(widget.get("title"), 80)
        if title:
            out["title"] = title
        if kind == "section":
            section = str(widget.get("section") or "")
            if section not in shown:
                raise TypeError_(f'A widget shows the section "{section}", which this layout does not have')
            out["section"] = section
        elif kind == "note":
            out["text"] = str(widget.get("text") or "")[:NOTE_MAX]
        elif kind == "buttons":
            out["buttons"] = clean_buttons(widget.get("buttons"))
        elif kind == "chart":
            # Which widget of which dashboard, and the field of the incident its query is narrowed by.
            out["dashboard"] = _text(widget.get("dashboard"), 64)
            out["widget"] = _text(widget.get("widget"), 64)
            out["field"] = _text(widget.get("field"), 64)
        cleaned.append(out)
    return cleaned


def without_gone(layout: dict[str, Any] | None) -> dict[str, Any] | None:
    """A stored layout as it is read: without the widgets of a kind that no longer exists. A layout
    saved before 6.2 may hold playbook buttons; nothing is rewritten in the database for them."""
    if not isinstance(layout, dict):
        return layout

    def kept(grid: Any) -> Any:
        if not isinstance(grid, list):
            return grid
        return [widget for widget in grid if not (isinstance(widget, dict) and widget.get("kind") in GONE_KINDS)]

    out = dict(layout)
    if "grid" in out:
        out["grid"] = kept(out["grid"])
        if not out["grid"]:
            del out["grid"]  # nothing is left of it: the page is the generated one again
    if isinstance(out.get("pages"), list):
        out["pages"] = [
            {**page, "grid": kept(page.get("grid"))} if isinstance(page, dict) else page for page in out["pages"]
        ]
    return out


def generated_layout(known: dict[str, Field], kind: IncidentType | None) -> dict[str, Any]:
    """The layout of a type that has none: the key facts, then its own fields, in order."""
    own = [item["name"] for item in (kind.fields if kind is not None else None) or [] if item.get("name") in known]
    everywhere = sorted(
        (
            field.name
            for field in known.values()
            if field.all_types and not field.system and field.applies_to == "incident"
        ),
        key=lambda name: (known[name].label or name).lower(),
    )
    extra = [name for name in everywhere if name not in own]
    sections = [
        {"id": "key", "title": "Key facts", "key": True, "columns": 1, "fields": list(KEY_FIELDS)},
        {"id": "about", "title": "What it is about", "key": False, "columns": 2, "fields": list(MORE_FIELDS)},
    ]
    if own or extra:
        sections.append({"id": "fields", "title": "More", "key": False, "columns": 2, "fields": [*own, *extra]})
    return {"sections": sections, "tabs": [], "hidden": []}


def clean(db: OrmSession, body: dict[str, Any], existing: IncidentType | None = None) -> dict[str, Any]:
    """What a type is saved with, checked. Keys left out keep what the type has."""
    known = registry.registry(db)
    out: dict[str, Any] = {}
    if "name" in body or existing is None:
        name = _text(body.get("name"), 80)
        if not name:
            raise TypeError_("A type needs a name")
        taken = db.scalars(select(IncidentType).where(func.lower(IncidentType.name) == name.lower())).first()
        if taken is not None and (existing is None or taken.id != existing.id):
            raise TypeError_("There is a type with this name already")
        out["name"] = name
    if "description" in body:
        out["description"] = _text(body.get("description"), 1000)
    if "colour" in body:
        colour = str(body.get("colour") or "slate")
        if colour not in COLOURS:
            raise TypeError_("A colour is one of: " + ", ".join(COLOURS))
        out["colour"] = colour
    if "icon" in body:
        out["icon"] = _text(body.get("icon"), 32)
    if "fields" in body:
        out["fields"] = clean_fields(known, body.get("fields"))
    own = {item["name"] for item in out.get("fields", existing.fields if existing is not None else []) or []}
    if "layout" in body:
        out["layout"] = clean_layout(known, own, body.get("layout"))
    elif "fields" in out and existing is not None and existing.layout:
        # A field taken off the type leaves its sections too.
        kept = dict(existing.layout)
        kept["sections"] = [
            {
                **section,
                "fields": [
                    name
                    for name in section.get("fields") or []
                    if name in known and (known[name].system or known[name].all_types or name in own)
                ],
            }
            for section in kept.get("sections") or []
        ]
        out["layout"] = kept
    if "sla" in body:
        from . import timers

        try:
            out["sla"] = timers.clean_sla(db, body.get("sla"))
        except timers.TimerError as error:
            raise TypeError_(error.message) from None
    if "closeReasons" in body:
        reasons = body.get("closeReasons") or []
        if not isinstance(reasons, list) or len(reasons) > REASONS_MAX:
            raise TypeError_(f"The close reasons are a list, {REASONS_MAX} at most")
        out["close_reasons"] = list(dict.fromkeys(_text(item, 80) for item in reasons if _text(item, 80)))
    if "defaultPlaybookId" in body:
        playbook_id = body.get("defaultPlaybookId") or None
        if playbook_id is not None and db.get(Playbook, str(playbook_id)) is None:
            raise TypeError_("The playbook of the type does not exist")
        out["default_playbook_id"] = str(playbook_id) if playbook_id else None
    if "autoRun" in body:
        out["auto_run"] = bool(body.get("autoRun"))
    if out.get("auto_run", existing.auto_run if existing is not None else False) and not out.get(
        "default_playbook_id", existing.default_playbook_id if existing is not None else None
    ):
        raise TypeError_("To run by itself a type needs its playbook")
    if "visibleToRoles" in body:
        roles = body.get("visibleToRoles")
        if roles is not None:
            if not isinstance(roles, list) or any(
                role not in ROLE_PERMISSIONS or role == SYSTEM_ROLE for role in roles
            ):
                raise TypeError_("The roles that see a type are roles that exist")
            roles = sorted(set(roles))
        out["visible_to_roles"] = roles or None
    return out


# --------------------------------------------------------------------------- #
# Storing                                                                     #
# --------------------------------------------------------------------------- #
def seed(db: OrmSession) -> int:
    """Add the shipped types that are missing (the caller commits). One that is there is the team's: left alone."""
    known = {row.id for row in db.scalars(select(IncidentType))}
    names = {row.name.lower() for row in db.scalars(select(IncidentType))}
    added = 0
    for item in SHIPPED:
        if item["id"] in known or item["name"].lower() in names:
            continue
        stamp = now_iso()
        db.add(
            IncidentType(
                id=item["id"],
                name=item["name"],
                description=item["description"],
                colour=item["colour"],
                icon=item["icon"],
                fields=[],
                layout=item["layout"],
                sla=[],
                close_reasons=item["closeReasons"],
                builtin=True,
                created_at=stamp,
                updated_at=stamp,
                updated_by="nik",
            )
        )
        added += 1
    return added


def every(db: OrmSession) -> list[IncidentType]:
    """The types, ``Unclassified`` first, then by name; the shipped ones are added when missing."""
    rows = db.scalars(select(IncidentType)).all()
    if not any(row.id == UNCLASSIFIED for row in rows):
        seed(db)
        db.flush()
        rows = db.scalars(select(IncidentType)).all()
    return sorted(rows, key=lambda row: (row.id != UNCLASSIFIED, row.name.lower()))


def new_id(db: OrmSession, name: str) -> str:
    """An id read in addresses and files: the name in lower case, with dashes."""
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:28] or "type"
    if not base[0].isalpha():
        base = "t-" + base
    candidate, counter = base, 2
    while db.get(IncidentType, candidate) is not None:
        candidate = f"{base[:28]}-{counter}"
        counter += 1
    return candidate


def incidents_of(db: OrmSession, type_id: str) -> int:
    if type_id == UNCLASSIFIED:
        condition = Incident.type_id.is_(None) | (Incident.type_id == UNCLASSIFIED)
    else:
        condition = Incident.type_id == type_id
    return db.scalar(select(func.count()).select_from(Incident).where(condition)) or 0


def out(db: OrmSession, row: IncidentType, known: dict[str, Field] | None = None) -> dict[str, Any]:
    known = known if known is not None else registry.registry(db)
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "colour": row.colour,
        "icon": row.icon,
        "builtin": bool(row.builtin),
        "fields": [
            {
                "name": item["name"],
                "required": bool(item.get("required")),
                "requiredOnClose": bool(item.get("required_on_close")),
            }
            for item in row.fields or []
            if item.get("name") in known
        ],
        # What the page is drawn from: the saved layout, or one made from the fields.
        "layout": without_gone(row.layout) or generated_layout(known, row),
        "customLayout": bool(row.layout),
        "sla": _sla_out(row.sla),
        "closeReasons": row.close_reasons or [],
        "defaultPlaybookId": row.default_playbook_id,
        "autoRun": bool(row.auto_run),
        "visibleToRoles": row.visible_to_roles,
        "incidents": incidents_of(db, row.id),
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


def _sla_out(rules: list | None) -> list[dict[str, Any]]:
    from . import timers

    return timers.sla_out(rules)
