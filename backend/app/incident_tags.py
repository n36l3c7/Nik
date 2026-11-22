"""The tags of an incident: the rules of a tag, and how tags are added and taken off.

An incident's tags are its field ``labels`` of the registry: that is the name
it has where it is stored (``incidents.fields``), in the types, the mappers
and the packs, and it stays. A person reads **Tags**; a query asks ``tag:``,
``tags:`` or ``labels:``; an expression reads ``incident.tags`` or
``incident.labels``.

A tag is what a tag is on an indicator and on an artifact, so that one tag
means the same thing wherever it is put:

- lower case: ``Phish`` is kept as ``phish``, and found by either;
- a letter or a digit, then letters, digits and ``. _ : -``, 40 characters at
  most. A ``#`` in front is dropped, and the spaces inside a tag become ``-``
  (``data leak`` is ``data-leak``): a tag is one word;
- once on an incident, 12 on an incident at most.

What an incident held before these rules (a label with a capital, or with a
character a tag does not take) is kept as it is until somebody takes it off:
only what is added is held to the rules.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy.orm import Session as OrmSession

from . import artifacts
from . import fields as registry
from .core.models import Incident

FIELD = "labels"  # the name of the field in the registry, and where the tags are stored
ALIASES = ("tag", "tags")  # the other names of the field in a query; ``tags`` in an expression
TAG_RE = artifacts.TAG_RE  # one way to write a tag, whatever carries it
TAGS_MAX = 12
RULE = "A tag is a letter or a digit, then letters, digits and . _ : - (40 characters at most)"


def clean_tag(raw: Any) -> str:
    """A tag as it is kept; ``FieldError`` when what was given cannot be one."""
    text = "-".join(str(raw if raw is not None else "").split()).lower().lstrip("#")
    if not TAG_RE.fullmatch(text):
        shown = str(raw)[:60]
        raise registry.FieldError(f'"{shown}" is not a tag. {RULE}', FIELD)
    return text


def given(value: Any) -> list[Any]:
    """What was sent as tags: a list, or a text of them separated by commas."""
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    return [item for item in items if str(item if item is not None else "").strip()]


def clean(value: Any, held: Iterable[str] = ()) -> list[str]:
    """The tags of an incident as they are kept, from what was sent for them.

    ``held`` is what the incident has now: a tag it has already is kept as it
    is written there, whatever the rules say of it. Everything else is a new
    tag, and is held to the rules.
    """
    known = {str(tag).casefold(): str(tag) for tag in held or []}
    kept: list[str] = []
    seen: set[str] = set()
    new = False
    for item in given(value):
        tag = known.get(str(item).strip().casefold())
        fresh = False
        if tag is None:
            cleaned = clean_tag(item)
            # The same tag written another way (Phish, #phish) is the one it has.
            tag = known.get(cleaned.casefold())
            if tag is None:
                tag, fresh = cleaned, True
        if tag.casefold() in seen:
            continue
        seen.add(tag.casefold())
        kept.append(tag)
        new = new or fresh
    if new and len(kept) > TAGS_MAX:
        raise registry.FieldError(f"An incident holds {TAGS_MAX} tags at most", FIELD)
    return kept


def of(incident: Incident) -> list[str]:
    """The tags an incident has, in the order they were put."""
    stored = incident.fields if isinstance(incident.fields, dict) else {}
    held = stored.get(FIELD)
    return [str(tag) for tag in held] if isinstance(held, list) else []


def added(held: list[str], tags: Any) -> list[str]:
    """``held`` with these tags put on it: those it has already are not added again."""
    return clean([*held, *given(tags)], held)


def removed(held: list[str], tags: Any) -> list[str]:
    """``held`` without these tags, compared without regard to case. One that is not a tag is
    still looked for as it was written: that is how a label from before the rules is taken off."""
    gone = set()
    for item in given(tags):
        gone.add(str(item).strip().casefold())
        gone.add("-".join(str(item).split()).lower().lstrip("#"))
    return [tag for tag in held if tag.casefold() not in gone]


def named(db: OrmSession, values: dict[str, Any]) -> dict[str, Any]:
    """The fields of an incident as an expression reads them: ``tags`` is there beside ``labels``
    when the incident has tags, unless a field of the registry is called ``tags`` itself."""
    if FIELD not in values or "tags" in values or "tags" in registry.registry(db):
        return values
    return {**values, "tags": values[FIELD]}
