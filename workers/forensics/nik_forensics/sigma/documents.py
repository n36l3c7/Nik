"""The text of Sigma rules: where each YAML document is, and a bounded, safe load of it.

A text may hold several documents (``---`` between them). Each is looked at on its own so that an error is
placed in the whole text by its line, and a document that is not a rule does not hide the others. A hostile
text must cost little: a document is cut at ``MAX_DOCUMENT_CHARS``, and the nodes of its graph are counted
(with the aliases followed) before anything is built, so that "billion laughs" is refused, not expanded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

MAX_DOCUMENT_CHARS = 1_000_000
MAX_NODES = 200_000
MAX_DEPTH = 64
_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_SEPARATOR = re.compile(r"^(---|\.\.\.)(\s|$)")


class DocumentError(Exception):
    """A document that cannot be read: where (1-based, in the document) and why."""

    def __init__(self, line: int, column: int, message: str) -> None:
        super().__init__(message)
        self.line, self.column, self.message = line, column, message


@dataclass
class Chunk:
    """One YAML document of a text: its first line in the whole text (1-based) and its own text."""

    line: int
    text: str


def split(text: str) -> list[Chunk]:
    """The documents of a text, without the ``---`` lines. A part that holds only blanks and comments is not one."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    parts: list[tuple[int, list[str]]] = [(1, [])]
    for number, line in enumerate(lines, start=1):
        if _SEPARATOR.match(line):
            parts.append((number + 1, []))
        else:
            parts[-1][1].append(line)
    chunks = []
    for first, body in parts:
        skip = 0
        while skip < len(body) and not body[skip].strip():
            skip += 1
        if not any(row.strip() and not row.lstrip().startswith("#") for row in body):
            continue
        chunks.append(Chunk(first + skip, "\n".join(body[skip:]).rstrip() + "\n"))
    return chunks


def _check_size(node: yaml.Node) -> None:
    """Count the nodes with the aliases followed: a document that expands to more is refused."""
    seen = 0
    stack: list[tuple[yaml.Node, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        seen += 1
        if seen > MAX_NODES:
            raise DocumentError(
                node.start_mark.line + 1,
                node.start_mark.column + 1,
                "the document is too large once its aliases are expanded",
            )
        if depth > MAX_DEPTH:
            raise DocumentError(
                current.start_mark.line + 1, current.start_mark.column + 1, "the document is nested too deep"
            )
        if isinstance(current, yaml.MappingNode):
            for key, value in current.value:
                stack.append((key, depth + 1))
                stack.append((value, depth + 1))
        elif isinstance(current, yaml.SequenceNode):
            stack.extend((item, depth + 1) for item in current.value)


def load(text: str) -> tuple[yaml.Node, Any]:
    """The node graph (with positions) and the plain value of a single YAML document. Raises ``DocumentError``."""
    if len(text) > MAX_DOCUMENT_CHARS:
        raise DocumentError(1, 1, f"the document is longer than {MAX_DOCUMENT_CHARS} characters")
    loader = _Loader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            raise DocumentError(1, 1, "the document is empty")
        _check_size(node)
        return node, loader.construct_document(node)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        message = getattr(error, "problem", None) or str(error)
        raise DocumentError(mark.line + 1 if mark else 1, mark.column + 1 if mark else 1, str(message)) from None
    except RecursionError:
        raise DocumentError(1, 1, "the document is nested too deep") from None
    finally:
        loader.dispose()
