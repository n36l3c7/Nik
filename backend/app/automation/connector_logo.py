"""The logo of a connector: an image somebody uploaded, shown to everyone who reads incidents.

A connector is a package: its file, and beside it a logo and a README. The
logo comes from outside (a pack, an upload), so it is checked before it is
kept and served as an image and nothing else:

- PNG, by its signature, or SVG, as text;
- 256 KB at most;
- an SVG holds no script, no ``foreignObject``, no event handler, no
  ``DOCTYPE`` or entity, and refers to nothing outside itself.

It is shown with ``<img>``, which runs no script of an SVG; the route that
serves it adds a content security policy of its own all the same.
"""

from __future__ import annotations

import re

MAX_BYTES = 256 * 1024
PNG = "image/png"
SVG = "image/svg+xml"
TYPES = (PNG, SVG)
EXTENSIONS = {PNG: "png", SVG: "svg"}

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# What an SVG shown as a logo has no use for, and what could reach outside it.
_ELEMENTS = r"<\s*(script|foreignobject|iframe|object|embed|audio|video)\b"
_INLINE_IMAGE = r"data:image/(?:png|jpeg|gif);base64,"
_FORBIDDEN = (
    (re.compile(r"<!\s*(doctype|entity)", re.IGNORECASE), "a DOCTYPE or an entity"),
    (re.compile(_ELEMENTS, re.IGNORECASE), "an element that is not a drawing"),
    (re.compile(r"\son[a-z]+\s*=", re.IGNORECASE), "an event handler"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "a script address"),
    (
        re.compile(rf"(?:href|src)\s*=\s*[\"'](?!\s*(?:#|{_INLINE_IMAGE}))", re.IGNORECASE),
        "a reference outside the file",
    ),
    (re.compile(r"url\((?!\s*[\"']?\s?#)", re.IGNORECASE), "a reference outside the file"),
    (re.compile(r"@import", re.IGNORECASE), "an imported style sheet"),
)


class LogoError(ValueError):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def clean(data: bytes) -> tuple[bytes, str]:
    """The image as it is kept, and its type. Raises ``LogoError`` saying what is wrong with it."""
    if not data:
        raise LogoError("The logo is empty")
    if len(data) > MAX_BYTES:
        raise LogoError(f"A logo is {MAX_BYTES // 1024} KB at most")
    if data.startswith(_PNG_SIGNATURE):
        return bytes(data), PNG
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise LogoError("A logo is a PNG or an SVG image") from None
    if "<svg" not in text.lower():
        raise LogoError("A logo is a PNG or an SVG image")
    for pattern, what in _FORBIDDEN:
        if pattern.search(text):
            raise LogoError(f"The SVG holds {what}: a logo is a drawing and nothing else")
    body = text.lstrip()
    if body.startswith("<?xml"):
        body = body[body.find("?>") + 2 :].lstrip() if "?>" in body else ""
    while body.startswith("<!--"):
        end = body.find("-->")
        if end == -1:
            break
        body = body[end + 3 :].lstrip()
    if not re.match(r"<svg[\s>]", body, re.IGNORECASE) or "</svg>" not in body.lower():
        raise LogoError("A logo is a PNG or an SVG image")
    return text.encode("utf-8"), SVG


def by_name(name: str) -> bool:
    """Whether a file of a package is its logo, by its name: ``logo.svg`` or ``logo.png``."""
    return name.lower() in ("logo.svg", "logo.png")
