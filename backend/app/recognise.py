"""What in a text is an indicator, and of which type.

The one place that answers it: the action that makes indicators of a string
(``nik.make-indicators``), the step that finds them when an incident comes in
(``indicators_found.py``) and the reader of a pasted list
(``ioc_library.refang``) all come here. Pure functions: nothing is read from
the database, nothing is asked of the network.

    find(text)        every indicator in a text, in the order met, once each
    identify(text)    what one string *is* (a URL gives the URL and its host),
                      or the sentence that says why it is nothing

Only the types Nik keeps are recognised (``iocs.TYPES``): ``ip`` (IPv4 and
IPv6), ``domain``, ``url``, ``email``, ``md5``, ``sha1``, ``sha256``. A value
comes out in the spelling the library stores (``iocs.normalize``), so the
same thing written twice is one indicator.

The rules, and why each is there:

- **Defanged forms are read as meant**: ``hxxp://``, ``[.]``, ``(.)``,
  ``{.}``, ``[dot]``, ``[at]``, ``[@]``, ``[:]``, ``[://]``. Reports and
  tickets write indicators that way so that nobody clicks them.
- **A URL** is ``http``, ``https`` or ``ftp``, the schemes the library takes
  for one. What follows it in a sentence is not part of it: closing
  punctuation, and a closing bracket that nothing opened inside the URL. Its
  scheme and host are written lower-case, a port that is the scheme's own is
  dropped, a name with letters outside ASCII becomes its ``xn--`` form. It
  gives **two** indicators: the URL, and its host (a domain, or an address
  when the host is one). User names and ports are not part of the host.
- **An e-mail address** gives the address and nothing else: its domain is
  most often a mail provider's or the organisation's own, and would link
  incidents that have nothing in common.
- **A domain** has a top-level domain of the Public Suffix List (the copy
  the ``publicsuffixlist`` package carries: no download) and a name under
  it, so ``kernel32.dll``, ``report.final.docx`` and ``1.2.3`` are not
  domains. Where a top-level domain is also a file extension (``zip``,
  ``mov``, ``sh``, ``md``, ``py``…) a name of two labels reads as a file; so
  does anything written in a path (``C:\\tools\\evil.com``,
  ``/tmp/update.pl``). A name called like a function (``window.open(``), the
  attribute of a word of code (``this.name``) and a package written
  backwards (``com.google.chrome``) are not domains either.
- **An address** is four numbers that ``ipaddress`` takes (no leading
  zeros, none over 255) and that are not a version: not more or fewer than
  four parts, not glued to letters, not after ``version``, ``build`` or
  ``Name/``. IPv6 in every form the standard library reads, with a zone
  dropped; a word of two hex groups with no digit (``Cafe::Add``) is code.
- **A hash** is 32, 40 or 64 hex characters as a whole token: nothing of a
  longer run of hex (a SHA-512, a key) is one, and neither is a run of
  digits alone. SHA-512 is not a type Nik keeps.

What is recognised and is no threat is **marked**, not dropped, so the caller
decides: ``private`` (an address that is not public, a URL on an internal
name), ``benign`` (names reserved for documentation, the hosts of XML and
JSON schemas, the digests of nothing), ``own`` (the organisation's own
domains) and ``allowlisted`` (the IOC allowlist of Settings).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

TEXT_MAX = 200_000  # characters of one text that are read
FOUND_MAX = 2000  # indicators of one text
VALUE_MAX = 1024  # the longest value the library stores
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
MARKS = ("private", "benign", "own", "allowlisted")

# --------------------------------------------------------------------------- #
# Defanged forms                                                              #
# --------------------------------------------------------------------------- #
_REFANG = (
    (re.compile(r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}", re.IGNORECASE), "."),
    (re.compile(r"\[(?:@|at)\]|\((?:@|at)\)|\{(?:@|at)\}", re.IGNORECASE), "@"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    # The brackets first: the scheme is read once its colon and slashes are back.
    (re.compile(r"\bh(?:xx|\*\*)p(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bfxp(s?)://", re.IGNORECASE), r"ftp\1://"),
)


def refang(text: str) -> str:
    """``hxxps://evil[.]example`` as it is meant: ``https://evil.example``."""
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


# --------------------------------------------------------------------------- #
# What is known to be no threat                                               #
# --------------------------------------------------------------------------- #
# Top-level domains kept for documentation and tests (RFC 2606, RFC 6761): never public names.
RESERVED_TLDS = frozenset({"example", "test", "invalid", "localhost"})
# Names kept for documentation, and the hosts XML and JSON documents name as their schema.
BENIGN_DOMAINS = frozenset(
    {
        "example.com",
        "example.net",
        "example.org",
        "w3.org",
        "xmlsoap.org",
        "openxmlformats.org",
        "schemas.microsoft.com",
        "schemas.android.com",
        "json-schema.org",
        "schema.org",
        "purl.org",
        "xmlns.com",
        "ns.adobe.com",
        "oasis-open.org",
        "ietf.org",
        "iana.org",
        "omg.org",
        "java.sun.com",
        "xml.apache.org",
        "maven.apache.org",
        "docbook.org",
        "dublincore.org",
        "opengis.net",
        "mitre.org",
    }
)
# The digests of no bytes at all: every empty file has them.
EMPTY_DIGESTS = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
)
# Top-level domains that are file extensions too: a name of two labels under one reads as a file.
# (The library's own list, ``parsing.malware._FALSE_POSITIVE_DOMAINS``, holds the extensions that
# are no top-level domain and is applied by ``iocs.normalize``.)
# Poland and Serbia are among them: as bare words in an alert ``update.pl`` and ``main.rs`` are
# scripts far more often than names, and a name under them is still read with a third label
# (``www.sklep.pl``), inside a URL, or when the caller says it is a domain.
FILE_TLDS = frozenset({"zip", "mov", "sh", "md", "py", "pm", "ps", "so", "app", "cab", "rs", "pl"})
# Words of code whose attribute reads as a name under a top-level domain (``this.name``, ``e.target``).
CODE_WORDS = frozenset(
    {
        "this",
        "self",
        "window",
        "document",
        "console",
        "object",
        "system",
        "sys",
        "os",
        "e",
        "event",
        "obj",
        "item",
        "string",
        "math",
        "json",
        "process",
        "module",
        "exports",
        "req",
        "res",
        "request",
        "response",
        "args",
        "config",
        "env",
        "props",
        "state",
        "node",
        "element",
        "result",
        "error",
        "value",
    }
)
# The first label of a package written backwards (``com.google.chrome``, ``org.apache.commons``).
REVERSED_FIRST = frozenset({"com", "org", "net", "java", "javax", "android", "kotlin", "sun"})
_VERSION_WORD = re.compile(r"(?:\bv|\bver|\bversion|\bbuild|\brelease|\brev)[\s:=]*$", re.IGNORECASE)
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_LOCAL = re.compile(r"[A-Za-z0-9._%+-]{1,64}")
_HEX = frozenset("0123456789abcdefABCDEF")
_DIGITS = frozenset("0123456789")

_PSL = None


def _suffix(name: str) -> str | None:
    """The public suffix of a name by the list (ICANN's part of it: ``github.io`` is a name under
    ``io``, not a suffix), None when its top-level domain is not one."""
    global _PSL
    if _PSL is None:
        from publicsuffixlist import PublicSuffixList

        _PSL = PublicSuffixList(accept_unknown=False, only_icann=True)
    return _PSL.publicsuffix(name)


@dataclass(frozen=True)
class Known:
    """What the caller knows of the organisation: its own domains, and its allowlist as a
    function ``(type, value) -> bool``."""

    own_domains: frozenset = frozenset()
    allowlisted: Callable[[str, str], bool] | None = None

    def own(self, host: str) -> bool:
        return any(host == domain or host.endswith("." + domain) for domain in self.own_domains)


NOTHING_KNOWN = Known()


@dataclass(frozen=True)
class Found:
    """One indicator: its type, its value as the library stores it, why a caller may leave it out
    (``marks``), and the URL it is the host of when it was read from one."""

    type: str
    value: str
    marks: tuple[str, ...] = ()
    host_of: str = ""


# --------------------------------------------------------------------------- #
# One value of each type                                                      #
# --------------------------------------------------------------------------- #
def _stored(kind: str, value: str) -> str | None:
    """The spelling the library stores, or None when it would not keep the value."""
    from .iocs import normalize

    return normalize(kind, value)


def _marked(kind: str, value: str, marks: list[str], known: Known) -> tuple[str, ...]:
    if known.allowlisted is not None and known.allowlisted(kind, value):
        marks.append("allowlisted")
    return tuple(mark for mark in MARKS if mark in marks)


def _ascii_host(host: str) -> str | None:
    """A host name lower-case, without its last dot, in its ``xn--`` form; None when it is not one."""
    host = host.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        return None
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    labels = host.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        return None
    return host


def _public(host: str) -> bool:
    """Whether a host name is one of the public Internet: a name under a known top-level domain."""
    suffix = _suffix(host) if "." in host else None
    return suffix is not None and suffix != host


def _domain_marks(host: str, known: Known) -> list[str]:
    marks = []
    if host.rsplit(".", 1)[-1] in RESERVED_TLDS or any(
        host == name or host.endswith("." + name) for name in BENIGN_DOMAINS
    ):
        marks.append("benign")
    if known.own(host):
        marks.append("own")
    return marks


def domain(text: str, known: Known = NOTHING_KNOWN, *, strict: bool = True) -> tuple[Found | None, str]:
    """A domain, or why the text is not one. ``strict`` adds the rules that tell a name from a
    file, a word of code and a package (left out when a person says "this is a domain", and for
    the host of a URL)."""
    host = _ascii_host(text)
    if host is None or "." not in host:
        return None, "it is not a host name"
    labels = host.split(".")
    if labels[-1] not in RESERVED_TLDS:
        suffix = _suffix(host)
        if suffix is None:
            return None, f'".{labels[-1]}" is not a top-level domain'
        if suffix == host:
            return None, "it is a public suffix, not a name under one"
    if strict:
        if len(labels) == 2 and labels[-1] in FILE_TLDS:
            return None, "it reads as a file name: write it as a URL, or say it is a domain"
        if len(labels) == 2 and labels[0] in CODE_WORDS:
            return None, "it reads as code, not as a name"
        if len(labels) >= 3 and labels[0] in REVERSED_FIRST:
            return None, "it reads as the name of a package, written backwards"
    value = _stored("domain", host)
    if value is None:
        return None, "it reads as a file name"
    return Found("domain", value, _marked("domain", value, _domain_marks(value, known), known)), ""


def address(text: str, known: Known = NOTHING_KNOWN) -> tuple[Found | None, str]:
    """An IPv4 or IPv6 address, or why the text is not one."""
    raw = text.strip().strip("[]").split("%")[0]
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        return None, "it is not an IP address"
    # An IPv4 address written inside an IPv6 one is that address.
    parsed = getattr(parsed, "ipv4_mapped", None) or parsed
    value = _stored("ip", str(parsed))
    if value is None:
        return None, "it is not an IP address"
    public = parsed.is_global and not (parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified)
    marks = [] if public else ["private"]
    return Found("ip", value, _marked("ip", value, marks, known)), ""


def digest(text: str, known: Known = NOTHING_KNOWN) -> tuple[Found | None, str]:
    """An MD5, SHA-1 or SHA-256 digest, or why the text is not one."""
    raw = text.strip()
    if not raw or any(char not in _HEX for char in raw):
        return None, "it is not a hash"
    kind = HASH_TYPES.get(len(raw))
    if kind is None:
        if len(raw) == 128:
            return None, "it is as long as a SHA-512 digest, which Nik does not keep: MD5, SHA-1 and SHA-256 are"
        return None, "a hash is 32, 40 or 64 hex characters"
    if all(char in _DIGITS for char in raw):
        return None, "it is a number, not a hash"
    value = _stored(kind, raw)
    if value is None:
        return None, "it is not a hash"
    marks = ["benign"] if value in EMPTY_DIGESTS else []
    return Found(kind, value, _marked(kind, value, marks, known)), ""


def email(text: str, known: Known = NOTHING_KNOWN) -> tuple[Found | None, str]:
    """An e-mail address, or why the text is not one."""
    raw = text.strip()
    if raw.lower().startswith("mailto:"):
        raw = raw[7:]
    local, at, host = raw.rpartition("@")
    if not at or not _LOCAL.fullmatch(local) or local.startswith(".") or local.endswith("."):
        return None, "it is not an e-mail address"
    name, why = domain(host, known, strict=False)
    if name is None:
        return None, f"it is not an e-mail address: {why}"
    value = _stored("email", f"{local}@{name.value}")
    if value is None:
        return None, "it is not an e-mail address"
    marks = [mark for mark in name.marks if mark != "allowlisted"]
    return Found("email", value, _marked("email", value, marks, known)), ""


def _trimmed(url: str) -> str:
    """A URL without what follows it in a sentence: punctuation, and a closing bracket that
    nothing opened inside it."""
    pairs = {")": "(", "]": "[", "}": "{", ">": "<"}
    counts = {char: url.count(char) for char in "()[]{}<>"}
    end = len(url)
    while end:
        last = url[end - 1]
        if last in ".,;:!?*'\"`\\":
            end -= 1
        elif last in pairs and counts[last] > counts[pairs[last]]:
            counts[last] -= 1
            end -= 1
        else:
            break
    return url[:end]


def url(text: str, known: Known = NOTHING_KNOWN) -> tuple[list[Found], str]:
    """A URL and its host (``[url, host]``, or the URL alone when its host is no indicator), or
    why the text is not one."""
    raw = _trimmed(text.strip())
    try:
        parts = urlsplit(raw)
        port = parts.port
        host = parts.hostname or ""
    except ValueError:
        return [], "it is not a URL"
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return [], "a URL starts with http://, https:// or ftp://"
    if not host:
        return [], "it is a URL without a host"
    marks: list[str] = []
    inside: Found | None
    if ":" in host or host.replace(".", "").isdigit():
        inside, why = address(host, known)
        if inside is None:
            return [], f"the host of the URL is not one: {why}"
        shown = f"[{inside.value}]" if ":" in inside.value else inside.value
        marks += [mark for mark in inside.marks if mark != "allowlisted"]
    else:
        shown = _ascii_host(host) or ""
        if not shown:
            return [], "the host of the URL is not a host name"
        inside, _why = domain(shown, known, strict=False)
        if inside is not None:
            marks += [mark for mark in inside.marks if mark != "allowlisted"]
        elif not _public(shown):
            marks.append("private")  # a name that is no public one: a URL of the inside
    user = parts.netloc.rpartition("@")[0]
    netloc = (f"{user}@" if user else "") + shown + (f":{port}" if port and port != _DEFAULT_PORTS[scheme] else "")
    rest = raw[len(parts.scheme) + 3 + len(parts.netloc) :]
    value = _stored("url", f"{scheme}://{netloc}{rest}")
    if value is None:
        return [], f"it is longer than {VALUE_MAX} characters"
    found = [Found("url", value, _marked("url", value, marks, known))]
    if inside is not None:
        found.append(Found(inside.type, inside.value, inside.marks, host_of=value))
    return found, ""


# --------------------------------------------------------------------------- #
# A text                                                                      #
# --------------------------------------------------------------------------- #
_URL_START = re.compile(r"(?:https?|ftp)://", re.IGNORECASE)
_URL_END = re.compile(r"[\s\"'<>`\x00-\x1f]")
_RUN = re.compile(r"[A-Za-z0-9\u00a1-\uffff._%+@:\-]+")
_DOTTED = re.compile(r"\d+(?:\.\d+)+")


def _urls(text: str) -> list[tuple[int, int]]:
    """Where the URLs of a text are: ``(start, end)``, the end before what cannot be in one."""
    spans = []
    at = 0
    while True:
        start = _URL_START.search(text, at)
        if start is None:
            return spans
        end = _URL_END.search(text, start.end())
        stop = end.start() if end is not None else len(text)
        spans.append((start.start(), stop))
        at = max(stop, start.end())


def _version_before(text: str, start: int) -> bool:
    """Whether what stands before four dotted numbers says they are a version."""
    before = text[max(0, start - 12) : start]
    if _VERSION_WORD.search(before):
        return True
    # ``Chrome/120.0.0.1``: the name of a product, a slash, its version.
    return len(before) >= 2 and before[-1] == "/" and before[-2].isalnum()


def _in_path(text: str, start: int, end: int) -> bool:
    """Whether a name is a step of a path (``C:\\tools\\evil.com``, ``/tmp/update.pl``) or is
    called like a function (``window.open(``). A host after two slashes is not a step of one."""
    before, after = text[max(0, start - 2) : start], text[end : end + 1]
    if before in ("//", "\\\\"):
        return False
    return after in ("(", "\\") or before.endswith(("/", "\\", "$", "~"))


def _piece(piece: str, text: str, start: int, known: Known) -> list[Found]:
    """What a run of letters, digits, dots and hyphens is: an address, a hash or a domain."""
    stripped = piece.lstrip(".-")
    start += len(piece) - len(stripped)
    piece = stripped.rstrip(".-")
    end = start + len(piece)
    if not piece:
        return []
    if _DOTTED.fullmatch(piece):
        if piece.count(".") != 3 or _version_before(text, start):
            return []
        found, _why = address(piece, known)
        return [found] if found else []
    if "-" in piece and all(_DOTTED.fullmatch(part) and part.count(".") == 3 for part in piece.split("-")):
        # A range of addresses, 10.0.0.1-10.0.0.9: both ends.
        ends = [address(part, known)[0] for part in piece.split("-")]
        return [found for found in ends if found]
    if "." not in piece:
        found, _why = digest(piece, known)
        return [found] if found else []
    if any(char in piece for char in "_%+") or _in_path(text, start, end):
        return []
    found, _why = domain(piece, known)
    if found is None:
        # A file called by its hash: 9f86…0a08.exe.
        found, _why = digest(piece.split(".")[0], known)
    return [found] if found else []


def _six(run: str, known: Known) -> Found | None:
    """An IPv6 address written in a run with two colons or more, when it is one and not code."""
    raw = run.split("%")[0].rstrip(".")
    groups = [group for group in raw.split(":") if group]
    if not any(char in _DIGITS for char in raw) and len(groups) < 4:
        return None  # Cafe::Add, std::dec
    found, _why = address(raw, known)
    return found


def find(text: str, known: Known = NOTHING_KNOWN, limit: int = FOUND_MAX) -> list[Found]:
    """Every indicator in a text, in the order met, once each (see the module docstring)."""
    text = refang(str(text or "")[:TEXT_MAX])
    out: dict[tuple[str, str], Found] = {}

    def keep(items: Iterable[Found]) -> None:
        for item in items:
            # The first reading of a value stands.
            if (item.type, item.value) not in out and len(out) < limit:
                out[(item.type, item.value)] = item

    spans = _urls(text)
    at = 0
    for start, stop in [*spans, (len(text), len(text))]:
        for run in _RUN.finditer(text, at, start):
            keep(_run(run.group(), text, run.start(), known))
        if start < stop:
            found, _why = url(text[start:stop], known)
            keep(found)
        at = stop
    return list(out.values())


def _run(run: str, text: str, start: int, known: Known) -> list[Found]:
    if "@" in run:
        left, _, right = run.rpartition("@")
        local = re.split(r"[:@]", left)[-1]
        host = right.split(":")[0].rstrip(".-_")
        found, _why = email(f"{local}@{host}", known)
        return [found] if found else []
    if run.count(":") >= 2:
        six = _six(run, known)
        if six is not None:
            return [six]
    found: list[Found] = []
    offset = 0
    for piece in run.split(":"):
        found += _piece(piece, text, start + offset, known)
        offset += len(piece) + 1
    return found


_WRAPPING = "\"'<>()[]{}` \t\r\n"


def identify(text: str, known: Known = NOTHING_KNOWN, force: str = "") -> tuple[list[Found], str]:
    """What one string is: its indicators (a URL and its host, or the one thing it is; every
    indicator in it when it is a longer text), or nothing and the sentence that says why.

    ``force`` names the type the caller says it is: the string is then that or nothing.
    """
    raw = refang(str(text or "")).strip()
    if not raw:
        return [], "it is empty"
    if len(raw) > TEXT_MAX:
        return [], "it is too long to be read"
    if force:
        return _forced(raw.strip(_WRAPPING), force, known)
    whole = raw.strip(_WRAPPING)
    if _URL_START.match(whole) and not _URL_END.search(whole):
        return url(whole, known)
    why = ""
    if not any(char.isspace() for char in whole):
        if "@" in whole:
            found, why = email(whole, known)
            if found:
                return [found], ""
        else:
            # A bracketed IPv6 address keeps its brackets until it is read: [2001:db8::1]:443.
            one = _one(raw.strip(_WRAPPING.replace("[", "").replace("]", "")), known)
            if one[0]:
                return one
            why = one[1]
    found_all = find(raw, known)
    if found_all:
        return found_all, ""
    return [], why or "no indicator was recognised in it"


def _one(whole: str, known: Known) -> tuple[list[Found], str]:
    """A single word that is an address, a hash or a domain; ``([], "")`` when it is none plainly."""
    bare = whole.strip(".,;")
    # An address with its port, a bracketed IPv6 with one, a name with its port or a path after it.
    if bare.startswith("[") and "]" in bare:
        found, why = address(bare[1:].split("]")[0], known)
        return ([found], "") if found else ([], why)
    bare = bare.strip("[]")
    found = _six(bare, known) if bare.count(":") >= 2 else address(bare, known)[0]
    if found:
        return [found], ""
    host = bare.split("/")[0]
    if host.count(":") == 1:
        host = host.split(":")[0]
    if _DOTTED.fullmatch(host):
        if host.count(".") != 3:
            return [], "it reads as a version number, not as an address"
        found, why = address(host, known)
        return ([found], "") if found else ([], why)
    if all(char in _HEX for char in bare) and len(bare) >= 16:
        found, why = digest(bare, known)
        return ([found], "") if found else ([], why)
    if "." in host and not any(char in host for char in "_%+\\"):
        found, why = domain(host, known)
        return ([found], "") if found else ([], why)
    return [], ""


def _forced(raw: str, kind: str, known: Known) -> tuple[list[Found], str]:
    if kind == "url":
        return url(raw, known)
    if kind == "domain":
        host = raw.split("/")[0]
        found, why = domain(host.split(":")[0] if host.count(":") == 1 else host, known, strict=False)
    elif kind == "ip":
        host = raw.split("/")[0]
        found, why = address(host.split(":")[0] if host.count(":") == 1 else host, known)
    elif kind == "email":
        found, why = email(raw, known)
    elif kind in HASH_TYPES.values():
        found, why = digest(raw, known)
        if found is not None and found.type != kind:
            found, why = None, f"it is not {'an' if kind == 'md5' else 'a'} {kind.upper()} digest"
    else:
        return [], f'"{kind}" is not a type of indicator'
    return ([found], "") if found else ([], why)
