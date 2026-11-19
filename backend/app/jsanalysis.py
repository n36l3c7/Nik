"""Scripts of a scanned page, read as text and checked against signatures.

Nothing is run. Each script the page loaded (its body comes from the visit's
network log) or carried inline is measured (size, entropy, how much of it is
obfuscated), matched against the signatures below, searched for indicators,
and recognised when it is a well-known library.

A signature is a regular expression with a severity and the points it adds
to the scan's score; some need a second expression to match too (a key
listener is a keylogger only if the script also sends something out). Nik
ships the set below; it is kept in ``script_signatures``, where whoever
manages rules turns one off, changes it or adds their own
(``load_signatures``). A signature is matched with a time limit: one that
takes too long on a script is left out of that script, never of the scan.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import regex

from .iocs import normalize, text_iocs

MAX_SCRIPTS = 60
MAX_CODE = 300_000  # characters of one script kept and analysed
MAX_TOTAL = 3_000_000
EXCERPT = 90

_SENDS = (
    r"(?:\bfetch\s*\(|XMLHttpRequest|sendBeacon\s*\(|\$\.(?:post|ajax|get)\s*\(|axios\.(?:post|get)"
    r"|new\s+WebSocket\s*\(|new\s+Image\s*\(\s*\)\s*\.src|\.src\s*=\s*['\"`]https?:)"
)


SEVERITIES = ("high", "medium", "low")
KEY_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,60}$")
PATTERN_MAX = 2000
MATCH_TIMEOUT = 0.5  # seconds one signature is given on one script
_FLAGS = regex.IGNORECASE | regex.DOTALL
CACHE_SECONDS = 5.0


@dataclass(frozen=True)
class Signature:
    id: str
    severity: str  # high | medium | low
    points: int
    title: str
    pattern: Any  # compiled with the ``regex`` module, which can be given a time limit
    also: Any = None  # must match somewhere in the script too
    source: str = ""  # the patterns as they were written
    also_source: str = ""


def _sig(key: str, severity: str, points: int, title: str, pattern: str, also: str | None = None) -> Signature:
    return Signature(
        key,
        severity,
        points,
        title,
        regex.compile(pattern, _FLAGS),
        regex.compile(also, _FLAGS) if also else None,
        pattern,
        also or "",
    )


SIGNATURES: tuple[Signature, ...] = (
    _sig("exfil.telegram", "high", 30, "Data sent to a Telegram bot", r"api\.telegram\.org/bot[\w:-]*"),
    _sig("exfil.discord", "high", 30, "Data sent to a Discord webhook", r"discord(?:app)?\.com/api/webhooks/[\w/-]*"),
    _sig(
        "grabber.credentials",
        "high",
        25,
        "A password field is read and the script sends data out",
        r"(?:querySelector(?:All)?|getElementById|getElementsByName)\s*\(\s*['\"`][^'\"`]{0,60}"
        r"(?:pass|pwd|i0118)[^'\"`]{0,60}['\"`]\s*\)(?:\s*\[\s*0\s*\])?\s*\.value"
        r"|input\[type=[\\'\"]*password[\\'\"]*\][^;]{0,80}\.value",
        _SENDS,
    ),
    _sig(
        "keylogger",
        "high",
        20,
        "Key presses are listened to and the script sends data out",
        r"(?:addEventListener\s*\(\s*['\"`]key(?:down|press|up)['\"`]|\bonkey(?:down|press|up)\s*=)",
        _SENDS,
    ),
    _sig(
        "exfil.form-service",
        "medium",
        10,
        "Form contents go to a third-party form service",
        r"(?:formspree\.io|formsubmit\.co|submit-form\.com|getform\.io|api\.emailjs\.com|formcarry\.com)[\w./-]*",
    ),
    _sig(
        "smuggling.html",
        "high",
        20,
        "A file is assembled in the page and saved (HTML smuggling)",
        r"new\s+Blob\s*\(\s*\[[^\]]{0,200}\][\s\S]{0,400}?(?:msSaveOrOpenBlob|createObjectURL)[\s\S]{0,300}?\.download\s*=",
    ),
    _sig(
        "miner",
        "high",
        25,
        "Cryptocurrency miner",
        r"coinhive|cryptonight|coinimp|deepminer|jsecoin|stratum\+tcp://|\bminer\.start\s*\(",
    ),
    _sig(
        "drainer.wallet",
        "high",
        25,
        "A crypto wallet is asked to approve transfers",
        r"(?:eth_requestAccounts|wallet_switchEthereumChain)[\s\S]{0,4000}?(?:setApprovalForAll|increaseAllowance|\bpermit\b)",
    ),
    _sig(
        "obf.eval-decode",
        "medium",
        10,
        "Code decoded at run time and executed",
        r"(?:\beval|\bFunction|setTimeout|setInterval)\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(",
    ),
    _sig(
        "obf.packer",
        "medium",
        10,
        "Packed with Dean Edwards' packer",
        r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)",
    ),
    _sig(
        "obf.string-array",
        "medium",
        10,
        "Obfuscated: string array with a decoder (javascript-obfuscator)",
        r"(?:var|const|let)\s+_0x[a-f0-9]{3,8}\s*=\s*\[|function\s+_0x[a-f0-9]{3,8}\s*\(\s*_0x[a-f0-9]{3,8}",
    ),
    _sig("obf.jsfuck", "medium", 10, "Obfuscated with symbols only (JSFuck)", r"[\[\]()!+]{300,}"),
    _sig(
        "obf.document-write",
        "medium",
        10,
        "Page content written from encoded text",
        r"document\.write(?:ln)?\s*\(\s*(?:unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\(",
    ),
    _sig(
        "redirect.encoded",
        "medium",
        10,
        "Redirect to an address that is decoded at run time",
        r"location(?:\.href|\.replace|\.assign)?\s*[=(]\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(",
    ),
    _sig(
        "anti-debug",
        "medium",
        10,
        "Hinders inspection with the developer tools",
        r"setInterval\s*\(\s*(?:function\s*\(\s*\)\s*\{|\(\s*\)\s*=>\s*\{?)\s*debugger"
        r"|\(function\s*\(\s*\)\s*\{\s*\}\s*\.constructor\s*\(\s*['\"`]debugger"
        r"|devtools?(?:-detect|detector|\.isOpen|Open)",
    ),
    _sig(
        "evasion.automation",
        "low",
        5,
        "Checks whether the browser is automated",
        r"navigator\.webdriver|HeadlessChrome|\b_?phantom\b|__nightmare|callPhantom",
    ),
    _sig(
        "recon.ip-lookup",
        "low",
        5,
        "Looks up the visitor's address or location",
        r"(?:api(?:64)?\.ipify\.org|ipinfo\.io|ip-api\.com|geolocation-db\.com|ipapi\.co|api\.db-ip\.com)[\w./?=&-]*",
    ),
    _sig(
        "clipboard.write",
        "low",
        5,
        "Writes to the clipboard",
        r"navigator\.clipboard\.writeText\s*\(|document\.execCommand\s*\(\s*['\"`]copy['\"`]",
    ),
)
POINTS = {signature.id: signature.points for signature in SIGNATURES}

# A banner near the top, or the host that serves it, names a well-known library.
_LIBRARIES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        ("jQuery", r"jQuery (?:JavaScript Library )?v?(\d+\.\d+(?:\.\d+)?)"),
        ("Bootstrap", r"Bootstrap v(\d+\.\d+(?:\.\d+)?)"),
        ("React", r"@license React\b|react(?:-dom)?\.production\.min\.js"),
        ("Vue.js", r"Vue\.js v(\d+\.\d+(?:\.\d+)?)"),
        ("AngularJS", r"AngularJS v(\d+\.\d+(?:\.\d+)?)"),
        ("Lodash", r"lodash(?:\.js)? (\d+\.\d+(?:\.\d+)?)|@license\s+Lodash"),
        ("Moment.js", r"moment\.js|//! moment"),
        ("Popper", r"@popperjs/core v(\d+\.\d+(?:\.\d+)?)"),
        ("Modernizr", r"modernizr v?(\d+\.\d+(?:\.\d+)?)"),
        ("Font Awesome", r"Font Awesome (?:Free )?(\d+\.\d+(?:\.\d+)?)"),
    )
)
_LIBRARY_HOSTS = {
    "www.googletagmanager.com": "Google Tag Manager",
    "www.google-analytics.com": "Google Analytics",
    "www.google.com": "Google (reCAPTCHA)",
    "www.gstatic.com": "Google static",
    "challenges.cloudflare.com": "Cloudflare Turnstile",
    "static.cloudflareinsights.com": "Cloudflare Insights",
    "connect.facebook.net": "Facebook SDK",
    "js.hcaptcha.com": "hCaptcha",
}
_ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
_HEX_NAMES = re.compile(r"\b_0x[a-f0-9]{3,8}\b")


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return round(-sum(n / total * math.log2(n / total) for n in counts.values()), 2)


def obfuscation(code: str) -> int:
    """How much of the script looks obfuscated, 0 to 100."""
    if len(code) < 200:
        return 0
    escaped = sum(len(m.group()) for m in _ESCAPES.finditer(code))
    names = sum(len(m.group()) for m in _HEX_NAMES.finditer(code))
    return min(100, round((escaped + names * 3) / len(code) * 100))


def library(code: str, host: str) -> str | None:
    if host in _LIBRARY_HOSTS:
        return _LIBRARY_HOSTS[host]
    head = code[:1500]
    for name, pattern in _LIBRARIES:
        match = pattern.search(head)
        if match:
            version = next((g for g in match.groups() if g), None) if match.groups() else None
            return f"{name} {version}" if version else name
    return None


def findings(
    code: str, signatures: Iterable[Signature] | None = None, timed_out: list[str] | None = None
) -> list[dict[str, Any]]:
    """Every signature that matches, with where and what: ``{id, severity,
    points, title, start, end, line, excerpt}`` (the first match of each).

    ``signatures`` are the ones in use (``load_signatures(db)``); Nik's own when left out. A signature
    that does not finish in ``MATCH_TIMEOUT`` on this script is left out of it and named in ``timed_out``."""
    found = []
    for signature in SIGNATURES if signatures is None else signatures:
        try:
            match = signature.pattern.search(code, timeout=MATCH_TIMEOUT)
            if not match or (signature.also is not None and not signature.also.search(code, timeout=MATCH_TIMEOUT)):
                continue
        except TimeoutError:
            if timed_out is not None:
                timed_out.append(signature.id)
            continue
        start, end = match.start(), min(match.end(), match.start() + 400)
        left = max(0, start - 20)
        found.append(
            {
                "id": signature.id,
                "severity": signature.severity,
                "points": signature.points,
                "title": signature.title,
                "start": start,
                "end": end,
                "line": code.count("\n", 0, start) + 1,
                "excerpt": " ".join(code[left : left + EXCERPT].split()),
            }
        )
    order = {"high": 0, "medium": 1, "low": 2}
    found.sort(key=lambda f: (order[f["severity"]], -f["points"], f["start"]))
    return found


def indicators(code: str, limit: int = 40) -> list[dict[str, str]]:
    seen: dict[tuple[str, str], None] = {}
    for kind, raw in text_iocs(code):
        value = normalize(kind, raw)
        if value and kind in ("url", "domain", "ip", "email"):
            seen.setdefault((kind, value))
        if len(seen) >= limit:
            break
    return [{"type": kind, "value": value} for kind, value in seen]


def analyse(
    code: str,
    *,
    kind: str,
    url: str = "",
    host: str = "",
    page_host: str = "",
    signatures: Iterable[Signature] | None = None,
) -> dict[str, Any]:
    """What the Scripts tab lists for one script (without its code)."""
    raw = code.encode("utf-8", "replace")
    kept = code[:MAX_CODE]
    known = library(kept, host)
    slow: list[str] = []
    found = findings(kept, signatures, slow)
    score = obfuscation(kept)
    if score >= 25 and not any(f["id"].startswith("obf.") for f in found) and not known:
        found.append(
            {
                "id": "obf.heavy",
                "severity": "medium",
                "points": 10,
                "title": f"Obfuscated: {score} % of the script is escaped text or generated names",
                "start": 0,
                "end": 0,
                "line": 1,
                "excerpt": " ".join(kept[:EXCERPT].split()),
            }
        )
    worst = found[0]["severity"] if found else None
    return {
        "kind": kind,
        "url": url[:2000],
        "host": host,
        "thirdParty": bool(host and page_host and host != page_host and not host.endswith("." + page_host)),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "entropy": entropy(kept[:100_000]),
        "obfuscation": score,
        "library": known,
        "truncated": len(code) > MAX_CODE,
        "findings": found,
        "severity": worst,
        "iocs": indicators(kept),
        # The signatures that took too long on this script and were left out of it.
        **({"timedOut": slow} if slow else {}),
    }


def score_findings(scripts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The scan findings the scripts add: one per signature, however many
    scripts match it, as ``{id, points, severity, text}``."""
    by_signature: dict[str, dict[str, Any]] = {}
    for index, script in enumerate(scripts):
        name = script.get("url") or f"inline script {index + 1}"
        for finding in script.get("findings") or []:
            entry = by_signature.setdefault(
                finding["id"],
                {
                    "id": f"script:{finding['id']}",
                    "points": finding["points"],
                    "severity": finding["severity"],
                    "title": finding["title"],
                    "where": [],
                },
            )
            entry["where"].append(str(name).rsplit("/", 1)[-1][:60] or str(name)[:60])
    out = []
    for entry in by_signature.values():
        where = entry.pop("where")
        title = entry.pop("title")
        more = f" and {len(where) - 1} more" if len(where) > 1 else ""
        out.append({**entry, "text": f"script {where[0]}{more}: {title[0].lower()}{title[1:]}"})
    return out


# --------------------------------------------------------------------------- #
# The signatures in use: Nik's own, as changed here, and the ones added here  #
# --------------------------------------------------------------------------- #
class SignatureError(ValueError):
    """A signature that cannot be saved: a sentence safe to show, and the field it is about."""

    def __init__(self, message: str, field: str = ""):
        super().__init__(message)
        self.message = message
        self.field = field


BUILTIN = {signature.id: signature for signature in SIGNATURES}
# Long texts a pattern is tried on before it is saved: the shapes that make a careless expression
# take for ever (one character repeated, nested brackets, quotes never closed, a minified line).
_ADVERSARIAL = (
    "a" * 40_000 + "!",
    " " * 40_000 + "x",
    "(" * 20_000 + ")" * 20_000,
    "'" + "\\'" * 20_000,
    "aA1_" * 10_000 + "\n",
    'var a="' + "x" * 30_000 + '";' + "b=a+a;" * 2_000,
    "0x41," * 8_000 + "\n" + "<" * 8_000,
)


def clean(body: dict[str, Any]) -> dict[str, Any]:
    """What a signature is saved with, checked. Raises ``SignatureError``."""
    key = str(body.get("key") or "").strip()
    if not KEY_RE.match(key):
        raise SignatureError(
            "A key is a lower-case letter, then lower-case letters, digits, dots, - or _ (2 to 61)", "key"
        )
    title = " ".join(str(body.get("title") or "").split())[:200]
    if not title:
        raise SignatureError("A signature needs a title: what it says of a script that matches", "title")
    severity = str(body.get("severity") or "")
    if severity not in SEVERITIES:
        raise SignatureError("A severity is high, medium or low", "severity")
    points = body.get("points")
    if isinstance(points, bool) or not isinstance(points, int) or not 0 <= points <= 100:
        raise SignatureError("The points are a whole number from 0 to 100", "points")
    pattern = str(body.get("pattern") or "")
    also = str(body.get("also") or "")
    if not pattern.strip():
        raise SignatureError("A signature needs a pattern", "pattern")
    for name, source in (("pattern", pattern), ("also", also)):
        if len(source) > PATTERN_MAX:
            raise SignatureError(f"A pattern is {PATTERN_MAX} characters at most", name)
        if source:
            problem = pattern_problem(source)
            if problem:
                raise SignatureError(problem, name)
    return {
        "key": key,
        "title": title,
        "severity": severity,
        "points": points,
        "pattern": pattern,
        "also": also,
        "enabled": bool(body.get("enabled", True)),
    }


def pattern_problem(source: str) -> str | None:
    """Why a pattern cannot be used: it does not compile, it matches nothing at all of a text (the
    empty text), or it takes too long on a long hostile one."""
    try:
        compiled = regex.compile(source, _FLAGS)
    except regex.error as error:
        return f"The pattern cannot be read: {error}"
    if compiled.search("") is not None:
        return "The pattern matches an empty text: it would match every script"
    for text in _ADVERSARIAL:
        try:
            compiled.search(text, timeout=MATCH_TIMEOUT)
        except TimeoutError:
            return "The pattern takes too long on a long text: it would stall the analysis of a page"
    return None


def compiled(definition: dict[str, Any]) -> Signature:
    return _sig(
        definition["key"],
        definition["severity"],
        int(definition["points"]),
        definition["title"],
        definition["pattern"],
        definition.get("also") or None,
    )


def builtin_definition(key: str) -> dict[str, Any] | None:
    """A signature of Nik's own, as it ships."""
    signature = BUILTIN.get(key)
    if signature is None:
        return None
    return {
        "key": signature.id,
        "title": signature.title,
        "severity": signature.severity,
        "points": signature.points,
        "pattern": signature.source,
        "also": signature.also_source,
        "enabled": True,
    }


def changed(row: Any) -> bool:
    """Whether a signature of Nik's own was changed here (anything but its being on or off)."""
    shipped = builtin_definition(row.key)
    if shipped is None:
        return False
    return any(getattr(row, name) != shipped[name] for name in ("title", "severity", "points", "pattern", "also"))


def out(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "key": row.key,
        "title": row.title,
        "severity": row.severity,
        "points": row.points,
        "pattern": row.pattern,
        "also": row.also or "",
        "enabled": bool(row.enabled),
        "builtin": bool(row.builtin),
        "changed": bool(row.builtin) and changed(row),
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


def seed(db: Any, now: str) -> int:
    """Add the signatures Nik ships that are missing, bring up to date those nobody changed here, and
    let go of those a release no longer ships (the caller commits)."""
    from sqlalchemy import select

    from .core.models import ScriptSignature

    held = {row.key: row for row in db.scalars(select(ScriptSignature)).all()}
    count = 0
    for key in BUILTIN:
        shipped = builtin_definition(key)
        row = held.get(key)
        if row is None:
            db.add(
                ScriptSignature(
                    id=hashlib.sha256(f"script-signature:{key}".encode()).hexdigest()[:32],
                    key=key,
                    title=shipped["title"],
                    severity=shipped["severity"],
                    points=shipped["points"],
                    pattern=shipped["pattern"],
                    also=shipped["also"],
                    enabled=True,
                    builtin=True,
                    updated_at=now,
                    updated_by="nik",
                )
            )
            count += 1
        elif row.builtin and row.updated_by == "nik" and changed(row):
            # Nobody changed it here: it follows the release.
            for name in ("title", "severity", "points", "pattern", "also"):
                setattr(row, name, shipped[name])
            row.updated_at = now
            count += 1
        elif not row.builtin:
            row.builtin = True  # someone had made one with the key a release now ships: it is kept, as an override
            count += 1
    for key, row in held.items():
        if row.builtin and key not in BUILTIN:
            row.builtin = False  # no longer shipped: it stays, as one of yours
            count += 1
    if count:
        clear_cache()
    return count


_cache: tuple[float, tuple[Signature, ...]] | None = None


def clear_cache() -> None:
    global _cache
    _cache = None


def load_signatures(db: Any) -> tuple[Signature, ...]:
    """The signatures in use, compiled: the rows of ``script_signatures`` that are on. Kept for a few
    seconds, and dropped when this process changes one; Nik's own when the table is empty."""
    global _cache
    if _cache is not None and time.monotonic() - _cache[0] < CACHE_SECONDS:
        return _cache[1]
    from sqlalchemy import select

    from .core.models import ScriptSignature

    rows = db.scalars(select(ScriptSignature).order_by(ScriptSignature.key)).all()
    if not rows:
        found = SIGNATURES
    else:
        kept = []
        for row in rows:
            if not row.enabled:
                continue
            try:
                kept.append(compiled(out(row)))
            except regex.error:
                continue  # a pattern a newer regex module no longer reads: left out rather than breaking a scan
        found = tuple(kept)
    _cache = (time.monotonic(), found)
    return found


def try_on(definition: dict[str, Any], code: str) -> dict[str, Any]:
    """What a signature finds in a piece of code: ``{matches, finding?, timedOut}``."""
    slow: list[str] = []
    found = findings(code[:MAX_CODE], [compiled(definition)], slow)
    return {"matches": bool(found), "finding": found[0] if found else None, "timedOut": bool(slow)}
