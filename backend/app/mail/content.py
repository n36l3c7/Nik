"""The message body as an analyst should see it.

- ``safe_html``: the HTML body cleaned with nh3 (ammonia): no scripts, event
  handlers, iframes, objects or forms that could run or post anything; inline
  ``cid:`` images become ``data:`` URIs; text hidden from the reader (font
  size 0, ``display:none``, white on white…) is revealed and outlined in red.
  The browser shows it in a sandboxed frame whose Content-Security-Policy
  blocks every network request, so remote images stay unloaded until the
  analyst asks (and tracking pixels stay blocked even then).
- ``remote_images``: each remote image, flagged when it is a tracking pixel.
- ``pressure``: phrases of urgency, payment and credential requests (BEC).
- ``qr_codes``: the content of the QR codes in images (quishing).
"""

from __future__ import annotations

import base64
import io
import re
from html.parser import HTMLParser
from typing import Any

MAX_INLINE_IMAGE = 2 * 1024 * 1024

ALLOWED_TAGS = {
    "a", "abbr", "address", "b", "big", "blockquote", "br", "caption", "center", "cite", "code", "col",
    "colgroup", "dd", "del", "div", "dl", "dt", "em", "font", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i",
    "img", "ins", "kbd", "li", "mark", "ol", "p", "pre", "q", "s", "small", "span", "strike", "strong", "style",
    "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "tt", "u", "ul", "label", "button",
}  # fmt: skip
COMMON_ATTRIBUTES = {
    "style", "class", "align", "valign", "width", "height", "bgcolor", "color", "border", "cellpadding",
    "cellspacing", "dir", "title", "colspan", "rowspan", "face", "size", "lang",
}  # fmt: skip

_HIDDEN = re.compile(
    r"font-size\s*:\s*0(?:px|pt|em|%)?\s*(?:;|$|!)|display\s*:\s*none|visibility\s*:\s*hidden|"
    r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|max-height\s*:\s*0|(?<![-\w])color\s*:\s*(?:#fff(?:fff)?|white|transparent)\b",
    re.IGNORECASE,
)
_WHITE_ONLY = re.compile(r"^(?<![-\w])color\s*:", re.IGNORECASE)


def _is_hidden(style: str) -> bool:
    """Text the reader cannot see. White text counts only without a background
    in the same style (a white button label on a coloured button is fine)."""
    matches = [m.group(0) for m in _HIDDEN.finditer(style)]
    if not matches:
        return False
    if all(_WHITE_ONLY.match(m) for m in matches):
        return "background" not in style.lower()
    return True


_REVEAL = "outline:1px dashed #cf222e!important;color:#cf222e!important;font-size:11px!important;"

TRACKING_HINTS = re.compile(
    r"(?:/o\.gif|/open|/pixel|/track|/beacon|/wf/open|/e2t/|utm_|[?&](?:u|uid|email|e|rcpt)=|%40|@)", re.IGNORECASE
)

PRESSURE = {
    "urgency": re.compile(
        r"\b(?:urgent[ei]?|urgently|immediately|immediatamente|entro (?:24|48) ore|within (?:24|48) hours|"
        r"as soon as possible|il prima possibile|final notice|ultimo avviso|scadenza|expires? today|scade oggi)\b",
        re.IGNORECASE,
    ),
    "account threat": re.compile(
        r"\b(?:suspended|sospes[oa]|sospensione|will be (?:closed|deactivated|locked)|"
        r"verr[àa] (?:chius|bloccat|disattivat)\w*|"
        r"unusual (?:sign-in|activity)|accesso (?:anomalo|sospetto))\b",
        re.IGNORECASE,
    ),
    "credentials": re.compile(
        r"\b(?:verify your (?:account|identity|password)|verifica (?:il tuo|i tuoi|la tua) \w+|confirm your password|"
        r"conferma (?:la )?password|log ?in to (?:view|confirm)|accedi per (?:visualizzare|confermare)|"
        r"reset your password)\b",
        re.IGNORECASE,
    ),
    "payment": re.compile(
        r"\b(?:wire transfer|bonifico|iban|bank details|coordinate bancarie|change (?:of|in) (?:bank|payment) details|"
        r"nuov[oe] (?:iban|coordinate)|outstanding invoice|fattura (?:scaduta|non pagata|in scadenza)|unpaid invoice|"
        r"payment (?:overdue|failed))\b",
        re.IGNORECASE,
    ),
    "gift cards": re.compile(
        r"\b(?:gift ?cards?|buoni regalo|itunes cards?|google play cards?|steam cards?)\b", re.IGNORECASE
    ),
    "secrecy": re.compile(
        r"\b(?:keep (?:this )?confidential|riservat[oa]|don't tell|non dirlo|i'?m in a meeting|sono in riunione)\b",
        re.IGNORECASE,
    ),
}


class _Images(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.images: list[dict[str, Any]] = []

    def handle_starttag(self, tag, attrs):
        if tag != "img":
            return
        attrs = dict(attrs)
        src = (attrs.get("src") or "").strip()
        if not src.lower().startswith(("http://", "https://", "//")):
            return
        size = []
        for key in ("width", "height"):
            try:
                size.append(int(re.sub(r"\D", "", attrs.get(key) or "") or 99))
            except ValueError:
                size.append(99)
        style = (attrs.get("style") or "").lower()
        tiny = all(v <= 2 for v in size) or bool(re.search(r"(?:width|height)\s*:\s*[0-2]px", style))
        self.images.append(
            {
                "url": src if not src.startswith("//") else "https:" + src,
                "tracking": tiny or bool(TRACKING_HINTS.search(src)),
                "reason": "1×1 image" if tiny else ("tracking parameters" if TRACKING_HINTS.search(src) else ""),
            }
        )


def remote_images(html: str | None) -> list[dict[str, Any]]:
    if not html:
        return []
    parser = _Images()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 - malformed HTML: keep what was read
        pass
    seen, out = set(), []
    for image in parser.images:
        if image["url"] not in seen:
            seen.add(image["url"])
            out.append(image)
    return out


def safe_html(html: str | None, inline: dict[str, tuple[str, bytes]]) -> tuple[str, int]:
    """Sanitised HTML and the number of elements with hidden text."""
    if not html:
        return "", 0
    import nh3

    hidden = 0

    def attribute_filter(tag: str, attribute: str, value: str) -> str | None:
        nonlocal hidden
        if attribute == "style" and _is_hidden(value):
            hidden += 1
            return value + ";" + _REVEAL
        if tag == "img" and attribute == "src" and value.lower().startswith("cid:"):
            found = inline.get(value[4:].strip("<>").lower())
            if found and len(found[1]) <= MAX_INLINE_IMAGE and found[0].startswith("image/"):
                return f"data:{found[0]};base64,{base64.b64encode(found[1]).decode()}"
            return None
        return value

    attributes = {"*": COMMON_ATTRIBUTES, "a": {"href", "name", "target"}, "img": {"src", "alt"}}
    cleaned = nh3.clean(
        html,
        tags=ALLOWED_TAGS,
        clean_content_tags={"script", "noscript", "iframe", "object", "embed", "template"},
        attributes=attributes,
        url_schemes={"http", "https", "mailto", "data", "cid", "tel"},
        attribute_filter=attribute_filter,
        link_rel="noopener noreferrer nofollow",
        strip_comments=True,
    )
    return cleaned, hidden


def pressure(text: str) -> list[dict[str, Any]]:
    """Phrases of social-engineering pressure found in the text."""
    found = []
    for label, pattern in PRESSURE.items():
        matches = sorted({m.group(0).strip() for m in pattern.finditer(text or "")})
        if matches:
            found.append({"kind": label, "phrases": matches[:5]})
    return found


def html_to_text(html: str | None) -> str:
    if not html:
        return ""
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    import html as htmllib

    return re.sub(r"[ \t]+", " ", htmllib.unescape(text)).strip()


def qr_codes(data: bytes) -> list[str]:
    """Text of the QR codes (and other 2-D codes) in an image."""
    try:
        import zxingcpp
        from PIL import Image
    except ImportError:  # pragma: no cover - both are requirements
        return []
    try:
        with Image.open(io.BytesIO(data)) as image:
            # The size is in the header: checked before the pixels are decoded,
            # which is what a small file declaring a huge image is built to make costly.
            if image.width * image.height > 40_000_000:
                return []
            image.load()
            results = zxingcpp.read_barcodes(image.convert("RGB"))
    except Exception:  # noqa: BLE001 - not an image Pillow can read
        return []
    return [r.text for r in results if r.text]
