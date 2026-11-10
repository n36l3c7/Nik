"""Links of a message: where they really go, and what is wrong with them.

Nothing here fetches a URL. Each link is read from the HTML (``href``, form
``action``) or the text, then:

- unwrapped when a security gateway rewrote it and the original is in the
  URL itself (Microsoft SafeLinks, Proofpoint URLDefense v1–v3, Google and
  Facebook redirects, Barracuda); Mimecast's rewritten links are opaque and
  are only marked as such;
- compared with the text shown to the reader (``text ≠ target`` when the
  text looks like a URL or a domain on another host);
- checked for punycode, lookalikes of well-known brands and of your own
  domains, shorteners, IP hosts, ``@`` in the authority, ``data:`` and
  ``javascript:``, throwaway TLDs, and pages hosted on generic cloud
  services that phishing kits favour.
"""

from __future__ import annotations

import base64
import html as htmllib
import ipaddress
import re
import unicodedata
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

URL_IN_TEXT = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\)\]]+", re.IGNORECASE)
MAX_LINKS = 500

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in", "qrco.de", "bl.ink", "short.io", "trib.al",
}  # fmt: skip
CLOUD_HOSTING = (
    "sharepoint.com", "onedrive.live.com", "1drv.ms", "docs.google.com", "drive.google.com", "sites.google.com",
    "forms.gle", "firebaseapp.com", "web.app", "appspot.com", "storage.googleapis.com", "blob.core.windows.net",
    "azurewebsites.net", "workers.dev", "pages.dev", "r2.dev", "netlify.app", "vercel.app", "glitch.me",
    "github.io", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "wixsite.com", "weebly.com", "square.site",
    "notion.site", "canva.site", "dropboxusercontent.com", "s3.amazonaws.com", "herokuapp.com", "repl.co",
)  # fmt: skip
RISKY_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "su", "click", "buzz", "monster", "rest", "zip", "mov",
    "country", "kim", "work", "link", "support", "cam", "icu", "cyou", "sbs", "quest",
}  # fmt: skip
BRANDS = (
    "microsoft", "office", "office365", "outlook", "onedrive", "sharepoint", "live", "teams", "azure", "google",
    "gmail", "apple", "icloud", "paypal", "amazon", "netflix", "facebook", "instagram", "linkedin", "dhl", "fedex",
    "ups", "docusign", "dropbox", "adobe", "wetransfer", "poste", "posteitaliane", "intesasanpaolo", "unicredit",
    "bancobpm", "fineco", "nexi", "aruba", "pec", "agenziaentrate", "inps", "spid",
)  # fmt: skip

# Characters that read as Latin letters (a subset of Unicode confusables).
_CONFUSABLE = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
        "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ν": "v", "ο": "o", "α": "a", "ε": "e", "ı": "i", "ł": "l",
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
    }
)  # fmt: skip


def skeleton(label: str) -> str:
    """A label with lookalike characters folded: ``micros0ft`` → ``microsoft``."""
    text = unicodedata.normalize("NFKD", label.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch)).translate(_CONFUSABLE)
    return text.replace("rn", "m").replace("vv", "w").replace("cl", "d").replace("-", "")


def _distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, row[0] = row[0], i
        for j, cb in enumerate(b, 1):
            prev, row[j] = row[j], min(row[j] + 1, row[j - 1] + 1, prev + (ca != cb))
    return row[-1]


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _decode_host(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


# Registrable domains the brands really use (never lookalikes of themselves).
GENUINE = {
    "microsoft.com", "microsoftonline.com", "office.com", "office.net", "office365.com", "outlook.com", "live.com",
    "sharepoint.com", "onedrive.com", "windows.net", "azure.com", "teams.microsoft.com", "google.com", "gmail.com",
    "googleusercontent.com", "gstatic.com", "apple.com", "icloud.com", "paypal.com", "paypal.it", "amazon.com",
    "amazon.it", "netflix.com", "facebook.com", "instagram.com", "linkedin.com", "dhl.com", "dhl.it", "fedex.com",
    "ups.com", "docusign.com", "docusign.net", "dropbox.com", "adobe.com", "wetransfer.com", "poste.it",
    "posteitaliane.it", "intesasanpaolo.com", "unicredit.it", "bancobpm.it", "fineco.it", "nexi.it", "aruba.it",
    "agenziaentrate.gov.it", "inps.it", "spid.gov.it",
}  # fmt: skip


def lookalike(host: str, own_domains: list[str], org_domain) -> str | None:
    """The brand or own domain a host imitates, or None.

    Three signals on the registrable label (``login-micros0ft365`` of
    ``login-micros0ft365.com``): lookalike characters that fold into a brand
    (``micros0ft``, ``rnicrosoft``); one letter away from a brand
    (``paypai``); the brand as a hyphen-separated token (``microsoft-login``).
    The brands' real domains and your own are never flagged.
    """
    if not host:
        return None
    registrable = org_domain(host)
    if registrable in GENUINE or registrable in own_domains:
        return None
    label = registrable.split(".")[0].lower()
    folded = skeleton(_decode_host(label))
    tokens = [skeleton(t) for t in re.split(r"[-_]", _decode_host(label)) if t]
    for brand in (*BRANDS, *(d.split(".")[0].lower() for d in own_domains if d)):
        if len(tokens) > 1 and any(t == brand or t.rstrip("0123456789") == brand for t in tokens):
            return brand  # brand-login, secure-brand365
        if len(brand) < 4:
            continue
        if brand in folded and brand not in label:
            return brand  # hidden by lookalike characters
        if len(label) >= 5 and _distance(folded, brand) == 1:
            return brand  # one letter away
    return None


# --------------------------------------------------------------------------- #
# Unwrapping                                                                  #
# --------------------------------------------------------------------------- #
def _proofpoint_v3(url: str) -> str | None:
    match = re.match(r"https://urldefense\.com/v3/__(.+?)__;([^!]*)!", url)
    if not match:
        return None
    target, encoded = match.group(1), match.group(2)
    try:
        replacements = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8", "replace")
    except ValueError:
        replacements = ""
    out, used = [], iter(replacements)
    for char in target:
        out.append(next(used, "*") if char == "*" else char)
    return "".join(out)


def _on(host: str, domain: str) -> bool:
    """The host is ``domain`` or one of its subdomains (not merely containing it)."""
    return host == domain or host.endswith("." + domain)


def unwrap(url: str) -> tuple[str, str | None]:
    """``(original URL, gateway)``; the URL itself and None when not wrapped."""
    host = host_of(url)
    query = parse_qs(urlsplit(url).query) if "?" in url else {}
    if _on(host, "safelinks.protection.outlook.com") and "url" in query:
        return query["url"][0], "Microsoft SafeLinks"
    if host == "urldefense.com" and "/v3/" in url:
        original = _proofpoint_v3(url)
        if original:
            return original, "Proofpoint URLDefense"
    if host in ("urldefense.proofpoint.com", "urldefense.com") and "u" in query:
        encoded = query["u"][0]
        if "/v2/" in url:
            encoded = encoded.replace("-", "%").replace("_", "/")
        return unquote(encoded), "Proofpoint URLDefense"
    if _on(host, "google.com") and urlsplit(url).path == "/url" and ("q" in query or "url" in query):
        return (query.get("q") or query["url"])[0], "Google redirect"
    if host in ("l.facebook.com", "lm.facebook.com") and "u" in query:
        return query["u"][0], "Facebook redirect"
    if host == "linkprotect.cudasvc.com" and "a" in query:
        return query["a"][0], "Barracuda Link Protection"
    if _on(host, "mimecast.com") and urlsplit(url).path.startswith("/s/"):
        return url, "Mimecast (opaque: the original cannot be read from the link)"
    return url, None


# --------------------------------------------------------------------------- #
# Extraction                                                                  #
# --------------------------------------------------------------------------- #
class _Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._open: list[dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            link = {"url": attrs["href"].strip(), "text": "", "kind": "link"}
            self.links.append(link)
            self._open.append(link)
        elif tag == "form" and attrs.get("action"):
            self.links.append({"url": attrs["action"].strip(), "text": "", "kind": "form"})
        elif tag in ("area",) and attrs.get("href"):
            self.links.append({"url": attrs["href"].strip(), "text": "", "kind": "link"})

    def handle_endtag(self, tag):
        if tag == "a" and self._open:
            self._open.pop()

    def handle_data(self, data):
        if self._open:
            self._open[-1]["text"] += data


def extract(html: str | None, text: str | None) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    if html:
        parser = _Anchors()
        try:
            parser.feed(html)
        except Exception:  # noqa: BLE001 - malformed HTML: keep what was read
            pass
        found += parser.links
    # A URL written as the text of a link is what the reader sees, not where
    # the link goes: it is judged as that link's text, not listed again.
    shown = {" ".join(link["text"].split()) for link in found if link["text"]}
    targets = {link["url"] for link in found}
    for source in (text or "", re.sub(r"<[^>]+>", " ", htmllib.unescape(html or ""))):
        for match in URL_IN_TEXT.finditer(source):
            url = match.group().rstrip(".,;")
            if url in shown and url not in targets:
                continue
            found.append({"url": url, "text": "", "kind": "text"})
    seen, out = set(), []
    for link in found:
        key = (link["url"], " ".join(link["text"].split()))
        if key in seen or link["url"].startswith(("mailto:", "#", "cid:", "tel:")):
            continue
        seen.add(key)
        out.append({**link, "text": " ".join(link["text"].split())[:300]})
    return out[:MAX_LINKS]


_TEXT_URL = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)", re.IGNORECASE)


def analyse(links: list[dict[str, str]], own_domains: list[str], org_domain, allowlist=None) -> list[dict[str, Any]]:
    out = []
    for link in links:
        raw = link["url"]
        lower = raw.lower()
        findings: list[dict[str, str]] = []
        target, gateway = unwrap(raw)
        host = host_of(target)
        decoded = _decode_host(host)
        if lower.startswith(("javascript:", "data:", "vbscript:")):
            findings.append({"id": "script-url", "label": f"{lower.split(':', 1)[0]}: link", "severity": "high"})
        shown = _TEXT_URL.match(link.get("text", "").strip())
        if shown and host:
            shown_host = shown.group(1).lower()
            if org_domain(shown_host) != org_domain(host):
                findings.append({"id": "text-mismatch", "label": "text ≠ target", "severity": "high"})
        if "xn--" in host:
            findings.append({"id": "punycode", "label": f"punycode ({decoded})", "severity": "high"})
        imitated = lookalike(host, own_domains, org_domain)
        if imitated:
            findings.append({"id": "lookalike", "label": f"lookalike of {imitated}", "severity": "high"})
        if host in SHORTENERS:
            findings.append({"id": "shortener", "label": "URL shortener", "severity": "medium"})
        try:
            ipaddress.ip_address(host.strip("[]"))
            findings.append({"id": "ip-host", "label": "IP address as host", "severity": "medium"})
        except ValueError:
            pass
        authority = urlsplit(target).netloc if "://" in target else ""
        if "@" in authority:
            findings.append({"id": "userinfo", "label": "@ in the address", "severity": "high"})
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            findings.append(
                {"id": "risky-tld", "label": f"throwaway TLD .{host.rsplit('.', 1)[-1]}", "severity": "medium"}
            )
        if any(host == c or host.endswith("." + c) for c in CLOUD_HOSTING):
            findings.append({"id": "cloud-hosted", "label": "page on a cloud service", "severity": "medium"})
        if link["kind"] == "form":
            findings.append({"id": "form", "label": "form posts to this address", "severity": "high"})
        allowlisted = bool(allowlist and host and allowlist.matches("url", target))
        if allowlisted:
            findings = [f for f in findings if f["severity"] == "high" and f["id"] in ("text-mismatch", "form")]
        out.append(
            {
                "url": raw,
                "target": target,
                "host": host,
                "displayHost": decoded,
                "text": link.get("text", ""),
                "kind": link["kind"],
                "gateway": gateway,
                "allowlisted": allowlisted,
                "findings": findings,
            }
        )
    return out
