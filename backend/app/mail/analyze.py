"""One e-mail, analysed: everything the Mail Analysis tab shows.

``analyse_mail(data, ...)`` parses the file, reads the route and the sender
from the headers, checks SPF/DKIM/DMARC through DNS, cleans the HTML body,
looks at every link and attachment, and weighs the evidence into a score:

- 70 and above: **phishing**: several strong signs together;
- 40 to 69: **suspicious**: worth a closer look;
- below 40: **no strong signs**: not proof of a clean message.

Each finding says what was seen and how much it weighs, so the verdict can be
explained (and challenged) line by line.
"""

from __future__ import annotations

from typing import Any, Callable

from ..parsing.malware import hashes
from . import attachments as attach
from . import content, headers, links, verify
from .parse import parse_mail, rtf_to_text

ANALYSIS_VERSION = 1
PHISHING, SUSPICIOUS = 70, 40

# Points per finding (one finding counts once, however many links show it).
WEIGHTS = {
    "dmarc-fail": 30,
    "spf-fail": 15,
    "dkim-fail": 10,
    "no-auth": 10,
    "from-lookalike": 40,
    "display-name-spoof": 25,
    "display-name-brand": 20,
    "reply-to-mismatch": 20,
    "return-path-mismatch": 8,
    "own-domain-external": 30,
    "link-script-url": 30,
    "link-text-mismatch": 20,
    "link-lookalike": 35,
    "link-punycode": 20,
    "link-userinfo": 20,
    "link-form": 25,
    "link-ip-host": 15,
    "link-shortener": 8,
    "link-risky-tld": 10,
    "link-cloud-hosted": 10,
    "attachment-high": 35,
    "attachment-medium": 15,
    "attachment-low": 0,
    "pressure": 8,
    "hidden-text": 10,
    "qr-code": 20,
    "clock-backwards": 5,
    "nested-phishing": 30,
}
PRESSURE_MAX = 24


def _bad(result: str | None) -> bool:
    return (result or "") in ("fail", "softfail", "permerror")


def _attachment_tree(items: list[dict], body_text: str, prefix: str, settings: dict, depth: int, **kw) -> list[dict]:
    out = []
    for index, item in enumerate(items):
        path = f"{prefix}{index}"
        info = attach.inspect(item, body_text)
        info["path"] = path
        if item.get("nested"):
            info["message"] = _analyse_parsed(item["nested"], b"", settings, depth + 1, path + ".", **kw)
        out.append(info)
    return out


def analyse_mail(
    data: bytes,
    settings: dict[str, Any] | None = None,
    allowlist=None,
    lookup: Callable[[str], list[str]] | None = None,
    check_dns: bool = True,
) -> dict[str, Any]:
    """The full analysis of an ``.eml`` or ``.msg`` file (raises ``MailError``)."""
    parsed = parse_mail(data)
    result = _analyse_parsed(
        parsed, data, settings or {}, 0, "", allowlist=allowlist, lookup=lookup, check_dns=check_dns
    )
    result["size"] = len(data)
    result["hashes"] = hashes(data)
    result["analysisVersion"] = ANALYSIS_VERSION
    return result


def _analyse_parsed(
    parsed: dict[str, Any],
    raw: bytes,
    settings: dict[str, Any],
    depth: int,
    prefix: str,
    *,
    allowlist=None,
    lookup=None,
    check_dns: bool = True,
) -> dict[str, Any]:
    own = [d.lower().strip() for d in settings.get("orgDomains") or [] if d.strip()]
    trusted = [d.lower().strip() for d in settings.get("trustedAuthServers") or [] if d.strip()]
    hdrs = parsed["headers"]
    who = headers.sender(hdrs)
    route = headers.hops(hdrs)
    origin = headers.origin_ip(route, trusted + own)
    reported = headers.reported_auth(hdrs, trusted)

    text = parsed.get("text") or ""
    html = parsed.get("html") or ""
    if not text and not html and parsed.get("rtf"):
        text = rtf_to_text(parsed["rtf"])
    inline = {
        (a.get("content_id") or "").lower(): (a.get("content_type") or "", a.get("data") or b"")
        for a in parsed["attachments"]
        if a.get("content_id")
    }
    safe, hidden = content.safe_html(html, inline)
    plain = text or content.html_to_text(html)
    images = content.remote_images(html)

    # Authentication: Nik's own check when the original bytes are here (an
    # .eml); a .msg keeps no original body, so DKIM cannot be checked.
    from_domain = who["from"]["domain"]
    helo = next((h["from"] for h in route if h["ip"] == origin), "") if origin else ""
    verified = None
    if check_dns and raw and parsed["format"] == "eml" and depth == 0:
        verified = verify.verify_all(raw, from_domain, origin, who["returnPath"], helo, lookup)
    auth = {"reported": reported, "verified": verified, "dkimVerifiable": parsed["format"] == "eml"}

    link_list = links.analyse(links.extract(html, text), own, verify.org_domain, allowlist)
    atts = _attachment_tree(
        parsed["attachments"], plain, prefix, settings, depth, allowlist=allowlist, lookup=lookup, check_dns=check_dns
    )
    body_qr = [code for a in atts if a.get("inline") for code in a.get("qrCodes", [])]

    findings: list[dict[str, Any]] = []

    def add(code: str, severity: str, text_: str, weight_key: str | None = None) -> None:
        key = weight_key or code
        if any(f["id"] == code for f in findings):
            return
        findings.append({"id": code, "severity": severity, "label": text_, "points": WEIGHTS.get(key, 0)})

    # --- authentication -------------------------------------------------- #
    def outcome(method: str) -> tuple[str | None, str]:
        if verified and verified.get(method, {}).get("result") not in (None, "none", "temperror"):
            return verified[method]["result"], "checked by Nik"
        summary = reported["summary"].get(method)
        if summary and summary["trusted"]:
            return summary["result"], "reported by your mail server"
        if summary and not trusted:
            return summary["result"], "reported by a receiving server"
        return None, ""

    dmarc, dmarc_src = outcome("dmarc")
    spf, spf_src = outcome("spf")
    dkim, dkim_src = outcome("dkim")
    if dmarc == "fail":
        add("dmarc-fail", "high", f"DMARC fails for {from_domain} ({dmarc_src})")
    if _bad(spf):
        add("spf-fail", "medium", f"SPF {spf} ({spf_src})")
    if _bad(dkim):
        add("dkim-fail", "medium", f"DKIM {dkim} ({dkim_src})")
    if (
        depth == 0
        and spf in (None, "none")
        and dkim in (None, "none")
        and dmarc in (None, "none")
        and parsed["format"] == "eml"
    ):
        add("no-auth", "low", "no SPF, DKIM or DMARC result for this message")

    # --- sender ---------------------------------------------------------- #
    display = who["from"]["name"] or ""
    shown = headers.domain_of(display) if "@" in display else ""
    if shown and from_domain and verify.org_domain(shown) != verify.org_domain(from_domain):
        add("display-name-spoof", "high", f"the display name shows {shown}, the address is on {from_domain}")
    imitated = links.lookalike(from_domain, own, verify.org_domain) if from_domain else None
    if imitated:
        add("from-lookalike", "high", f"the sender domain {from_domain} imitates {imitated}")
    else:
        lowered = display.lower()
        brand = next((b for b in links.BRANDS if len(b) >= 4 and b in lowered.replace(" ", "")), None)
        if (
            brand
            and from_domain
            and verify.org_domain(from_domain) not in links.GENUINE
            and not any(verify.org_domain(from_domain) == verify.org_domain(d) for d in own)
        ):
            add("display-name-brand", "medium", f"the name says “{display}”, the address is on {from_domain}")
    if own and from_domain and any(verify.org_domain(from_domain) == verify.org_domain(d) for d in own):
        if dmarc == "fail" or _bad(spf):
            add(
                "own-domain-external",
                "high",
                f"claims to come from your own domain {from_domain} but fails authentication",
            )
    for reply in who["replyTo"]:
        domain = headers.domain_of(reply["address"])
        if domain and from_domain and verify.org_domain(domain) != verify.org_domain(from_domain):
            add("reply-to-mismatch", "high", f"replies go to {reply['address']}, not to {from_domain}")
            break
    rp = who["returnPathDomain"]
    if rp and from_domain and verify.org_domain(rp) != verify.org_domain(from_domain):
        add("return-path-mismatch", "low", f"bounces go to {rp} (often a mailing service)")

    # --- route ----------------------------------------------------------- #
    if any(h["backwards"] for h in route):
        add("clock-backwards", "low", "a Received header is dated before the previous hop")

    # --- body ------------------------------------------------------------ #
    for link in link_list:
        for finding in link["findings"]:
            add(
                f"link-{finding['id']}",
                finding["severity"],
                f"link {link['displayHost'] or link['url'][:60]}: {finding['label']}",
            )
    pressure = content.pressure(f"{who['subject']}\n{plain}")
    for item in pressure:
        add(f"pressure-{item['kind']}", "low", f"{item['kind']}: “{item['phrases'][0]}”", "pressure")
    if hidden:
        add("hidden-text", "medium", f"{hidden} element(s) with text hidden from the reader")
    if body_qr:
        add("qr-code", "medium", f"a QR code in the body points to {body_qr[0][:80]}")

    # --- attachments ----------------------------------------------------- #
    for item in atts:
        for finding in item["findings"]:
            if finding["id"] == "qr-code" and item.get("inline"):
                continue
            add(
                f"attachment-{finding['id']}",
                finding["severity"],
                f"{item['name']}: {finding['label']}",
                f"attachment-{finding['severity']}",
            )
        nested = item.get("message")
        if nested and nested["verdict"] == "phishing":
            add("nested-phishing", "high", f"the attached message {item['name']} looks like phishing")

    # One finding per id; pressure phrases together weigh at most PRESSURE_MAX.
    score = 0
    pressure_points = 0
    for finding in findings:
        if finding["id"].startswith("pressure-"):
            gained = min(finding["points"], PRESSURE_MAX - pressure_points)
            pressure_points += gained
            finding["points"] = gained
        score += finding["points"]
    score = min(score, 100)
    verdict = "phishing" if score >= PHISHING else "suspicious" if score >= SUSPICIOUS else "clean"
    findings.sort(key=lambda f: -f["points"])

    return {
        "format": parsed["format"],
        "subject": who["subject"],
        "date": who["date"],
        "sender": who,
        "headers": hdrs,
        "route": route,
        "originIp": origin,
        "auth": auth,
        "body": {
            "text": plain[:500_000],
            "html": safe,
            "hasHtml": bool(html),
            "htmlSource": html[:1_000_000],
            "hiddenElements": hidden,
            "remoteImages": images,
            "pressure": pressure,
        },
        "links": link_list,
        "attachments": atts,
        "findings": findings,
        "score": score,
        "verdict": verdict,
        "iocs": _iocs(who, origin, link_list, atts, images),
    }


def _iocs(who: dict, origin: str | None, link_list: list[dict], atts: list[dict], images: list[dict]) -> list[dict]:
    """Indicators of the message: sender addresses, sending IP, link targets
    and hosts, attachment hashes, QR-code targets (nested messages included)."""
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []

    def add(kind: str, value: str | None, where: str) -> None:
        if not value:
            return
        key = (kind, value.lower())
        if key not in seen:
            seen.add(key)
            out.append({"type": kind, "value": value, "where": where})

    add("email", who["from"]["address"], "From")
    for reply in who["replyTo"]:
        add("email", reply["address"], "Reply-To")
    add("email", who["returnPath"], "Return-Path")
    add("domain", who["from"]["domain"], "From")
    add("ip", origin, "sending server")
    add("ip", who.get("originatingIp"), "X-Originating-IP")
    for link in link_list:
        if link["target"].lower().startswith(("http://", "https://")):
            add("url", link["target"], "link")
            if link["host"]:
                add("domain", link["host"], "link")
    for image in images:
        if image["tracking"]:
            add("url", image["url"], "tracking pixel")
    for item in atts:
        if item.get("hashes"):
            add("sha256", item["hashes"]["sha256"], item["name"])
            add("md5", item["hashes"]["md5"], item["name"])
        for code in item.get("qrCodes", []):
            if code.lower().startswith(("http://", "https://")):
                add("url", code, f"QR code in {item['name']}")
        for url in (item.get("calendar") or {}).get("urls", []):
            add("url", url, item["name"])
        for url in (item.get("pdf") or {}).get("urls", []):
            if url.lower().startswith(("http://", "https://")):
                add("url", url, item["name"])
        for ioc in (item.get("message") or {}).get("iocs", []):
            add(ioc["type"], ioc["value"], f"{item['name']} → {ioc['where']}")
    return out[:2000]
