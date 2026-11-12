"""Who registered a domain or holds an address, read from the registries.

No account and no key: RDAP, the successor of WHOIS, is HTTPS and answers in
JSON. IANA publishes which server answers for each top-level domain and each
address block (the "bootstrap" files, kept for a day). A top-level domain
with no RDAP server is asked the old way, WHOIS on port 43, and its text is
read for the few lines every registry writes.

The age of a domain is a signal of its own: one registered in the last 30
days is reported as suspicious, and counts in the indicator's score. Anything
else here is information and does not move the score.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any

from . import providers

BOOTSTRAP = "https://data.iana.org/rdap/{}.json"
BOOTSTRAP_TTL = 86_400
YOUNG_DAYS = 30
WHOIS_TIMEOUT = 10
WHOIS_MAX = 200_000
_cache: dict[str, tuple[float, Any]] = {}


def reset_cache() -> None:
    _cache.clear()


def _bootstrap(name: str) -> list[Any]:
    """IANA's list of ``[[keys…], [urls…]]`` for ``dns``, ``ipv4`` or ``ipv6``."""
    kept = _cache.get(name)
    if kept and time.time() - kept[0] < BOOTSTRAP_TTL:
        return kept[1]
    status, answer = providers._request(BOOTSTRAP.format(name))
    services = answer.get("services") if status == 200 and isinstance(answer, dict) else None
    if not isinstance(services, list):
        return kept[1] if kept else []
    _cache[name] = (time.time(), services)
    return services


def _base(urls: list[str]) -> str | None:
    best = next((u for u in urls if str(u).startswith("https://")), None)
    return best if best is None or best.endswith("/") else best + "/"


def domain_server(tld: str) -> str | None:
    for keys, urls in (entry[:2] for entry in _bootstrap("dns") if len(entry) >= 2):
        if tld in keys:
            return _base(urls)
    return None


def ip_server(value: str) -> str | None:
    address = ipaddress.ip_address(value)
    best: tuple[int, str] | None = None
    for keys, urls in (entry[:2] for entry in _bootstrap(f"ipv{address.version}") if len(entry) >= 2):
        for key in keys:
            try:
                network = ipaddress.ip_network(key, strict=False)
            except ValueError:
                continue
            if address in network and (best is None or network.prefixlen > best[0]) and _base(urls):
                best = (network.prefixlen, _base(urls))
    return best[1] if best else None


# --------------------------------------------------------------------------- #
# RDAP                                                                        #
# --------------------------------------------------------------------------- #
def _vcard(entity: dict[str, Any]) -> dict[str, str]:
    """Name, organisation, e-mail and country of an entity's jCard."""
    out: dict[str, str] = {}
    card = entity.get("vcardArray")
    for item in card[1] if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list) else []:
        if not isinstance(item, list) or len(item) < 4:
            continue
        name, params, value = item[0], item[1] if isinstance(item[1], dict) else {}, item[3]
        if name == "fn" and isinstance(value, str) and value.strip():
            out["name"] = value.strip()[:200]
        elif name == "org" and value:
            out["org"] = str(value[0] if isinstance(value, list) else value)[:200]
        elif name == "email" and isinstance(value, str):
            out.setdefault("email", value[:200])
        elif name == "adr":
            country = params.get("cc") or (value[-1] if isinstance(value, list) and value else "")
            if isinstance(country, str) and country.strip():
                out["country"] = country.strip()[:60]
    return out


def _entities(node: dict[str, Any], depth: int = 0) -> list[tuple[set[str], dict[str, Any]]]:
    found = []
    for entity in node.get("entities") or []:
        if isinstance(entity, dict):
            found.append(({str(r) for r in entity.get("roles") or []}, entity))
            if depth < 2:
                found += _entities(entity, depth + 1)
    return found


def _events(node: dict[str, Any]) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    for event in node.get("events") or []:
        if isinstance(event, dict):
            out.setdefault(str(event.get("eventAction") or ""), providers._iso_ms(event.get("eventDate")))
    return out


def _redacted(text: str) -> bool:
    return bool(re.search(r"redacted|privacy|whoisguard|withheld|not disclosed|data protected|proxy", text, re.I))


def _age_days(created: int | None, now: float | None = None) -> int | None:
    if not created:
        return None
    return max(0, int(((now or time.time()) * 1000 - created) // 86_400_000))


def _verdict(age: int | None) -> tuple[str, list[str]]:
    if age is not None and age < YOUNG_DAYS:
        return "suspicious", [f"registered {age} day{'s' if age != 1 else ''} ago"]
    return "unknown", []


def _day(ms: int | None) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d") if ms else "an unknown date"


def _domain_result(name: str, answer: dict[str, Any], source: str, link: str, calls: int) -> dict[str, Any]:
    events = _events(answer)
    created = events.get("registration")
    registrar = registrant = abuse = None
    registrar_id = None
    for roles, entity in _entities(answer):
        card = _vcard(entity)
        if "registrar" in roles and registrar is None:
            registrar = card.get("name") or card.get("org")
            registrar_id = next(
                (
                    str(i.get("identifier"))
                    for i in entity.get("publicIds") or []
                    if isinstance(i, dict) and "IANA" in str(i.get("type") or "")
                ),
                None,
            )
        if "registrant" in roles and registrant is None:
            registrant = card
        if "abuse" in roles and abuse is None:
            abuse = card.get("email")
    owner = " · ".join(x for x in ((registrant or {}).get("org"), (registrant or {}).get("name")) if x)
    private = bool(registrant is not None and (not owner or _redacted(owner)))
    age = _age_days(created)
    verdict, signals = _verdict(age)
    if private:
        signals.append("the registrant is hidden")
    summary = (
        f"registered {age} day{'s' if age != 1 else ''} ago ({_day(created)})"
        if verdict == "suspicious"
        else f"registered {_day(created)}"
    )
    if registrar:
        summary += f", {registrar}"
    return providers._result(
        verdict,
        summary,
        link,
        raw=answer,
        calls=calls,
        kind="domain",
        name=str(answer.get("ldhName") or name).lower(),
        registered=created,
        changed=events.get("last changed"),
        expires=events.get("expiration"),
        ageDays=age,
        young=verdict == "suspicious" or None,
        registrar=registrar,
        registrarId=registrar_id,
        registrant=None if private else owner,
        registrantCountry=(registrant or {}).get("country"),
        private=private or None,
        abuse=abuse,
        nameservers=sorted(
            {
                str(ns.get("ldhName")).lower()
                for ns in answer.get("nameservers") or []
                if isinstance(ns, dict) and ns.get("ldhName")
            }
        )[:12],
        status=[str(s) for s in answer.get("status") or []][:12],
        dnssec="signed" if (answer.get("secureDNS") or {}).get("delegationSigned") else "unsigned",
        signals=signals,
        source=source,
    )


def _candidates(name: str) -> list[str]:
    """The names to ask for, shortest first: the registered domain is a suffix
    of the host (``a.b.example.co.uk`` → ``co.uk``, ``example.co.uk``, …)."""
    labels = name.strip(".").split(".")
    return [".".join(labels[-n:]) for n in range(2, min(len(labels), 4) + 1)]


def domain(name: str) -> dict[str, Any]:
    name = name.lower().strip(".")
    link = f"https://client.rdap.org/?type=domain&object={name}"
    server = domain_server(name.rsplit(".", 1)[-1])
    calls = 0
    if server:
        for candidate in _candidates(name):
            calls += 1
            status, answer = providers._request(f"{server}domain/{candidate}")
            if status == 200 and isinstance(answer, dict) and answer.get("objectClassName") == "domain":
                host = server.split("/")[2]
                return _domain_result(candidate, answer, f"RDAP · {host}", link, calls)
        return providers._result("unknown", "the registry has no record of this domain", link, calls=max(1, calls))
    return _whois_domain(name, link)


def ip(value: str) -> dict[str, Any]:
    link = f"https://client.rdap.org/?type=ip&object={value}"
    server = ip_server(value)
    if not server:
        return providers._result("unknown", "no registry answers for this address", link)
    status, answer = providers._request(f"{server}ip/{value}")
    if status != 200 or not isinstance(answer, dict):
        return providers._result("unknown", "the registry has no record of this address", link)
    events = _events(answer)
    holder = abuse = None
    for roles, entity in _entities(answer):
        card = _vcard(entity)
        if roles & {"registrant", "administrative"} and holder is None:
            holder = card.get("org") or card.get("name")
        if "abuse" in roles and abuse is None:
            abuse = card.get("email")
    cidrs = [
        f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
        for c in answer.get("cidr0_cidrs") or []
        if isinstance(c, dict) and (c.get("v4prefix") or c.get("v6prefix"))
    ]
    network = cidrs[0] if cidrs else f"{answer.get('startAddress')} – {answer.get('endAddress')}"
    name = str(answer.get("name") or answer.get("handle") or "")
    summary = " · ".join(x for x in (name, holder, str(answer.get("country") or "")) if x) or "registered network"
    return providers._result(
        "unknown",
        summary[:200],
        link,
        raw=answer,
        kind="ip",
        name=name,
        handle=str(answer.get("handle") or ""),
        network=network,
        holder=holder,
        country=str(answer.get("country") or ""),
        type=str(answer.get("type") or ""),
        registered=events.get("registration"),
        changed=events.get("last changed"),
        abuse=abuse,
        source=f"RDAP · {server.split('/')[2]}",
    )


# --------------------------------------------------------------------------- #
# WHOIS on port 43, for the registries without RDAP                           #
# --------------------------------------------------------------------------- #
def _whois(server: str, query: str) -> str:
    """One WHOIS question and its answer as text."""
    try:
        with socket.create_connection((server, 43), timeout=WHOIS_TIMEOUT) as connection:
            connection.sendall(query.encode("idna") + b"\r\n")
            chunks, size = [], 0
            while size < WHOIS_MAX:
                chunk = connection.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
    except (OSError, UnicodeError) as exc:
        raise providers.ProviderError(
            "network", f"WHOIS (port 43) of {server} cannot be reached: {getattr(exc, 'strerror', None) or exc}"
        ) from exc
    return b"".join(chunks).decode("utf-8", "replace")


_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d-%m-%Y",
    "%d/%m/%Y",
    "%Y.%m.%d",
    "%Y/%m/%d",
    "%d.%m.%Y",
    "%Y%m%d",
)


def _date(text: str) -> int | None:
    cleaned = text.strip()
    direct = providers._iso_ms(cleaned)
    if direct:
        return direct
    cleaned = re.split(r"\s+(?:UTC|GMT|CET|CEST)\b", cleaned)[0].split("+")[0].rstrip("Z").split(".")[0].strip()
    for fmt in _DATE_FORMATS:
        try:
            return int(datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc).timestamp() * 1000)
        except ValueError:
            continue
    return None


def _field(text: str, *names: str) -> str | None:
    for name in names:
        match = re.search(rf"^[ \t]*{name}[ \t]*:[ \t]*(\S.*)$", text, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()[:200]
    return None


_HOST = re.compile(r"[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)


def _block(text: str, title: str) -> list[str]:
    """The indented lines under a line that holds only ``title`` (read line by
    line: a registry's text is not to be trusted with a backtracking pattern)."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().lower() == title:
            block = []
            for following in lines[index + 1 : index + 40]:
                if following[:1] not in (" ", "\t") or not following.strip():
                    break
                block.append(following.strip())
            return block
    return []


def parse_whois(text: str) -> dict[str, Any]:
    """The few lines every registry writes, whatever it calls them."""
    created = _field(
        text,
        "Creation Date",
        "Created On",
        "Created",
        "Registered on",
        "Registration Time",
        "Domain Registration Date",
        "registered",
        "created",
    )
    expires = _field(
        text,
        "Registry Expiry Date",
        "Expiration Date",
        "Expire Date",
        "Expiry Date",
        "paid-till",
        "Expires On",
        "Expires",
        "expire",
    )
    changed = _field(text, "Updated Date", "Last Update", "Last Modified", "last-modified", "changed", "modified")
    registrar = _field(text, "Registrar", "Sponsoring Registrar", "registrar")
    if registrar is None:
        # ".it" and others write the registrar as a block: "Registrar" then "Organization: …".
        for line in _block(text, "registrar"):
            name, _, value = line.partition(":")
            if name.strip().lower() in ("organization", "name") and value.strip():
                registrar = value.strip()[:200]
                break
    servers = re.findall(
        r"^[ \t]*(?:Name Server|nserver|Nameservers?)[ \t]*:[ \t]*([a-z0-9.-]+\.[a-z]{2,})", text, re.I | re.M
    )
    if not servers:
        servers = [line.split()[0] for line in _block(text, "nameservers") if _HOST.fullmatch(line.split()[0])]
    return {
        "registered": _date(created) if created else None,
        "expires": _date(expires) if expires else None,
        "changed": _date(changed) if changed else None,
        "registrar": registrar,
        "nameservers": sorted({s.lower().rstrip(".") for s in servers})[:12],
        "status": [
            s.split()[0] for s in re.findall(r"^[ \t]*(?:Domain )?Status[ \t]*:[ \t]*(\S.*)$", text, re.I | re.M)
        ][:12],
    }


def _whois_domain(name: str, link: str) -> dict[str, Any]:
    tld = name.rsplit(".", 1)[-1]
    referral = _field(_whois("whois.iana.org", tld), "whois")
    if not referral or not re.fullmatch(r"[a-z0-9.-]+", referral, re.I):
        return providers._result("unknown", f"no registry answers for .{tld}", link)
    calls = 1
    for candidate in _candidates(name):
        calls += 1
        text = _whois(referral.lower(), candidate)
        parsed = parse_whois(text)
        if parsed["registered"] or parsed["registrar"] or parsed["nameservers"]:
            age = _age_days(parsed["registered"])
            verdict, signals = _verdict(age)
            summary = (
                f"registered {age} day{'s' if age != 1 else ''} ago ({_day(parsed['registered'])})"
                if verdict == "suspicious"
                else f"registered {_day(parsed['registered'])}"
            )
            if parsed["registrar"]:
                summary += f", {parsed['registrar']}"
            return providers._result(
                verdict,
                summary,
                link,
                raw={"whois": text[:WHOIS_MAX], "server": referral},
                calls=calls,
                kind="domain",
                name=candidate,
                ageDays=age,
                young=verdict == "suspicious" or None,
                signals=signals,
                source=f"WHOIS · {referral.lower()}",
                **parsed,
            )
    return providers._result("unknown", "the registry has no record of this domain", link, calls=calls)


def lookup(kind: str, value: str, key: str | None = None, options: dict | None = None) -> dict[str, Any]:
    return ip(value) if kind == "ip" else domain(value)
