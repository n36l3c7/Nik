"""SPF, DKIM and DMARC checked by Nik itself, through DNS.

These say what the DNS says *now*: a DKIM key rotated since the message was
sent, or an SPF record changed, gives a different result than on the day it
arrived. The receiving server's own verdicts (``headers.reported_auth``)
are shown next to these for that reason.

- DKIM: every ``DKIM-Signature`` verified with dkimpy (key from
  ``<selector>._domainkey.<d>``).
- SPF: the sending server's IP (first public hop) against the Return-Path
  domain (or the HELO name) with pyspf.
- DMARC: the From domain's policy (``_dmarc.<domain>``, then its
  organisational domain) and the alignment of the passing SPF and DKIM
  identities (relaxed or strict, RFC 7489).

DNS lookups go through ``txt_lookup`` and pyspf's resolver; tests replace
them. Every lookup times out after a few seconds; a failure is reported as
``temperror``, never as a pass.
"""

from __future__ import annotations

import re
from typing import Any, Callable

# DKIM signatures verified per message (each is a DNS lookup on a domain the sender chose).
MAX_DKIM_SIGNATURES = 5

TIMEOUT = 3.0

TxtLookup = Callable[[str], list[str]]


def txt_lookup(name: str) -> list[str]:
    """TXT records of a name ([] when there are none); raises on DNS failure."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise OSError(str(exc)) from exc
    return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]


_PSL = None


def org_domain(domain: str) -> str:
    """The organisational domain (registrable part) of a name."""
    global _PSL
    if _PSL is None:
        from publicsuffixlist import PublicSuffixList

        _PSL = PublicSuffixList()
    domain = domain.lower().strip(".")
    return _PSL.privatesuffix(domain) or domain


def aligned(identity: str, from_domain: str, mode: str) -> bool:
    if not identity or not from_domain:
        return False
    identity, from_domain = identity.lower(), from_domain.lower()
    if mode == "s":
        return identity == from_domain
    return org_domain(identity) == org_domain(from_domain)


# --------------------------------------------------------------------------- #
def verify_dkim(raw: bytes, lookup: TxtLookup) -> list[dict[str, Any]]:
    import dkim

    def dnsfunc(name, timeout=TIMEOUT):
        records = lookup((name.decode() if isinstance(name, bytes) else name).rstrip("."))
        return "".join(records).encode() if records else b""

    results = []
    try:
        message = dkim.DKIM(raw)
    except Exception:  # noqa: BLE001 - unparsable message
        return results
    signatures = [value for name, value in message.headers if name.lower() == b"dkim-signature"]
    # Each signature costs a DNS lookup on a domain the sender chose: a message
    # with hundreds of them would keep a worker busy for minutes.
    for index, value in enumerate(signatures[:MAX_DKIM_SIGNATURES]):
        tags = dict(
            (k.strip(), v.strip())
            for k, _, v in (
                part.partition("=") for part in re.sub(r"\s+", "", value.decode("utf-8", "replace")).split(";")
            )
            if k.strip()
        )
        domain, selector = tags.get("d", ""), tags.get("s", "")
        try:
            ok = message.verify(idx=index, dnsfunc=dnsfunc)
            result = "pass" if ok else "fail"
            detail = "signature valid" if ok else "signature does not match the key or the body changed"
        except (OSError, dkim.DnsTimeoutError) as exc:
            result, detail = "temperror", f"DNS: {exc}"
        except dkim.ValidationError as exc:  # body hash mismatch, expired signature…
            result, detail = "fail", str(exc)[:200]
        except Exception as exc:  # noqa: BLE001 - dkimpy raises its own errors for bad keys/signatures
            result, detail = "permerror", str(exc)[:200]
        results.append({"domain": domain, "selector": selector, "result": result, "detail": detail})
    skipped = len(signatures) - MAX_DKIM_SIGNATURES
    if skipped > 0:
        results.append(
            {
                "domain": "",
                "selector": "",
                "result": "none",
                "detail": f"{skipped} more signatures not checked (only the first {MAX_DKIM_SIGNATURES} are)",
            }
        )
    return results


def verify_spf(ip: str | None, mail_from: str, helo: str) -> dict[str, Any]:
    if not ip:
        return {"result": "none", "detail": "no public sending IP in the Received headers", "domain": ""}
    import spf

    sender = mail_from or (f"postmaster@{helo}" if helo else "")
    if not sender:
        return {"result": "none", "detail": "no Return-Path and no HELO name", "domain": ""}
    try:
        result, explanation = spf.check2(i=ip, s=sender, h=helo or sender.rsplit("@", 1)[-1], timeout=TIMEOUT)
    except Exception as exc:  # noqa: BLE001 - pyspf raises on DNS trouble
        result, explanation = "temperror", str(exc)[:200]
    return {"result": result, "detail": explanation, "domain": sender.rsplit("@", 1)[-1].lower(), "ip": ip}


def _dmarc_record(domain: str, lookup: TxtLookup) -> tuple[str, dict[str, str]] | None:
    for name in dict.fromkeys([domain, org_domain(domain)]):
        try:
            records = [r for r in lookup(f"_dmarc.{name}") if r.lower().startswith("v=dmarc1")]
        except OSError:
            raise
        if records:
            tags = {}
            for part in records[0].split(";"):
                key, _, value = part.strip().partition("=")
                if key:
                    tags[key.strip().lower()] = value.strip()
            return name, tags
    return None


def verify_dmarc(from_domain: str, spf_result: dict, dkim_results: list[dict], lookup: TxtLookup) -> dict[str, Any]:
    if not from_domain:
        return {"result": "none", "detail": "no From domain", "policy": None}
    try:
        found = _dmarc_record(from_domain, lookup)
    except OSError as exc:
        return {"result": "temperror", "detail": f"DNS: {exc}", "policy": None}
    if not found:
        return {"result": "none", "detail": f"no DMARC record for {from_domain}", "policy": None}
    record_domain, tags = found
    policy = tags.get("sp") if record_domain != from_domain and "sp" in tags else tags.get("p", "none")
    adkim, aspf = tags.get("adkim", "r"), tags.get("aspf", "r")
    dkim_aligned = [
        d["domain"] for d in dkim_results if d["result"] == "pass" and aligned(d["domain"], from_domain, adkim)
    ]
    spf_aligned = spf_result.get("result") == "pass" and aligned(spf_result.get("domain", ""), from_domain, aspf)
    if dkim_aligned or spf_aligned:
        how = []
        if dkim_aligned:
            how.append(f"DKIM d={dkim_aligned[0]}")
        if spf_aligned:
            how.append(f"SPF {spf_result['domain']}")
        return {"result": "pass", "detail": "aligned: " + ", ".join(how), "policy": policy, "record": record_domain}
    reasons = []
    if not any(d["result"] == "pass" for d in dkim_results):
        reasons.append("no valid DKIM signature")
    elif not dkim_aligned:
        reasons.append("DKIM d= not aligned with " + from_domain)
    if spf_result.get("result") != "pass":
        reasons.append(f"SPF {spf_result.get('result')}")
    elif not spf_aligned:
        reasons.append(f"SPF domain {spf_result.get('domain')} not aligned")
    return {"result": "fail", "detail": "; ".join(reasons), "policy": policy, "record": record_domain}


def verify_all(
    raw: bytes, from_domain: str, ip: str | None, mail_from: str, helo: str, lookup: TxtLookup | None = None
) -> dict[str, Any]:
    lookup = lookup or txt_lookup
    dkim_results = verify_dkim(raw, lookup)
    spf_result = verify_spf(ip, mail_from, helo)
    dmarc_result = verify_dmarc(from_domain, spf_result, dkim_results, lookup)
    if dkim_results:
        best = next((d for d in dkim_results if d["result"] == "pass"), dkim_results[0])
        dkim_summary = {**best, "signatures": dkim_results}
    else:
        dkim_summary = {"result": "none", "detail": "no DKIM signature", "signatures": []}
    return {"spf": spf_result, "dkim": dkim_summary, "dmarc": dmarc_result}
