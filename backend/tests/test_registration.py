"""Registration data of domains and addresses: RDAP, the WHOIS fallback, and what a young domain weighs."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.db import SessionLocal
from app.enrichment import providers, registration, service

DNS = {
    "services": [
        [["top", "com"], ["https://rdap.example-registry.test/"]],
        [["uk"], ["http://plain.test/", "https://rdap.nominet.test"]],
    ]
}
IPV4 = {
    "services": [[["185.0.0.0/8"], ["https://rdap.ripe.test/"]], [["185.220.0.0/16"], ["https://rdap.closer.test/"]]]
}


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rdap_domain(name: str, days_ago: int, registrant: str = "REDACTED FOR PRIVACY") -> dict:
    return {
        "objectClassName": "domain",
        "ldhName": name.upper(),
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": _iso(days_ago)},
            {"eventAction": "expiration", "eventDate": _iso(days_ago - 365)},
            {"eventAction": "last changed", "eventDate": _iso(days_ago)},
        ],
        "nameservers": [{"ldhName": "NS2.DNSOWL.COM"}, {"ldhName": "ns1.dnsowl.com"}],
        "secureDNS": {"delegationSigned": False},
        "entities": [
            {
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "1479"}],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "NameSilo, LLC"]]],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Abuse"], ["email", {}, "text", "abuse@namesilo.com"]],
                        ],
                    }
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", registrant], ["adr", {"cc": "PA"}, "text", ["", "", "", "", "", "", ""]]],
                ],
            },
        ],
    }


@pytest.fixture()
def registries(monkeypatch):
    """Answers by exact URL; records every request."""
    answers: dict[str, tuple[int, object]] = {
        "https://data.iana.org/rdap/dns.json": (200, DNS),
        "https://data.iana.org/rdap/ipv4.json": (200, IPV4),
    }
    calls: list[str] = []

    def request(url, *, headers=None, form=None, body=None):
        calls.append(url)
        return answers.get(url, (404, None))

    monkeypatch.setattr(providers, "_request", request)
    registration.reset_cache()
    service.limiter.reset()
    yield answers, calls
    registration.reset_cache()
    service.limiter.reset()


def test_a_domain_registered_days_ago_is_suspicious_and_says_so(registries):
    answers, calls = registries
    answers["https://rdap.example-registry.test/domain/cdn-update.top"] = (200, rdap_domain("cdn-update.top", 9))
    found = registration.lookup("domain", "cdn-update.top")
    assert found["verdict"] == "suspicious"
    assert found["summary"].startswith("registered 9 days ago (") and found["summary"].endswith(", NameSilo, LLC")
    data = found["data"]
    assert data["ageDays"] == 9 and data["young"] is True and data["registrar"] == "NameSilo, LLC"
    assert data["registrarId"] == "1479" and data["abuse"] == "abuse@namesilo.com" and data["private"] is True
    assert data["registrantCountry"] == "PA" and "registrant" not in data
    assert data["nameservers"] == ["ns1.dnsowl.com", "ns2.dnsowl.com"] and data["dnssec"] == "unsigned"
    assert data["signals"] == ["registered 9 days ago", "the registrant is hidden"]
    assert data["source"] == "RDAP · rdap.example-registry.test" and found["raw"]["ldhName"] == "CDN-UPDATE.TOP"

    # The bootstrap file is read once a day, not once a lookup.
    registration.lookup("domain", "cdn-update.top")
    assert calls.count("https://data.iana.org/rdap/dns.json") == 1


def test_an_old_domain_is_information_only_and_a_host_is_asked_by_its_registered_domain(registries):
    answers, calls = registries
    answers["https://rdap.example-registry.test/domain/example.com"] = (
        200,
        rdap_domain("example.com", 4000, "Example Org"),
    )
    found = registration.lookup("domain", "login.portal.example.com")
    assert found["verdict"] == "unknown" and found["summary"].startswith("registered 20")
    assert found["data"]["name"] == "example.com" and found["data"]["registrant"] == "Example Org"
    assert found["calls"] == 1 and "young" not in found["data"]
    # https is preferred among a registry's servers; an unknown name is an answer, not an error.
    assert registration.domain_server("uk") == "https://rdap.nominet.test/"
    missing = registration.lookup("domain", "nothing-here.top")
    assert missing["verdict"] == "unknown" and "no record" in missing["summary"]


def test_an_address_gets_its_network_and_holder(registries):
    answers, _ = registries
    answers["https://rdap.closer.test/ip/185.220.101.47"] = (
        200,
        {
            "handle": "185.220.101.0 - 185.220.101.255",
            "name": "TOR-EXIT",
            "country": "DE",
            "type": "ASSIGNED PA",
            "startAddress": "185.220.101.0",
            "endAddress": "185.220.101.255",
            "cidr0_cidrs": [{"v4prefix": "185.220.101.0", "length": 24}],
            "events": [{"eventAction": "registration", "eventDate": "2017-03-01T10:00:00Z"}],
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Zwiebelfreunde e.V."]]]},
                {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@torservers.net"]]]},
            ],
        },
    )
    found = registration.lookup("ip", "185.220.101.47")  # the most specific block's registry is asked
    assert found["verdict"] == "unknown" and found["summary"] == "TOR-EXIT · Zwiebelfreunde e.V. · DE"
    assert found["data"]["network"] == "185.220.101.0/24" and found["data"]["abuse"] == "abuse@torservers.net"
    assert registration.lookup("ip", "8.8.8.8")["summary"] == "no registry answers for this address"


WHOIS_IT = """Domain:             esempio.it
Status:             ok
Created:            {created} 00:00:00
Last Update:        2026-01-09 01:02:03
Expire Date:        2027-01-08

Registrar
  Organization:     Aruba s.p.a.
  Name:             ARUBA-REG

Nameservers
  dns.technorail.com
  dns2.technorail.com
"""


def test_a_registry_without_rdap_is_asked_over_whois(registries, monkeypatch):
    asked: list[tuple[str, str]] = []
    created = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%d")

    def whois(server, query):
        asked.append((server, query))
        if server == "whois.iana.org":
            return "domain:       IT\nwhois:        whois.nic.it\n"
        return WHOIS_IT.format(created=created) if query == "esempio.it" else "Status: AVAILABLE\n"

    monkeypatch.setattr(registration, "_whois", whois)
    found = registration.lookup("domain", "www.esempio.it")
    assert asked == [("whois.iana.org", "it"), ("whois.nic.it", "esempio.it")]
    assert found["verdict"] == "suspicious" and found["data"]["ageDays"] == 3
    assert found["data"]["registrar"] == "Aruba s.p.a." and found["data"]["source"] == "WHOIS · whois.nic.it"
    assert found["data"]["nameservers"] == ["dns.technorail.com", "dns2.technorail.com"]
    assert found["data"]["status"] == ["ok"] and found["calls"] == 2

    # The usual gTLD spelling of the same lines.
    parsed = registration.parse_whois(
        "Domain Name: EXAMPLE.ORG\nCreation Date: 1995-08-31T04:00:00Z\nRegistry Expiry Date: 2027-08-30T04:00:00Z\n"
        "Registrar: Example Registrar, Inc.\nName Server: A.IANA-SERVERS.NET\nDomain Status: clientDeleteProhibited https://icann.org/epp\n"
    )
    assert parsed["registrar"] == "Example Registrar, Inc." and parsed["nameservers"] == ["a.iana-servers.net"]
    assert parsed["status"] == ["clientDeleteProhibited"] and parsed["registered"] == 809841600000

    def unreachable(server, query):
        raise providers.ProviderError("network", "WHOIS (port 43) of whois.iana.org cannot be reached: timed out")

    monkeypatch.setattr(registration, "_whois", unreachable)
    with pytest.raises(providers.ProviderError):
        registration.lookup("domain", "www.esempio.it")


def test_only_a_young_domain_counts_in_the_score():
    # Facts that do not flag are left out of the score and of the count of sources.
    assert service.overall([("registration", "unknown")]) is None
    assert service.overall([("virustotal", "harmless"), ("registration", "unknown")]) == service.overall(
        [("virustotal", "harmless")]
    )
    young = service.overall([("virustotal", "harmless"), ("registration", "suspicious")])
    assert young["verdict"] == "suspicious" and young["score"] == 20 and young["checked"] == 2 and young["flagged"] == 1
    worse = service.overall([("urlscan", "malicious"), ("registration", "suspicious")])
    assert worse["verdict"] == "malicious" and worse["score"] == 75


def test_check_now_reads_the_registry_and_never_for_an_internal_name(admin: TestClient, registries):
    answers, calls = registries
    answers["https://rdap.example-registry.test/domain/cdn-update.top"] = (200, rdap_domain("cdn-update.top", 2))
    checked = admin.post("/api/enrichment/check", json={"type": "domain", "value": "cdn-update.top"})
    assert checked.status_code == 200, checked.text
    result = next(r for r in checked.json()["results"] if r["provider"] == "registration")
    assert result["verdict"] == "suspicious" and result["data"]["ageDays"] == 2 and result["hasRaw"]
    assert checked.json()["summary"]["verdict"] == "suspicious"

    before = len(calls)
    assert admin.post("/api/enrichment/check", json={"type": "domain", "value": "fileserver.corp"}).status_code == 422
    assert len(calls) == before
    with SessionLocal() as db:
        assert service.blocked(db, "domain", "fileserver.corp", service.Allowlist([])) is not None
    assert time.time() > 0


def test_a_hostile_whois_answer_is_read_in_linear_time():
    started = time.monotonic()
    parsed = registration.parse_whois("Registrar\n" + "\t\t\n" * 50_000 + "Nameservers\n" + "  x \n" * 50_000)
    assert parsed["registrar"] is None and parsed["nameservers"] == []
    assert time.monotonic() - started < 2
