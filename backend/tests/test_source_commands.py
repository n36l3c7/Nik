"""The reputation commands of the sources say what Nik's own look-ups say.

Each source of threat intelligence is a connector of its own (6.1), and its
reputation command is written to give, for the same answer of the vendor, the
verdict and the line that ``app.enrichment.providers`` gives. Here both are
given the same answer, the ones the tests of the look-ups use and the edges
(not found, nothing, one, several), and must agree.

abuse.ch is one look-up over three services and three connectors: a case
answers one service and leaves the others without a result, so what the
look-up says is what that service's command must say. When nothing is found
the look-up names two services in its line and a command names its own: the
verdict alone is compared there.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import pytest

from app.automation import connector_actions as ca
from app.automation import connector_runtime as rt
from app.automation import egress
from app.enrichment import providers, registration
from tests import vendor

NOW = 1_800_000_000.0  # 2027-01-15T08:00:00Z
IP = "93.184.216.34"
SHA = "a" * 64
CONNECTORS = {connector.id: connector for _text, connector in vendor.connectors()}
STATS = {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20}
RDAP_DOMAIN = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLE.TOP",
    "events": [{"eventAction": "registration", "eventDate": "2026-12-30T10:00:00Z"}],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]]}],
}
RDAP_NETWORK = {
    "objectClassName": "ip network",
    "handle": "NET-93-184-216-0-1",
    "name": "EXAMPLE-NET",
    "country": "US",
    "startAddress": "93.184.216.0",
    "endAddress": "93.184.216.255",
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Networks"]]]}],
}


def _vt(stats=None, **more):
    return {"data": {"attributes": {"last_analysis_stats": stats or {}, **more}}}


# (name, connector, command, provider, kind, value, {host of the vendor: (status, answer)}, compare the line too)
CASES = [
    # VirusTotal: the answers of test_enrichment, the thresholds, what it does not know.
    (
        "vt ip",
        "virustotal",
        "get-ip-report",
        "virustotal",
        "ip",
        IP,
        {"www.virustotal.com": (200, _vt(STATS, country="DE"))},
        True,
    ),
    (
        "vt ip harmless",
        "virustotal",
        "get-ip-report",
        "virustotal",
        "ip",
        IP,
        {"www.virustotal.com": (200, _vt({"malicious": 0, "harmless": 60, "undetected": 10}))},
        True,
    ),
    (
        "vt domain two engines",
        "virustotal",
        "get-domain-report",
        "virustotal",
        "domain",
        "evil.example.com",
        {"www.virustotal.com": (200, _vt({"malicious": 2, "harmless": 60}))},
        True,
    ),
    (
        "vt domain three engines",
        "virustotal",
        "get-domain-report",
        "virustotal",
        "domain",
        "evil.example.com",
        {"www.virustotal.com": (200, _vt({"malicious": 3, "harmless": 60}))},
        True,
    ),
    (
        "vt file suspicious only",
        "virustotal",
        "get-file-report",
        "virustotal",
        "sha256",
        SHA,
        {"www.virustotal.com": (200, _vt({"malicious": 0, "suspicious": 1, "undetected": 70}))},
        True,
    ),
    (
        "vt file undetected only",
        "virustotal",
        "get-file-report",
        "virustotal",
        "sha256",
        SHA,
        {"www.virustotal.com": (200, _vt({"undetected": 70}))},
        True,
    ),
    (
        "vt file unknown",
        "virustotal",
        "get-file-report",
        "virustotal",
        "sha256",
        SHA,
        {"www.virustotal.com": (404, {"error": {"code": "NotFoundError"}})},
        True,
    ),
    (
        "vt url",
        "virustotal",
        "get-url-reputation",
        "virustotal",
        "url",
        "http://evil.top/x?a=1",
        {"www.virustotal.com": (200, _vt(STATS))},
        True,
    ),
    (
        "vt url unknown",
        "virustotal",
        "get-url-reputation",
        "virustotal",
        "url",
        "http://evil.top/x",
        {"www.virustotal.com": (404, {"error": {"code": "NotFoundError"}})},
        True,
    ),
    # AbuseIPDB.
    (
        "abuseipdb malicious",
        "abuseipdb",
        "check-ip",
        "abuseipdb",
        "ip",
        IP,
        {"api.abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 100, "totalReports": 42, "isp": "Tor"}})},
        True,
    ),
    (
        "abuseipdb two reports",
        "abuseipdb",
        "check-ip",
        "abuseipdb",
        "ip",
        IP,
        {
            "api.abuseipdb.com": (
                200,
                {"data": {"abuseConfidenceScore": 80, "totalReports": 2, "numDistinctUsers": 2, "isTor": True}},
            )
        },
        True,
    ),
    (
        "abuseipdb suspicious, one report",
        "abuseipdb",
        "check-ip",
        "abuseipdb",
        "ip",
        IP,
        {"api.abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 25, "totalReports": 1}})},
        True,
    ),
    (
        "abuseipdb below",
        "abuseipdb",
        "check-ip",
        "abuseipdb",
        "ip",
        IP,
        {"api.abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 24, "totalReports": 3}})},
        True,
    ),
    (
        "abuseipdb whitelisted",
        "abuseipdb",
        "check-ip",
        "abuseipdb",
        "ip",
        IP,
        {"api.abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 90, "totalReports": 9, "isWhitelisted": True}})},
        True,
    ),
    (
        "abuseipdb nothing",
        "abuseipdb",
        "check-ip",
        "abuseipdb",
        "ip",
        IP,
        {
            "api.abuseipdb.com": (
                200,
                {"data": {"abuseConfidenceScore": None, "totalReports": None, "isWhitelisted": None}},
            )
        },
        True,
    ),
    # Shodan InternetDB.
    (
        "internetdb c2",
        "shodan",
        "check-ip",
        "internetdb",
        "ip",
        IP,
        {"internetdb.shodan.io": (200, {"ports": [22, 443], "vulns": ["CVE-1"], "tags": ["c2"]})},
        True,
    ),
    (
        "internetdb tor",
        "shodan",
        "check-ip",
        "internetdb",
        "ip",
        IP,
        {"internetdb.shodan.io": (200, {"ports": [22], "cpes": ["cpe:/a:x"], "vulns": [], "tags": ["tor"]})},
        True,
    ),
    (
        "internetdb tor and botnet",
        "shodan",
        "check-ip",
        "internetdb",
        "ip",
        IP,
        {"internetdb.shodan.io": (200, {"ports": [], "vulns": ["CVE-1", "CVE-2"], "tags": ["tor", "botnet", "cloud"]})},
        True,
    ),
    (
        "internetdb many ports",
        "shodan",
        "check-ip",
        "internetdb",
        "ip",
        IP,
        {"internetdb.shodan.io": (200, {"ports": list(range(20, 32)), "tags": ["a", "b", "c", "d", "e", "f"]})},
        True,
    ),
    (
        "internetdb unknown",
        "shodan",
        "check-ip",
        "internetdb",
        "ip",
        IP,
        {"internetdb.shodan.io": (404, {"detail": "No information available"})},
        True,
    ),
    # GreyNoise Community.
    (
        "greynoise malicious",
        "greynoise",
        "get-community-ip",
        "greynoise",
        "ip",
        IP,
        {"api.greynoise.io": (200, {"noise": True, "riot": False, "classification": "malicious", "name": "unknown"})},
        True,
    ),
    (
        "greynoise business service",
        "greynoise",
        "get-community-ip",
        "greynoise",
        "ip",
        IP,
        {"api.greynoise.io": (200, {"noise": False, "riot": True, "classification": "benign", "name": "Example DNS"})},
        True,
    ),
    (
        "greynoise benign scanner",
        "greynoise",
        "get-community-ip",
        "greynoise",
        "ip",
        IP,
        {
            "api.greynoise.io": (
                200,
                {"noise": True, "riot": False, "classification": "benign", "name": "Example Scanner"},
            )
        },
        True,
    ),
    (
        "greynoise not seen",
        "greynoise",
        "get-community-ip",
        "greynoise",
        "ip",
        IP,
        {
            "api.greynoise.io": (
                404,
                {"message": "IP not observed scanning the internet or contained in RIOT data set."},
            )
        },
        True,
    ),
    # urlscan.io: malicious in either shape of the answer.
    (
        "urlscan url",
        "urlscan",
        "get-url-reputation",
        "urlscan",
        "url",
        "http://evil.top/x",
        {
            "urlscan.io": (
                200,
                {
                    "total": 37,
                    "results": [
                        {"_id": "a", "verdicts": {"malicious": True}},
                        {"_id": "b", "verdicts": {"overall": {"malicious": True}}},
                        {"_id": "c"},
                    ],
                },
            )
        },
        True,
    ),
    (
        "urlscan domain, one scan",
        "urlscan",
        "get-domain-reputation",
        "urlscan",
        "domain",
        "evil.top",
        {
            "urlscan.io": (
                200,
                {
                    "total": 1,
                    "results": [{"_id": "a", "verdicts": {"overall": {"malicious": False}, "malicious": False}}],
                },
            )
        },
        True,
    ),
    (
        "urlscan never scanned",
        "urlscan",
        "get-domain-reputation",
        "urlscan",
        "domain",
        "evil.top",
        {"urlscan.io": (200, {"total": 0, "results": []})},
        True,
    ),
    # OTX.
    (
        "otx one pulse",
        "otx",
        "get-domain-reputation",
        "otx",
        "domain",
        "evil.example.com",
        {
            "otx.alienvault.com": (
                200,
                {
                    "pulse_info": {
                        "count": 1,
                        "pulses": [
                            {"id": "p1", "name": "AsyncRAT C2", "malware_families": [{"display_name": "AsyncRAT"}]}
                        ],
                    }
                },
            )
        },
        True,
    ),
    (
        "otx two pulses",
        "otx",
        "get-ip-reputation",
        "otx",
        "ip",
        IP,
        {"otx.alienvault.com": (200, {"pulse_info": {"count": 2, "pulses": []}})},
        True,
    ),
    (
        "otx whitelisted",
        "otx",
        "get-domain-reputation",
        "otx",
        "domain",
        "example.com",
        {
            "otx.alienvault.com": (
                200,
                {
                    "pulse_info": {"count": 0, "pulses": []},
                    "validation": [{"source": "majestic", "message": "Whitelisted domain"}],
                },
            )
        },
        True,
    ),
    (
        "otx no pulse",
        "otx",
        "get-file-reputation",
        "otx",
        "sha256",
        SHA,
        {"otx.alienvault.com": (200, {"pulse_info": {"count": 0, "pulses": []}, "validation": []})},
        True,
    ),
    (
        "otx unknown",
        "otx",
        "get-file-reputation",
        "otx",
        "sha256",
        SHA,
        {"otx.alienvault.com": (404, {"detail": "Not found."})},
        True,
    ),
    # abuse.ch, one service at a time.
    (
        "malwarebazaar sample",
        "malwarebazaar",
        "get-file-report",
        "abusech",
        "sha256",
        SHA,
        {
            "mb-api.abuse.ch": (
                200,
                {"query_status": "ok", "data": [{"sha256_hash": SHA, "signature": "AgentTesla", "tags": ["exe"]}]},
            )
        },
        True,
    ),
    (
        "malwarebazaar sample without a family",
        "malwarebazaar",
        "get-file-report",
        "abusech",
        "sha256",
        SHA,
        {"mb-api.abuse.ch": (200, {"query_status": "ok", "data": [{"sha256_hash": SHA, "signature": None}]})},
        True,
    ),
    (
        "malwarebazaar unknown",
        "malwarebazaar",
        "get-file-report",
        "abusech",
        "sha256",
        SHA,
        {"mb-api.abuse.ch": (200, {"query_status": "hash_not_found"})},
        False,
    ),
    (
        "threatfox domain",
        "threatfox",
        "get-domain-report",
        "abusech",
        "domain",
        "evil.example.com",
        {
            "threatfox-api.abuse.ch": (
                200,
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "id": "77",
                            "ioc": "evil.example.com",
                            "threat_type_desc": "botnet C2",
                            "malware_printable": "Cobalt Strike",
                            "confidence_level": 100,
                        }
                    ],
                },
            )
        },
        True,
    ),
    (
        "threatfox ip without a family",
        "threatfox",
        "get-ip-report",
        "abusech",
        "ip",
        IP,
        {
            "threatfox-api.abuse.ch": (
                200,
                {
                    "query_status": "ok",
                    "data": [{"id": "78", "ioc": IP + ":443", "threat_type": "botnet_cc", "malware_printable": None}],
                },
            )
        },
        True,
    ),
    (
        "threatfox url, bare",
        "threatfox",
        "get-url-report",
        "abusech",
        "url",
        "http://evil.top/x",
        {"threatfox-api.abuse.ch": (200, {"query_status": "ok", "data": [{"ioc": "http://evil.top/x"}]})},
        True,
    ),
    (
        "threatfox file",
        "threatfox",
        "get-file-report",
        "abusech",
        "sha256",
        SHA,
        {
            "threatfox-api.abuse.ch": (
                200,
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "id": "79",
                            "ioc": "1.2.3.4:80",
                            "threat_type_desc": "payload delivery",
                            "malware_printable": "Emotet",
                        }
                    ],
                },
            )
        },
        True,
    ),
    (
        "threatfox nothing",
        "threatfox",
        "get-domain-report",
        "abusech",
        "domain",
        "evil.example.com",
        {
            "threatfox-api.abuse.ch": (
                200,
                {"query_status": "no_result", "data": "Your search did not yield any results"},
            )
        },
        False,
    ),
    (
        "urlhaus url",
        "urlhaus",
        "get-url-report",
        "abusech",
        "url",
        "http://evil.top/x",
        {
            "urlhaus-api.abuse.ch": (
                200,
                {
                    "query_status": "ok",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
                    "url_status": "online",
                    "threat": "malware_download",
                },
            )
        },
        True,
    ),
    (
        "urlhaus url, bare",
        "urlhaus",
        "get-url-report",
        "abusech",
        "url",
        "http://evil.top/x",
        {"urlhaus-api.abuse.ch": (200, {"query_status": "ok"})},
        True,
    ),
    (
        "urlhaus url unknown",
        "urlhaus",
        "get-url-report",
        "abusech",
        "url",
        "http://evil.top/x",
        {"urlhaus-api.abuse.ch": (200, {"query_status": "no_results"})},
        False,
    ),
    (
        "urlhaus host",
        "urlhaus",
        "get-host-report",
        "abusech",
        "domain",
        "evil.example.com",
        {
            "urlhaus-api.abuse.ch": (
                200,
                {
                    "query_status": "ok",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.example.com/",
                    "url_count": "4",
                    "urls": [],
                },
            )
        },
        True,
    ),
    (
        "urlhaus host, one URL",
        "urlhaus",
        "get-host-report",
        "abusech",
        "domain",
        "evil.example.com",
        {"urlhaus-api.abuse.ch": (200, {"query_status": "ok", "url_count": 1})},
        True,
    ),
    (
        "urlhaus host unknown",
        "urlhaus",
        "get-host-report",
        "abusech",
        "domain",
        "evil.example.com",
        {"urlhaus-api.abuse.ch": (200, {"query_status": "no_results"})},
        False,
    ),
    # Google Safe Browsing.
    (
        "safebrowsing url",
        "safebrowsing",
        "check-url",
        "safebrowsing",
        "url",
        "http://evil.top/x",
        {"safebrowsing.googleapis.com": (200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})},
        True,
    ),
    (
        "safebrowsing domain, two lists",
        "safebrowsing",
        "check-domain",
        "safebrowsing",
        "domain",
        "evil.top",
        {
            "safebrowsing.googleapis.com": (
                200,
                {
                    "matches": [
                        {"threatType": "SOCIAL_ENGINEERING"},
                        {"threatType": "MALWARE"},
                        {"threatType": "MALWARE"},
                    ]
                },
            )
        },
        True,
    ),
    (
        "safebrowsing not listed",
        "safebrowsing",
        "check-url",
        "safebrowsing",
        "url",
        "http://example.com/",
        {"safebrowsing.googleapis.com": (200, {})},
        True,
    ),
    # Registration: the age of a domain is the verdict.
    (
        "rdap young domain",
        "rdap",
        "get-domain",
        "_registration",
        "domain",
        "example.top",
        {"rdap.org": (200, RDAP_DOMAIN)},
        True,
    ),
    (
        "rdap domain of one day",
        "rdap",
        "get-domain",
        "_registration",
        "domain",
        "example.top",
        {
            "rdap.org": (
                200,
                {**RDAP_DOMAIN, "events": [{"eventAction": "registration", "eventDate": "2027-01-14T07:00:00Z"}]},
            )
        },
        True,
    ),
    (
        "rdap old domain",
        "rdap",
        "get-domain",
        "_registration",
        "domain",
        "example.top",
        {
            "rdap.org": (
                200,
                {
                    **RDAP_DOMAIN,
                    "events": [
                        {"eventAction": "last changed", "eventDate": "2026-12-31T10:00:00Z"},
                        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                    ],
                },
            )
        },
        True,
    ),
    (
        "rdap domain of thirty days",
        "rdap",
        "get-domain",
        "_registration",
        "domain",
        "example.top",
        {
            "rdap.org": (
                200,
                {**RDAP_DOMAIN, "events": [{"eventAction": "registration", "eventDate": "2026-12-16T08:00:00Z"}]},
            )
        },
        True,
    ),
    (
        "rdap domain without a date",
        "rdap",
        "get-domain",
        "_registration",
        "domain",
        "example.top",
        {"rdap.org": (200, {"objectClassName": "domain", "ldhName": "example.top"})},
        True,
    ),
    (
        "rdap domain unknown",
        "rdap",
        "get-domain",
        "_registration",
        "domain",
        "example.top",
        {"rdap.org": (404, {"errorCode": 404, "title": "Not Found"})},
        True,
    ),
    ("rdap network", "rdap", "get-ip", "_registration", "ip", IP, {"rdap.org": (200, RDAP_NETWORK)}, True),
    (
        "rdap network, bare",
        "rdap",
        "get-ip",
        "_registration",
        "ip",
        IP,
        {"rdap.org": (200, {"objectClassName": "ip network"})},
        True,
    ),
    (
        "rdap network unknown",
        "rdap",
        "get-ip",
        "_registration",
        "ip",
        IP,
        {"rdap.org": (404, {"errorCode": 404, "title": "Not Found"})},
        True,
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_a_reputation_command_says_what_the_look_up_says(case, monkeypatch):
    _name, connector_id, command, provider, kind, value, answers, line_too = case

    def answered(host: str) -> tuple[int, object]:
        return next((answer for name, answer in answers.items() if host == name), (404, None))

    def request(url, *, headers=None, form=None, body=None):
        # As the look-ups read an answer: a 404 has no body.
        status, answer = answered(urlsplit(url).hostname or "")
        return status, None if status == 404 else answer

    monkeypatch.setattr(providers, "_request", request)
    # The registries are found through IANA's files by the look-up and through rdap.org by the connector:
    # here both are asked the one server of the case.
    monkeypatch.setattr(registration, "domain_server", lambda tld: "https://rdap.org/")
    monkeypatch.setattr(registration, "ip_server", lambda address: "https://rdap.org/")
    monkeypatch.setattr(registration.time, "time", lambda: NOW)
    said = getattr(providers, provider)(kind, value, "the-key")

    connector = CONNECTORS[connector_id]
    config = {
        param.name: param.default for param in connector.configuration if not param.is_auth and param.type != "secret"
    }

    def wire(policy, method, url, **sent):
        host = urlsplit(url).hostname or ""
        status, answer = answered(host)
        return egress.Response(
            status=status,
            headers={"content-type": "application/json"},
            body=json.dumps(answer).encode(),
            record={"method": method, "host": host, "path": "/", "status": status},
        )

    host = ca.host_of(connector, config).split(":")[0]
    rt.forget_tokens()
    runtime = rt.Runtime(
        connector,
        config,
        {"value": "the-key", "api_key": "the-key"},
        egress.Policy(mode="listed", hosts=frozenset({host})),
        send=wire,
        clock=lambda: NOW,
    )
    gave = runtime.run(command, {connector.command(command).arguments[0].name: value}).outputs
    assert gave["verdict"] == said["verdict"]
    if line_too:
        assert gave["summary"] == said["summary"]
        assert gave["link"] == said["link"]


def test_every_look_up_has_a_command_that_stands_for_it():
    """Each kind of indicator a source judges has a reputation command in the source's connector."""
    stands = {
        "virustotal": {"virustotal": {"ip", "domain", "url", "file"}},
        "abuseipdb": {"abuseipdb": {"ip"}},
        "abusech": {
            "threatfox": {"ip", "domain", "url", "file"},
            "urlhaus": {"url", "domain", "file"},
            "malwarebazaar": {"file"},
        },
        "otx": {"otx": {"ip", "domain", "url", "file"}},
        "urlscan": {"urlscan": {"domain", "url"}},
        "greynoise": {"greynoise": {"ip"}},
        "internetdb": {"shodan": {"ip"}},
        "safebrowsing": {"safebrowsing": {"domain", "url"}},
        "registration": {"rdap": {"domain", "ip"}},
    }
    assert set(stands) == set(providers.BY_ID)
    for provider, connectors in stands.items():
        judged = set()
        for connector_id, kinds in connectors.items():
            have = {command.reputation for command in CONNECTORS[connector_id].commands if command.reputation}
            assert have == kinds, f"{connector_id}: {sorted(have)}"
            judged |= kinds
        wanted = {"file" if kind in providers.HASHES else kind for kind in providers.BY_ID[provider].types}
        assert judged == wanted, provider
