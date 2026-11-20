"""What the reputation commands of the sources say, answer by answer.

A look-up of an indicator is the reputation command of a source's connector
(6.5). Each command is given here the answers a vendor gives (found, not
found, nothing, one, several, the edges of each threshold) and must say the
verdict, the line and the link written beside the case: they are what the
indicator's page shows and what the overall verdict is counted from, so a
connector file that changes one of them changes it here, on purpose.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import pytest

from app.automation import connector_actions as ca
from app.automation import connector_runtime as rt
from app.automation import egress
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


# (name, connector, command, kind, value, {host of the vendor: (status, answer)})
CASES = [
    (
        "vt ip",
        "virustotal",
        "get-ip-report",
        "ip",
        IP,
        {"www.virustotal.com": (200, _vt(STATS, country="DE"))},
    ),
    (
        "vt ip harmless",
        "virustotal",
        "get-ip-report",
        "ip",
        IP,
        {"www.virustotal.com": (200, _vt({"malicious": 0, "harmless": 60, "undetected": 10}))},
    ),
    (
        "vt domain two engines",
        "virustotal",
        "get-domain-report",
        "domain",
        "evil.example.com",
        {"www.virustotal.com": (200, _vt({"malicious": 2, "harmless": 60}))},
    ),
    (
        "vt domain three engines",
        "virustotal",
        "get-domain-report",
        "domain",
        "evil.example.com",
        {"www.virustotal.com": (200, _vt({"malicious": 3, "harmless": 60}))},
    ),
    (
        "vt file suspicious only",
        "virustotal",
        "get-file-report",
        "sha256",
        SHA,
        {"www.virustotal.com": (200, _vt({"malicious": 0, "suspicious": 1, "undetected": 70}))},
    ),
    (
        "vt file undetected only",
        "virustotal",
        "get-file-report",
        "sha256",
        SHA,
        {"www.virustotal.com": (200, _vt({"undetected": 70}))},
    ),
    (
        "vt file unknown",
        "virustotal",
        "get-file-report",
        "sha256",
        SHA,
        {"www.virustotal.com": (404, {"error": {"code": "NotFoundError"}})},
    ),
    (
        "vt url",
        "virustotal",
        "get-url-reputation",
        "url",
        "http://evil.top/x?a=1",
        {"www.virustotal.com": (200, _vt(STATS))},
    ),
    (
        "vt url unknown",
        "virustotal",
        "get-url-reputation",
        "url",
        "http://evil.top/x",
        {"www.virustotal.com": (404, {"error": {"code": "NotFoundError"}})},
    ),
    # AbuseIPDB.
    (
        "abuseipdb malicious",
        "abuseipdb",
        "check-ip",
        "ip",
        IP,
        {"api.abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 100, "totalReports": 42, "isp": "Tor"}})},
    ),
    (
        "abuseipdb two reports",
        "abuseipdb",
        "check-ip",
        "ip",
        IP,
        {
            "api.abuseipdb.com": (
                200,
                {"data": {"abuseConfidenceScore": 80, "totalReports": 2, "numDistinctUsers": 2, "isTor": True}},
            )
        },
    ),
    (
        "abuseipdb suspicious, one report",
        "abuseipdb",
        "check-ip",
        "ip",
        IP,
        {"api.abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 25, "totalReports": 1}})},
    ),
    (
        "abuseipdb below",
        "abuseipdb",
        "check-ip",
        "ip",
        IP,
        {"api.abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 24, "totalReports": 3}})},
    ),
    (
        "abuseipdb whitelisted",
        "abuseipdb",
        "check-ip",
        "ip",
        IP,
        {"api.abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 90, "totalReports": 9, "isWhitelisted": True}})},
    ),
    (
        "abuseipdb nothing",
        "abuseipdb",
        "check-ip",
        "ip",
        IP,
        {
            "api.abuseipdb.com": (
                200,
                {"data": {"abuseConfidenceScore": None, "totalReports": None, "isWhitelisted": None}},
            )
        },
    ),
    # Shodan InternetDB.
    (
        "internetdb c2",
        "shodan",
        "check-ip",
        "ip",
        IP,
        {"internetdb.shodan.io": (200, {"ports": [22, 443], "vulns": ["CVE-1"], "tags": ["c2"]})},
    ),
    (
        "internetdb tor",
        "shodan",
        "check-ip",
        "ip",
        IP,
        {"internetdb.shodan.io": (200, {"ports": [22], "cpes": ["cpe:/a:x"], "vulns": [], "tags": ["tor"]})},
    ),
    (
        "internetdb tor and botnet",
        "shodan",
        "check-ip",
        "ip",
        IP,
        {"internetdb.shodan.io": (200, {"ports": [], "vulns": ["CVE-1", "CVE-2"], "tags": ["tor", "botnet", "cloud"]})},
    ),
    (
        "internetdb many ports",
        "shodan",
        "check-ip",
        "ip",
        IP,
        {"internetdb.shodan.io": (200, {"ports": list(range(20, 32)), "tags": ["a", "b", "c", "d", "e", "f"]})},
    ),
    (
        "internetdb unknown",
        "shodan",
        "check-ip",
        "ip",
        IP,
        {"internetdb.shodan.io": (404, {"detail": "No information available"})},
    ),
    # GreyNoise Community.
    (
        "greynoise malicious",
        "greynoise",
        "get-community-ip",
        "ip",
        IP,
        {"api.greynoise.io": (200, {"noise": True, "riot": False, "classification": "malicious", "name": "unknown"})},
    ),
    (
        "greynoise business service",
        "greynoise",
        "get-community-ip",
        "ip",
        IP,
        {"api.greynoise.io": (200, {"noise": False, "riot": True, "classification": "benign", "name": "Example DNS"})},
    ),
    (
        "greynoise benign scanner",
        "greynoise",
        "get-community-ip",
        "ip",
        IP,
        {
            "api.greynoise.io": (
                200,
                {"noise": True, "riot": False, "classification": "benign", "name": "Example Scanner"},
            )
        },
    ),
    (
        "greynoise not seen",
        "greynoise",
        "get-community-ip",
        "ip",
        IP,
        {
            "api.greynoise.io": (
                404,
                {"message": "IP not observed scanning the internet or contained in RIOT data set."},
            )
        },
    ),
    # urlscan.io: malicious in either shape of the answer.
    (
        "urlscan url",
        "urlscan",
        "get-url-reputation",
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
    ),
    (
        "urlscan domain, one scan",
        "urlscan",
        "get-domain-reputation",
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
    ),
    (
        "urlscan never scanned",
        "urlscan",
        "get-domain-reputation",
        "domain",
        "evil.top",
        {"urlscan.io": (200, {"total": 0, "results": []})},
    ),
    # OTX.
    (
        "otx one pulse",
        "otx",
        "get-domain-reputation",
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
    ),
    (
        "otx two pulses",
        "otx",
        "get-ip-reputation",
        "ip",
        IP,
        {"otx.alienvault.com": (200, {"pulse_info": {"count": 2, "pulses": []}})},
    ),
    (
        "otx whitelisted",
        "otx",
        "get-domain-reputation",
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
    ),
    (
        "otx no pulse",
        "otx",
        "get-file-reputation",
        "sha256",
        SHA,
        {"otx.alienvault.com": (200, {"pulse_info": {"count": 0, "pulses": []}, "validation": []})},
    ),
    (
        "otx unknown",
        "otx",
        "get-file-reputation",
        "sha256",
        SHA,
        {"otx.alienvault.com": (404, {"detail": "Not found."})},
    ),
    # abuse.ch, one service at a time.
    (
        "malwarebazaar sample",
        "malwarebazaar",
        "get-file-report",
        "sha256",
        SHA,
        {
            "mb-api.abuse.ch": (
                200,
                {"query_status": "ok", "data": [{"sha256_hash": SHA, "signature": "AgentTesla", "tags": ["exe"]}]},
            )
        },
    ),
    (
        "malwarebazaar sample without a family",
        "malwarebazaar",
        "get-file-report",
        "sha256",
        SHA,
        {"mb-api.abuse.ch": (200, {"query_status": "ok", "data": [{"sha256_hash": SHA, "signature": None}]})},
    ),
    (
        "malwarebazaar unknown",
        "malwarebazaar",
        "get-file-report",
        "sha256",
        SHA,
        {"mb-api.abuse.ch": (200, {"query_status": "hash_not_found"})},
    ),
    (
        "threatfox domain",
        "threatfox",
        "get-domain-report",
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
    ),
    (
        "threatfox ip without a family",
        "threatfox",
        "get-ip-report",
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
    ),
    (
        "threatfox url, bare",
        "threatfox",
        "get-url-report",
        "url",
        "http://evil.top/x",
        {"threatfox-api.abuse.ch": (200, {"query_status": "ok", "data": [{"ioc": "http://evil.top/x"}]})},
    ),
    (
        "threatfox file",
        "threatfox",
        "get-file-report",
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
    ),
    (
        "threatfox nothing",
        "threatfox",
        "get-domain-report",
        "domain",
        "evil.example.com",
        {
            "threatfox-api.abuse.ch": (
                200,
                {"query_status": "no_result", "data": "Your search did not yield any results"},
            )
        },
    ),
    (
        "urlhaus url",
        "urlhaus",
        "get-url-report",
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
    ),
    (
        "urlhaus url, bare",
        "urlhaus",
        "get-url-report",
        "url",
        "http://evil.top/x",
        {"urlhaus-api.abuse.ch": (200, {"query_status": "ok"})},
    ),
    (
        "urlhaus url unknown",
        "urlhaus",
        "get-url-report",
        "url",
        "http://evil.top/x",
        {"urlhaus-api.abuse.ch": (200, {"query_status": "no_results"})},
    ),
    (
        "urlhaus host",
        "urlhaus",
        "get-host-report",
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
    ),
    (
        "urlhaus host, one URL",
        "urlhaus",
        "get-host-report",
        "domain",
        "evil.example.com",
        {"urlhaus-api.abuse.ch": (200, {"query_status": "ok", "url_count": 1})},
    ),
    (
        "urlhaus host unknown",
        "urlhaus",
        "get-host-report",
        "domain",
        "evil.example.com",
        {"urlhaus-api.abuse.ch": (200, {"query_status": "no_results"})},
    ),
    # Google Safe Browsing.
    (
        "safebrowsing url",
        "safebrowsing",
        "check-url",
        "url",
        "http://evil.top/x",
        {"safebrowsing.googleapis.com": (200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})},
    ),
    (
        "safebrowsing domain, two lists",
        "safebrowsing",
        "check-domain",
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
    ),
    (
        "safebrowsing not listed",
        "safebrowsing",
        "check-url",
        "url",
        "http://example.com/",
        {"safebrowsing.googleapis.com": (200, {})},
    ),
    # Registration: the age of a domain is the verdict.
    (
        "rdap young domain",
        "rdap",
        "get-domain",
        "domain",
        "example.top",
        {"rdap.org": (200, RDAP_DOMAIN)},
    ),
    (
        "rdap domain of one day",
        "rdap",
        "get-domain",
        "domain",
        "example.top",
        {
            "rdap.org": (
                200,
                {**RDAP_DOMAIN, "events": [{"eventAction": "registration", "eventDate": "2027-01-14T07:00:00Z"}]},
            )
        },
    ),
    (
        "rdap old domain",
        "rdap",
        "get-domain",
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
    ),
    (
        "rdap domain of thirty days",
        "rdap",
        "get-domain",
        "domain",
        "example.top",
        {
            "rdap.org": (
                200,
                {**RDAP_DOMAIN, "events": [{"eventAction": "registration", "eventDate": "2026-12-16T08:00:00Z"}]},
            )
        },
    ),
    (
        "rdap domain without a date",
        "rdap",
        "get-domain",
        "domain",
        "example.top",
        {"rdap.org": (200, {"objectClassName": "domain", "ldhName": "example.top"})},
    ),
    (
        "rdap domain unknown",
        "rdap",
        "get-domain",
        "domain",
        "example.top",
        {"rdap.org": (404, {"errorCode": 404, "title": "Not Found"})},
    ),
    ("rdap network", "rdap", "get-ip", "ip", IP, {"rdap.org": (200, RDAP_NETWORK)}),
    (
        "rdap network, bare",
        "rdap",
        "get-ip",
        "ip",
        IP,
        {"rdap.org": (200, {"objectClassName": "ip network"})},
    ),
    (
        "rdap network unknown",
        "rdap",
        "get-ip",
        "ip",
        IP,
        {"rdap.org": (404, {"errorCode": 404, "title": "Not Found"})},
    ),
]

# What each case must give: (verdict, line, link).
EXPECTED = {
    "vt ip": (
        "malicious",
        "7/88 engines flag it, 1 suspicious",
        "https://www.virustotal.com/gui/ip-address/93.184.216.34",
    ),
    "vt ip harmless": ("harmless", "0/70 engines flag it", "https://www.virustotal.com/gui/ip-address/93.184.216.34"),
    "vt domain two engines": (
        "suspicious",
        "2/62 engines flag it",
        "https://www.virustotal.com/gui/domain/evil.example.com",
    ),
    "vt domain three engines": (
        "malicious",
        "3/63 engines flag it",
        "https://www.virustotal.com/gui/domain/evil.example.com",
    ),
    "vt file suspicious only": (
        "suspicious",
        "0/71 engines flag it, 1 suspicious",
        "https://www.virustotal.com/gui/file/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
    "vt file undetected only": (
        "unknown",
        "0/70 engines flag it",
        "https://www.virustotal.com/gui/file/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
    "vt file unknown": (
        "unknown",
        "not in VirusTotal",
        "https://www.virustotal.com/gui/file/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
    "vt url": (
        "malicious",
        "7/88 engines flag it, 1 suspicious",
        "https://www.virustotal.com/gui/url/aHR0cDovL2V2aWwudG9wL3g_YT0x",
    ),
    "vt url unknown": ("unknown", "not in VirusTotal", "https://www.virustotal.com/gui/url/aHR0cDovL2V2aWwudG9wL3g"),
    "abuseipdb malicious": (
        "malicious",
        "confidence 100 %, 42 reports in 90 days",
        "https://www.abuseipdb.com/check/93.184.216.34",
    ),
    "abuseipdb two reports": (
        "malicious",
        "confidence 80 %, 2 reports in 90 days",
        "https://www.abuseipdb.com/check/93.184.216.34",
    ),
    "abuseipdb suspicious, one report": (
        "suspicious",
        "confidence 25 %, 1 report in 90 days",
        "https://www.abuseipdb.com/check/93.184.216.34",
    ),
    "abuseipdb below": (
        "unknown",
        "confidence 24 %, 3 reports in 90 days",
        "https://www.abuseipdb.com/check/93.184.216.34",
    ),
    "abuseipdb whitelisted": (
        "harmless",
        "confidence 90 %, 9 reports in 90 days",
        "https://www.abuseipdb.com/check/93.184.216.34",
    ),
    "abuseipdb nothing": (
        "unknown",
        "confidence 0 %, 0 reports in 90 days",
        "https://www.abuseipdb.com/check/93.184.216.34",
    ),
    "internetdb c2": ("malicious", "ports 22, 443; 1 CVE; tags c2", "https://www.shodan.io/host/93.184.216.34"),
    "internetdb tor": ("suspicious", "ports 22; tags tor", "https://www.shodan.io/host/93.184.216.34"),
    "internetdb tor and botnet": (
        "malicious",
        "no open port; 2 CVEs; tags tor, botnet, cloud",
        "https://www.shodan.io/host/93.184.216.34",
    ),
    "internetdb many ports": (
        "unknown",
        "ports 20, 21, 22, 23, 24, 25, 26, 27; tags a, b, c, d, e",
        "https://www.shodan.io/host/93.184.216.34",
    ),
    "internetdb unknown": ("unknown", "no open port known to Shodan", "https://www.shodan.io/host/93.184.216.34"),
    "greynoise malicious": ("malicious", "malicious internet scanner", "https://viz.greynoise.io/ip/93.184.216.34"),
    "greynoise business service": (
        "harmless",
        "common business service (Example DNS)",
        "https://viz.greynoise.io/ip/93.184.216.34",
    ),
    "greynoise benign scanner": (
        "harmless",
        "benign internet scanner (Example Scanner)",
        "https://viz.greynoise.io/ip/93.184.216.34",
    ),
    "greynoise not seen": ("unknown", "not seen scanning the internet", "https://viz.greynoise.io/ip/93.184.216.34"),
    "urlscan url": (
        "malicious",
        "37 public scans, 2 judged malicious",
        "https://urlscan.io/search/#page.url%3A%22http%3A//evil.top/x%22",
    ),
    "urlscan domain, one scan": ("unknown", "1 public scan", "https://urlscan.io/search/#page.domain%3A%22evil.top%22"),
    "urlscan never scanned": (
        "unknown",
        "never scanned on urlscan.io",
        "https://urlscan.io/search/#page.domain%3A%22evil.top%22",
    ),
    "otx one pulse": ("suspicious", "in 1 OTX pulse", "https://otx.alienvault.com/indicator/domain/evil.example.com"),
    "otx two pulses": ("suspicious", "in 2 OTX pulses", "https://otx.alienvault.com/indicator/ipv4/93.184.216.34"),
    "otx whitelisted": ("harmless", "whitelisted by OTX", "https://otx.alienvault.com/indicator/domain/example.com"),
    "otx no pulse": (
        "unknown",
        "in no OTX pulse",
        "https://otx.alienvault.com/indicator/file/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
    "otx unknown": (
        "unknown",
        "not in OTX",
        "https://otx.alienvault.com/indicator/file/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
    "malwarebazaar sample": (
        "malicious",
        "MalwareBazaar: AgentTesla",
        "https://bazaar.abuse.ch/sample/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
    ),
    "malwarebazaar sample without a family": (
        "malicious",
        "MalwareBazaar: known malware sample",
        "https://bazaar.abuse.ch/sample/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
    ),
    "malwarebazaar unknown": ("unknown", "not in MalwareBazaar", "https://bazaar.abuse.ch/"),
    "threatfox domain": ("malicious", "ThreatFox: Cobalt Strike (botnet C2)", "https://threatfox.abuse.ch/ioc/77/"),
    "threatfox ip without a family": ("malicious", "ThreatFox: botnet_cc", "https://threatfox.abuse.ch/ioc/78/"),
    "threatfox url, bare": ("malicious", "ThreatFox: known IOC", "https://threatfox.abuse.ch/"),
    "threatfox file": ("malicious", "ThreatFox: Emotet (payload delivery)", "https://threatfox.abuse.ch/ioc/79/"),
    "threatfox nothing": ("unknown", "not in ThreatFox", "https://threatfox.abuse.ch/"),
    "urlhaus url": ("malicious", "URLhaus: malware_download (online)", "https://urlhaus.abuse.ch/url/1/"),
    "urlhaus url, bare": ("malicious", "URLhaus: malware URL (status unknown)", "https://urlhaus.abuse.ch/"),
    "urlhaus url unknown": ("unknown", "not in URLhaus", "https://urlhaus.abuse.ch/"),
    "urlhaus host": (
        "suspicious",
        "URLhaus: 4 malware URLs on this host",
        "https://urlhaus.abuse.ch/host/evil.example.com/",
    ),
    "urlhaus host, one URL": ("suspicious", "URLhaus: 1 malware URL on this host", "https://urlhaus.abuse.ch/"),
    "urlhaus host unknown": ("unknown", "not in URLhaus", "https://urlhaus.abuse.ch/"),
    "safebrowsing url": (
        "malicious",
        "Google Safe Browsing: social engineering",
        "https://transparencyreport.google.com/safe-browsing/search?url=http%3A%2F%2Fevil.top%2Fx",
    ),
    "safebrowsing domain, two lists": (
        "malicious",
        "Google Safe Browsing: malware, social engineering",
        "https://transparencyreport.google.com/safe-browsing/search?url=evil.top",
    ),
    "safebrowsing not listed": (
        "unknown",
        "not on Google Safe Browsing lists",
        "https://transparencyreport.google.com/safe-browsing/search?url=http%3A%2F%2Fexample.com%2F",
    ),
    "rdap young domain": (
        "suspicious",
        "registered 15 days ago (2026-12-30), Example Registrar Inc.",
        "https://client.rdap.org/?type=domain&object=example.top",
    ),
    "rdap domain of one day": (
        "suspicious",
        "registered 1 day ago (2027-01-14), Example Registrar Inc.",
        "https://client.rdap.org/?type=domain&object=example.top",
    ),
    "rdap old domain": (
        "unknown",
        "registered 1995-08-14, Example Registrar Inc.",
        "https://client.rdap.org/?type=domain&object=example.top",
    ),
    "rdap domain of thirty days": (
        "unknown",
        "registered 2026-12-16, Example Registrar Inc.",
        "https://client.rdap.org/?type=domain&object=example.top",
    ),
    "rdap domain without a date": (
        "unknown",
        "registered an unknown date",
        "https://client.rdap.org/?type=domain&object=example.top",
    ),
    "rdap domain unknown": (
        "unknown",
        "the registry has no record of this domain",
        "https://client.rdap.org/?type=domain&object=example.top",
    ),
    "rdap network": (
        "unknown",
        "EXAMPLE-NET · Example Networks · US",
        "https://client.rdap.org/?type=ip&object=93.184.216.34",
    ),
    "rdap network, bare": ("unknown", "registered network", "https://client.rdap.org/?type=ip&object=93.184.216.34"),
    "rdap network unknown": (
        "unknown",
        "the registry has no record of this address",
        "https://client.rdap.org/?type=ip&object=93.184.216.34",
    ),
}


@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_a_reputation_command_says_this_of_this_answer(case):
    name, connector_id, command, _kind, value, answers = case
    connector = CONNECTORS[connector_id]
    config = {
        param.name: param.default for param in connector.configuration if not param.is_auth and param.type != "secret"
    }

    def wire(policy, method, url, **sent):
        host = urlsplit(url).hostname or ""
        status, answer = next((found for known, found in answers.items() if host == known), (404, None))
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
    assert (gave["verdict"], gave["summary"], gave["link"]) == EXPECTED[name]


def test_every_case_is_of_a_command_the_look_ups_would_choose():
    """A case stands for a look-up: its command is the one marked for the kind of its value."""
    for _name, connector_id, command, kind, _value, _answers in CASES:
        found = CONNECTORS[connector_id].command(command)
        assert found is not None and found.reputation == ("file" if kind == "sha256" else kind), command
        assert not found.premium and not found.changes_outside, command
