"""An indicator and the artifact that is its analysis: each leads to the other."""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app import analysis_links
from app.core.models import Artifact
from app.enrichment import service
from app.workers import previews
from tests.test_malware import STRINGS_PAYLOAD, fake_pe
from tests.test_urls import PHISH, browser  # noqa: F401 - browser is a fixture

SCANNED = "https://bit.ly/3xQ9a"


@pytest.fixture(autouse=True)
def fresh():
    analysis_links.reset_cache()
    yield
    analysis_links.reset_cache()


def _scan(admin: TestClient, url: str = SCANNED, incident: str | None = None) -> dict:
    body = {"url": url, **({"incident": incident} if incident else {})}
    made = admin.post("/api/artifacts/urls", json=body)
    assert made.status_code == 201, made.text
    return made.json()


def test_an_analysis_speaks_as_a_reputation_only_when_it_flags():
    def artifact(kind: str, verdict: str) -> Artifact:
        return Artifact(id=f"{kind}-x", kind=kind, ref="x", verdict=verdict)

    assert analysis_links.reputation(artifact("url", "phishing")) == "malicious"
    assert analysis_links.reputation(artifact("url", "suspicious")) == "suspicious"
    assert analysis_links.reputation(artifact("file", "high")) == "malicious"
    assert analysis_links.reputation(artifact("file", "medium")) == "suspicious"
    # A clean scan, a file no rule matches: not a judgement that the value is harmless.
    assert analysis_links.reputation(artifact("url", "clean")) is None
    assert analysis_links.reputation(artifact("file", "")) is None
    assert analysis_links.scan_id_of("http://192.168.1.10/admin") is None

    # Nik's analysis has the highest weight, and counts only when it flags.
    assert service.overall([("nik", "malicious")])["score"] == 100
    both = service.overall([("virustotal", "harmless"), ("nik", "malicious")])
    assert both["verdict"] == "malicious" and both["score"] == 50 and both["checked"] == 2
    assert service.overall([("virustotal", "harmless"), ("nik", "unknown")]) == service.overall(
        [("virustotal", "harmless")]
    )


def test_the_indicator_shows_the_analysis_and_counts_it_among_its_sources(admin: TestClient, browser):  # noqa: F811
    before = admin.get("/api/enrichment", params={"type": "url", "value": SCANNED}).json()
    assert before["analysis"]["artifacts"] == [] and before["analysis"]["canAnalyse"] is True
    assert before["analysis"]["verdict"] is None and before["summary"] is None

    scan = _scan(admin)
    detail = admin.get("/api/enrichment", params={"type": "url", "value": "hxxps://bit[.]ly/3xQ9a"}).json()
    analysis = detail["analysis"]
    assert analysis["label"] == "Nik's analysis" and analysis["weight"] == 3 and analysis["verdict"] == "malicious"
    shown = analysis["artifacts"][0]
    assert shown["id"] == scan["artifactId"] and shown["verdict"] == "phishing" and shown["score"] >= 70
    assert shown["finalUrl"] == PHISH and shown["screenshot"] is True and shown["findings"]
    assert detail["summary"]["verdict"] == "malicious" and detail["summary"]["checked"] == 1

    # For the whole domain a page on it is a warning, not a verdict.
    domain = admin.get("/api/enrichment", params={"type": "domain", "value": "bit.ly"}).json()
    assert domain["analysis"]["artifacts"][0]["id"] == scan["artifactId"]
    assert domain["analysis"]["verdict"] == "suspicious" and domain["summary"]["verdict"] == "suspicious"
    # An address that cannot be visited is never offered for analysis.
    internal = admin.get("/api/enrichment", params={"type": "domain", "value": "fileserver.corp"}).json()
    assert internal["analysis"]["canAnalyse"] is False

    # The artifact names the indicator it is the analysis of.
    artifact = admin.get(f"/api/artifacts/{scan['artifactId']}").json()
    assert artifact["indicator"] == {"type": "url", "value": SCANNED}


def test_a_file_is_the_analysis_of_its_hashes(admin: TestClient):
    data = fake_pe(payload=STRINGS_PAYLOAD)
    sha = hashlib.sha256(data).hexdigest()
    made = admin.post("/api/artifacts/files", files={"file": ("invoice.exe", data)}).json()
    assert admin.get(f"/api/artifacts/{made['id']}").json()["indicator"] == {"type": "sha256", "value": sha}
    for kind, value in (("sha256", sha), ("md5", hashlib.md5(data).hexdigest())):  # noqa: S324
        detail = admin.get("/api/enrichment", params={"type": kind, "value": value}).json()
        assert [a["id"] for a in detail["analysis"]["artifacts"]] == [made["id"]], kind
        assert detail["analysis"]["canAnalyse"] is False


def test_artifacts_on_their_own_are_in_the_library_and_in_seen_in(admin: TestClient, browser):  # noqa: F811
    scan = _scan(admin)
    library = admin.get("/api/iocs").json()
    rows = {(r["type"], r["value"]): r for r in library["iocs"]}
    scanned = rows[("url", SCANNED)]
    assert scanned["origin"] == "artifact" and scanned["incidents"] == 0
    assert scanned["analysis"]["id"] == scan["artifactId"] and scanned["analysis"]["verdict"] == "phishing"
    assert scanned["verdict"] == "malicious" and scanned["artifacts"][0]["id"] == scan["artifactId"]
    assert rows[("url", PHISH)]["origin"] == "artifact" and rows[("url", PHISH)]["analysis"] is None
    assert rows[("url", PHISH)]["canAnalyse"] is True

    assert [r["value"] for r in admin.get("/api/iocs?origin=artifact&analysis=done&type=url").json()["iocs"]] == [
        SCANNED
    ]
    waiting = admin.get("/api/iocs?analysis=none&type=url").json()
    assert PHISH in [r["value"] for r in waiting["iocs"]] and SCANNED not in [r["value"] for r in waiting["iocs"]]
    assert (
        library["counts"]["toAnalyse"]
        == waiting["total"] + admin.get("/api/iocs?analysis=none&type=domain").json()["total"]
    )

    seen = admin.get("/api/iocs/lookup", params={"type": "url", "value": PHISH}).json()
    assert seen["incidents"] == [] and [a["id"] for a in seen["artifacts"]] == [scan["artifactId"]]

    # Removing takes away what an analyst added; the artifact's indicator stays.
    admin.post("/api/iocs", json={"items": [{"type": "url", "value": PHISH, "note": "landing"}]})
    removed = admin.post("/api/iocs/remove", json={"items": [{"type": "url", "value": PHISH}]}).json()
    assert removed == {"removed": 0, "kept": 1}


def test_a_source_of_an_incident_names_its_artifact(admin: TestClient, browser):  # noqa: F811
    admin.post("/api/incidents", json={"id": "u1", "name": "u1", "data": {}})
    scan = _scan(admin, incident="u1")
    seen = admin.get("/api/iocs/lookup", params={"type": "url", "value": PHISH}).json()
    assert seen["artifacts"] == []  # in an incident: not on its own
    place = seen["incidents"][0]
    assert place["id"] == "u1" and place["sourceArtifacts"] == {s: scan["artifactId"] for s in place["sources"]}
    assert all(source.startswith("url:") for source in place["sources"])


def test_addresses_are_analysed_together_only_when_asked_and_never_the_internal_ones(
    admin: TestClient,
    browser,  # noqa: F811
    monkeypatch,
):
    _scan(admin)
    # The fake browser gives every visit the same session: here each needs its own.
    opened = previews.open_session
    sessions = iter(f"{n:032x}" for n in range(1, 50))

    def open_session(owner, network, html=None, url=None):
        return {**opened(owner, network, html, url), "id": next(sessions)}

    monkeypatch.setattr(previews, "open_session", open_session)
    admin.post(
        "/api/iocs",
        json={
            "text": f"https://fresh.example.org/login\nhttp://192.168.1.10/admin\n{SCANNED}\n185.220.101.47\nnew.example.net"
        },
    )
    scope = {"filters": {"origin": "added"}}
    visits = browser.count(("act", "inspect"))

    dry = admin.post("/api/iocs/analyse", json={"scope": scope, "dryRun": True}).json()
    assert sorted(dry["visit"]) == ["https://fresh.example.org/login", "https://new.example.net/"]
    reasons = {item["value"]: item["reason"] for item in dry["skipped"]}
    assert reasons[SCANNED] == "analysed already" and reasons["185.220.101.47"] == "not an address"
    # A private address is on the default allowlist; off it, the scan itself refuses it.
    assert reasons["http://192.168.1.10/admin"] == "on the allowlist"
    assert dry["started"] == [] and browser.count(("act", "inspect")) == visits  # nothing visited yet

    done = admin.post("/api/iocs/analyse", json={"scope": scope}).json()
    assert len(done["started"]) == 2 and browser.count(("act", "inspect")) == visits + 2
    assert all(admin.get(f"/api/artifacts/{item['artifactId']}").status_code == 200 for item in done["started"])
    again = admin.post("/api/iocs/analyse", json={"scope": scope, "dryRun": True}).json()
    assert again["visit"] == []

    # Off the allowlist, an internal host is still never visited.
    shared = admin.get("/api/settings").json()
    shared["iocAllowlist"] = []
    assert admin.put("/api/settings", json=shared).status_code == 200
    internal = admin.post(
        "/api/iocs/analyse",
        json={"scope": {"items": [{"type": "url", "value": "http://192.168.1.10/admin"}]}, "dryRun": True},
    ).json()
    assert internal["visit"] == [] and internal["skipped"][0]["reason"].startswith("cannot be visited")

    many = "\n".join(f"https://host{n}.example.org/" for n in range(21))
    admin.post("/api/iocs", json={"text": many, "list": {"name": "Many"}})
    listed = next(entry for entry in admin.get("/api/iocs/lists").json()["lists"] if entry["name"] == "Many")
    # More than the limit: the first 20 are offered, the rest waits for the next time.
    plan = admin.post("/api/iocs/analyse", json={"scope": {"list": listed["id"]}, "dryRun": True}).json()
    assert len(plan["visit"]) == 20 and plan["max"] == 20
    assert [item["reason"] for item in plan["skipped"]] == ["over the limit of 20 at a time"]
