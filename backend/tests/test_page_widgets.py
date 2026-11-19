"""Two widgets of an incident page: the incidents linked to one, and a chart narrowed to it."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app import iocs, page_widgets
from app.core.db import SessionLocal
from app.core.models import Incident
from tests.conftest import make_key
from tests.test_dashboards import made
from tests.test_fields import incident, put


def indicators(incident_id: str, *values: tuple[str, str]) -> None:
    with SessionLocal() as db:
        row = db.get(Incident, incident_id)
        for kind, value in values:
            assert iocs.add_manual(db, row, kind, value, "test") is not None
        db.commit()


def linked(admin: TestClient, incident_id: str = "i1", headers=None) -> dict:
    answer = admin.get(f"/api/incidents/{incident_id}/linked", headers=headers)
    assert answer.status_code == 200, answer.text
    return answer.json()


# --------------------------------------------------------------------------- #
# Linked incidents                                                            #
# --------------------------------------------------------------------------- #
def test_incidents_are_linked_by_the_field_and_by_the_indicators_they_share(admin: TestClient):
    for incident_id in ("i1", "i2", "i3", "i4", "i5"):
        incident(admin, incident_id, name=f"Case {incident_id}", severity="high")
    assert linked(admin) == {"incidents": [], "total": 0}

    indicators("i1", ("ip", "185.220.101.47"), ("domain", "inv0ice-portal.example"), ("domain", "www.google.com"))
    indicators("i2", ("ip", "185.220.101.47"), ("domain", "www.google.com"))
    indicators("i3", ("ip", "185.220.101.47"), ("domain", "inv0ice-portal.example"), ("domain", "www.google.com"))
    indicators("i4", ("domain", "www.google.com"))
    # A well-known value links nothing: it would link everything.
    assert admin.put("/api/settings", json={"iocAllowlist": ["google.com"]}).status_code == 200

    found = linked(admin)
    assert found["total"] == 2
    # Those that share the most first.
    assert [(item["id"], item["shared"], item["related"]) for item in found["incidents"]] == [
        ("i3", 2, False),
        ("i2", 1, False),
    ]
    first = found["incidents"][0]
    assert (first["name"], first["status"], first["severity"], first["type"]) == (
        "Case i3",
        "open",
        "high",
        "Unclassified",
    )
    assert first["number"] and first["indicators"] == [
        {"type": "domain", "value": "inv0ice-portal.example"},
        {"type": "ip", "value": "185.220.101.47"},
    ]

    # An incident the field names comes first, whatever it shares; the link is seen from both sides.
    numbered = admin.get("/api/incidents/i5").json()["number"]
    assert put(admin, {"related_incidents": ["i4", f"#{numbered}", "gone"]}).status_code == 200
    found = linked(admin)
    assert sorted(item["id"] for item in found["incidents"][:2]) == ["i4", "i5"]
    assert all(item["related"] and item["shared"] == 0 for item in found["incidents"][:2])
    assert [item["id"] for item in found["incidents"][2:]] == ["i3", "i2"] and found["total"] == 4
    back = linked(admin, "i4")
    assert [(item["id"], item["related"]) for item in back["incidents"]] == [("i1", True)]
    # One that is both is there once.
    assert put(admin, {"related_incidents": ["i3"]}).status_code == 200
    found = linked(admin)
    assert [(item["id"], item["related"], item["shared"]) for item in found["incidents"]] == [
        ("i3", True, 2),
        ("i2", False, 1),
    ]

    # Ten at most; whoever reads incidents reads this.
    with SessionLocal() as db:
        assert len(page_widgets.linked(db, db.get(Incident, "i1"), iocs.Allowlist([]), limit=1)["incidents"]) == 1
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert linked(admin, headers=viewer)["total"] == 2
    assert admin.get("/api/incidents/nope/linked").status_code == 404
    builder = make_key(admin, label="b", roles=["playbooks"])
    assert admin.get("/api/incidents/i1/linked", headers=builder).status_code == 403


# --------------------------------------------------------------------------- #
# A chart narrowed to the incident                                            #
# --------------------------------------------------------------------------- #
WIDGETS = [
    {"id": "sev", "title": "By severity", "type": "bar", "entity": "incidents", "query": "status:open",
     "groupBy": ["severity"], "x": 0, "y": 0, "w": 5, "h": 3},
    {"id": "all", "title": "All", "type": "number", "entity": "incidents", "x": 5, "y": 0, "w": 3, "h": 2},
    {"id": "note", "type": "text", "options": {"text": "# Notes"}, "x": 0, "y": 3, "w": 4, "h": 2},
]  # fmt: skip


def chart(admin: TestClient, headers=None, **params):
    return admin.get("/api/incidents/i1/chart", params=params, headers=headers)


def test_the_query_of_a_widget_is_narrowed_by_one_field_of_the_incident():
    assert page_widgets.condition("host", "WS-0231") == 'host:"WS-0231"'
    # Quoted, so that nothing a field holds is read as a wildcard, a group or another condition.
    assert page_widgets.condition("host", 'a "b" \\ * or status:open') == 'host:"a \\"b\\" \\\\ * or status:open"'
    assert page_widgets.condition("tags", ["a", "b c"]) == 'tags IN ("a", "b c")'
    assert page_widgets.condition("tags", ["only", ""]) == 'tags:"only"'
    assert page_widgets.narrowed("status:open or status:closed", "host", "x") == (
        '(status:open or status:closed) (host:"x")'
    )
    assert page_widgets.narrowed("  ", "host", "x") == 'host:"x"'


def test_a_chart_of_a_dashboard_is_read_for_an_incident(admin: TestClient):
    incident(admin, host="WS-0231", username="anna", severity="high")
    incident(admin, "i2", host="WS-0231")
    incident(admin, "i3", host="SRV-1")
    board = made(admin, widgets=WIDGETS, timeRange="7d", filter="!status:closed", filterEntity="incidents")

    found = chart(admin, dashboard=board["id"], widget="sev", field="host")
    assert found.status_code == 200, found.text
    shown = found.json()
    assert (shown["empty"], shown["value"], shown["field"], shown["title"]) == (False, "WS-0231", "host", "By severity")
    assert shown["widget"]["query"] == '(status:open) (host:"WS-0231")'
    assert shown["widget"]["groupBy"] == ["severity"] and shown["widget"]["type"] == "bar"
    assert shown["board"] == {
        "id": board["id"],
        "name": "Mine",
        "filter": "!status:closed",
        "filterEntity": "incidents",
        "timeRange": "7d",
    }
    # The narrowed query is one the query language runs: two incidents share the host.
    counted = admin.post(
        "/api/query/aggregate", json={"entity": "incidents", "query": shown["widget"]["query"], "measure": "count"}
    )
    assert counted.status_code == 200 and counted.json()["total"] == 2

    # An incident that was given no type has none to narrow by.
    assert chart(admin, dashboard=board["id"], widget="all", field="type").json()["empty"] is True
    assert admin.get("/api/incident-types").status_code == 200  # the shipped types are there from now on
    # A field under another of its names; the type by its name; the incident itself.
    assert chart(admin, dashboard=board["id"], widget="all", field="user").json()["widget"]["query"] == (
        'username:"anna"'
    )
    assert put(admin, {"type": "phishing"}).status_code == 200
    assert chart(admin, dashboard=board["id"], widget="all", field="type").json()["value"] == "Phishing"
    assert chart(admin, dashboard=board["id"], widget="all", field="id").json()["widget"]["query"] == 'id:"i1"'

    # Nothing on the incident for the field: no chart of everything.
    empty = chart(admin, dashboard=board["id"], widget="sev", field="ticket").json()
    assert empty["empty"] is True and empty["widget"] is None and empty["field"] == "ticket"

    def refused(**params) -> tuple[int, str]:
        answer = chart(admin, **params)
        return answer.status_code, answer.json()["detail"]

    assert refused(dashboard="nope", widget="sev", field="host") == (
        404,
        "The dashboard of this chart is gone, or is not shared with you",
    )
    assert refused(dashboard=board["id"], widget="gone", field="host") == (404, "Mine no longer has this widget")
    assert refused(dashboard=board["id"], widget="note", field="host")[1].startswith("This widget asks no query")
    assert refused(dashboard=board["id"], widget="sev", field="sender_domain")[1].startswith(
        '"sender_domain" is not a field of incidents in the query language'
    )
    assert refused(dashboard=board["id"], widget="sev", field="")[1].startswith("Choose the field")
    assert admin.get("/api/incidents/nope/chart", params={"dashboard": board["id"], "widget": "sev"}).status_code == 404

    # A dashboard is read as the person looking: one that is not shared with them is not found.
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert chart(admin, headers=viewer, dashboard=board["id"], widget="sev", field="host").status_code == 404
    shared = admin.put(f"/api/dashboards/{board['id']}/sharing", json={"everyone": True})
    assert shared.status_code == 200, shared.text
    assert chart(admin, headers=viewer, dashboard=board["id"], widget="sev", field="host").status_code == 200
