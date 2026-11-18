"""Dashboards: whose they are, who sees them, and what a widget may be."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app import dashboards
from app.main import app
from tests.conftest import make_key

WIDGETS = [
    {"id": "open", "title": "Open incidents", "type": "number", "entity": "incidents", "query": "status:open",
     "options": {"compare": True, "timeField": "created"}, "x": 0, "y": 0, "w": 3, "h": 2},
    {"id": "sev", "title": "By severity", "type": "bar", "entity": "incidents", "query": "status:open",
     "groupBy": ["severity"], "x": 3, "y": 0, "w": 5, "h": 3},
    {"id": "trend", "title": "New per day", "type": "trend", "entity": "incidents", "groupBy": ["created@day"],
     "options": {"timeField": "created"}, "x": 0, "y": 3, "w": 12, "h": 3},
    {"id": "ttc", "title": "Time to close", "type": "duration", "entity": "incidents", "query": "status:closed",
     "measure": "median:duration(created,closed)", "x": 8, "y": 0, "w": 4, "h": 2},
    {"id": "note", "type": "text", "options": {"text": "# Shift notes"}, "x": 0, "y": 6, "w": 4, "h": 2},
]  # fmt: skip


def made(client: TestClient, headers=None, **body) -> dict:
    answer = client.post("/api/dashboards", json={"name": "Mine", **body}, headers=headers)
    assert answer.status_code == 201, answer.text
    return answer.json()


def refused(client: TestClient, widget: dict) -> str:
    answer = client.post("/api/dashboards", json={"name": "No", "widgets": [widget]})
    assert answer.status_code == 400, answer.text
    return answer.json()["detail"]


def test_a_dashboard_keeps_its_widgets_as_they_were_checked(admin: TestClient):
    board = made(admin, widgets=WIDGETS, timeRange="7d", refreshSeconds=10, description="The shift")
    assert board["owner"] == "admin" and not board["builtin"] and not board["shared"] and board["canEdit"]
    assert board["timeRange"] == "7d" and board["refreshSeconds"] == 30  # never faster than half a minute
    by_id = {widget["id"]: widget for widget in board["widgets"]}
    assert by_id["open"] == {
        "id": "open", "title": "Open incidents", "type": "number", "entity": "incidents", "query": "status:open",
        "groupBy": [], "measure": "count", "options": {"timeField": "created", "compare": True},
        "x": 0, "y": 0, "w": 3, "h": 2,
    }  # fmt: skip
    assert by_id["trend"]["groupBy"] == ["created@day"] and by_id["ttc"]["measure"] == "median:duration(created,closed)"
    assert by_id["note"] == {
        "id": "note", "title": "", "type": "text", "options": {"text": "# Shift notes"}, "x": 0, "y": 6, "w": 4, "h": 2,
    }  # fmt: skip
    # The list gives no widgets; one dashboard gives them all.
    listed = admin.get("/api/dashboards").json()
    assert [(row["name"], row["widgetCount"]) for row in listed["dashboards"] if not row["builtin"]] == [("Mine", 5)]
    assert "widgets" not in listed["dashboards"][-1] and "number" in listed["types"]
    # What is left out of a change stays.
    renamed = admin.put(f"/api/dashboards/{board['id']}", json={"name": "Shift"}).json()
    assert renamed["name"] == "Shift" and len(renamed["widgets"]) == 5 and renamed["description"] == "The shift"
    assert admin.delete(f"/api/dashboards/{board['id']}").status_code == 204
    assert admin.get(f"/api/dashboards/{board['id']}").status_code == 404


def test_widgets_never_overlap_and_leave_no_hole_above(admin: TestClient):
    def at(*boxes):
        widgets = [
            {"id": f"w{index}", "type": "text", "x": x, "y": y, "w": w, "h": h}
            for index, (x, y, w, h) in enumerate(boxes)
        ]
        return [(w["id"], w["x"], w["y"]) for w in dashboards.clean_widgets(widgets)]

    # Two on the same cells: the second in reading order goes under the first.
    assert at((0, 0, 6, 2), (3, 0, 6, 2)) == [("w0", 0, 0), ("w1", 3, 2)]
    # One with room above moves up; one beside another stays beside it.
    assert at((0, 5, 4, 2), (4, 5, 4, 2)) == [("w0", 0, 0), ("w1", 4, 0)]
    # A widget is kept inside the twelve columns.
    assert at((10, 0, 6, 2)) == [("w0", 6, 0)]
    # One that says nothing of where it is goes to the end.
    placed = dashboards.clean_widgets([{"type": "text", "x": 0, "y": 0, "w": 12, "h": 2}, {"type": "text"}])
    assert (placed[1]["x"], placed[1]["y"], placed[1]["w"], placed[1]["h"]) == (0, 2, 4, 2)
    assert placed[0]["id"] != placed[1]["id"]


def test_a_widget_that_cannot_be_asked_is_refused_with_why(admin: TestClient):
    base = {"type": "bar", "entity": "incidents", "groupBy": ["severity"]}
    assert "its type is one of" in refused(admin, {"type": "hologram"})
    assert "Unknown entity" in refused(admin, {**base, "entity": "unicorns"})
    assert '"stauts" is not a field' in refused(admin, {**base, "query": "stauts:open"})
    assert "takes 1 group" in refused(admin, {**base, "groupBy": []})
    assert "takes no group" in refused(admin, {**base, "type": "number"})
    assert "takes 2 groups" in refused(admin, {**base, "type": "stacked_bar"})
    assert "over a date" in refused(admin, {**base, "type": "trend"})
    assert "not a number" in refused(admin, {**base, "measure": "avg:name"})
    assert "target above zero" in refused(admin, {"type": "gauge", "entity": "incidents"})
    assert "not a field of incidents" in refused(
        admin, {"type": "table", "entity": "incidents", "options": {"columns": ["name", "nothing"]}}
    )
    assert "time field is a date" in refused(admin, {**base, "options": {"timeField": "severity"}})
    assert admin.post("/api/dashboards", json={"widgets": []}).status_code == 400  # no name
    assert admin.post("/api/dashboards", json={"name": "x", "timeRange": "soon"}).status_code == 400
    assert admin.post("/api/dashboards", json={"name": "x", "filter": "nope:1"}).status_code == 400
    table = made(admin, widgets=[{"type": "table", "entity": "runs", "query": "status:failed",
                                  "options": {"columns": ["playbook", "started", "error"], "limit": 500}}])  # fmt: skip
    assert table["widgets"][0]["options"] == {"columns": ["playbook", "started", "error"], "limit": 100}


def test_a_dashboard_is_personal_until_someone_who_may_shares_it(admin: TestClient):
    viewer = make_key(admin, label="v", roles=["viewer"])
    analyst = make_key(admin, label="a", roles=["analyst"])
    sharer = make_key(admin, label="s", roles=["viewer", "dashboards"])
    other = TestClient(app)
    mine = made(other, headers=viewer, name="Viewer's")
    assert mine["owner"] == "api:v" and mine["canEdit"] and not mine["canShare"]
    path = f"/api/dashboards/{mine['id']}"

    def names(headers) -> list[str]:
        rows = other.get("/api/dashboards", headers=headers).json()["dashboards"]
        return [row["name"] for row in rows if not row["builtin"]]

    # Nobody else sees it, not even an administrator: it does not exist for them.
    assert names(analyst) == [] and names(viewer) == ["Viewer's"]
    assert other.get(path, headers=analyst).status_code == 404
    assert admin.get(path).status_code == 404
    assert other.put(path, json={"name": "Taken"}, headers=analyst).status_code == 404
    # Its owner cannot share it without the permission; who has it shares what they see.
    assert other.put(f"{path}/sharing", json={"everyone": True}, headers=viewer).status_code == 403
    assert other.put(f"{path}/sharing", json={"everyone": True}, headers=sharer).status_code == 404
    own = made(other, headers=sharer, name="Shared", widgets=WIDGETS[:2])
    shared_path = f"/api/dashboards/{own['id']}"
    shared = other.put(f"{shared_path}/sharing", json={"roles": ["analyst", "nope"]}, headers=sharer)
    assert shared.status_code == 200 and shared.json()["sharedWith"] == {
        "everyone": False, "roles": ["analyst"], "users": [],
    }  # fmt: skip
    assert names(analyst) == ["Shared"] and names(viewer) == ["Viewer's"]
    seen = other.get(shared_path, headers=analyst).json()
    assert seen["shared"] and not seen["canEdit"] and not seen["canShare"]
    # Who sees it without owning it cannot change or delete it; a copy is theirs.
    assert other.put(shared_path, json={"name": "Mine now"}, headers=analyst).status_code == 403
    assert other.delete(shared_path, headers=analyst).status_code == 403
    copy = other.post(f"{shared_path}/duplicate", headers=analyst)
    assert copy.status_code == 201 and copy.json()["owner"] == "api:a" and not copy.json()["shared"]
    assert copy.json()["name"] == "Shared" and len(copy.json()["widgets"]) == 2
    # A second copy does not take the name of the first.
    assert other.post(f"{shared_path}/duplicate", headers=analyst).json()["name"] == "Shared (2)"
    # Shared with one account by name, then with everyone, then with nobody again.
    assert other.put(f"{shared_path}/sharing", json={"users": ["api:v"]}, headers=sharer).status_code == 200
    # One's own first, then what others share.
    assert names(viewer) == ["Viewer's", "Shared"] and names(analyst) == ["Shared", "Shared (2)"]
    assert other.put(f"{shared_path}/sharing", json={"everyone": True}, headers=sharer).status_code == 200
    # Once shared, an administrator may change it; the change is in the audit log.
    assert admin.put(shared_path, json={"description": "Checked"}).status_code == 200
    actions = [
        entry["action"] for entry in admin.get("/api/audit", params={"q": "action:dashboard.*"}).json()["entries"]
    ]
    assert actions.count("dashboard.share") == 3 and "dashboard.update" in actions
    assert other.put(f"{shared_path}/sharing", json={}, headers=sharer).status_code == 200
    assert admin.get(shared_path).status_code == 404


def test_a_dashboard_goes_out_as_a_file_and_comes_back_as_ones_own(admin: TestClient):
    board = made(admin, name="SOC", widgets=WIDGETS, timeRange="24h", filter="severity:>=high")
    file = admin.get(f"/api/dashboards/{board['id']}/export").json()
    assert file["nik"] == "dashboard" and file["name"] == "SOC" and len(file["widgets"]) == 5
    assert "owner" not in file and "sharedWith" not in file and "id" not in file
    viewer = make_key(admin, label="v", roles=["viewer"])
    other = TestClient(app)
    back = other.post("/api/dashboards/import", json=file, headers=viewer)
    assert back.status_code == 201, back.text
    assert back.json()["owner"] == "api:v" and back.json()["filter"] == "severity:>=high"
    assert [w["id"] for w in back.json()["widgets"]] == [w["id"] for w in board["widgets"]]
    assert other.post("/api/dashboards/import", json={"name": "x"}, headers=viewer).status_code == 400
    broken = {**file, "widgets": [{"type": "bar", "entity": "incidents", "groupBy": ["nothing"]}]}
    assert other.post("/api/dashboards/import", json=broken, headers=viewer).status_code == 400
