"""Lists: the store, what the settings became, and what playbooks do with them."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import lists
from app.automation import state
from app.core.db import SessionLocal
from app.core.models import NamedList, Setting
from app.defaults import DEFAULT_BUSINESS_HOURS
from app.iocs import DEFAULT_ALLOWLIST
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    echo,
    edge,
    go,
    node,
    playbook,
    steps,
    test_actions,
)


def seed() -> int:
    with SessionLocal() as db:
        added = lists.seed(db)
        db.commit()
        return added


def by_name(client: TestClient) -> dict[str, dict]:
    return {item["name"]: item for item in client.get("/api/lists").json()["lists"]}


def make(admin: TestClient, name: str, **more) -> dict:
    made = admin.post("/api/lists", json={"name": name, **more})
    assert made.status_code == 201, made.text
    return made.json()


def test_what_the_settings_held_becomes_lists_and_the_settings_api_stays_the_same(admin: TestClient):
    # A server that has been used: its settings hold values of its own.
    saved = admin.put(
        "/api/settings",
        json={
            "businessHours": {"startHour": 9, "endHour": 17, "flagWeekends": False},
            "iocAllowlist": ["corp.example", "10.0.0.0/8"],
            "mail": {"orgDomains": ["Corp.Example."], "trustedAuthServers": ["mx.corp.example"]},
        },
    )
    assert saved.status_code == 200, saved.text
    with SessionLocal() as db:
        # As a release before this one left it: the values in the document, no list.
        for row in db.scalars(select(NamedList)).all():
            db.delete(row)
        db.get(Setting, 1).doc = {
            "businessHours": {"startHour": 9, "endHour": 17, "flagWeekends": False},
            "iocAllowlist": ["corp.example", "10.0.0.0/8"],
            "mail": {"orgDomains": ["corp.example"], "trustedAuthServers": ["mx.corp.example"]},
        }
        state.write(db, enabled=True)
        db.get(Setting, 2).doc = {"enabled": True, "hosts": ["siem.corp"], "heartbeat": 0.0}
        db.commit()
    lists.clear_cache()

    assert seed() == 5 and seed() == 0  # once
    found = by_name(admin)
    assert set(lists.BUILTIN) <= set(found) and all(found[name]["builtin"] for name in lists.BUILTIN)
    assert (found["ioc_allowlist"]["items"], found["ioc_allowlist"]["kind"]) == (2, "values")
    assert found["business_hours"]["kind"] == "json" and found["business_hours"]["items"] is None
    assert found["ioc_allowlist"]["usedBy"] == ["Settings → Indicators → Allowlist"]
    hours = admin.get("/api/lists/business_hours").json()
    assert hours["document"] == {"startHour": 9, "endHour": 17, "flagWeekends": False}
    # The suspicious keywords are Sigma rules since 7.0: there is no list of them.
    assert "suspicious_keywords" not in found and admin.get("/api/lists/suspicious_keywords").status_code == 404
    assert [item["key"] for item in admin.get("/api/lists/automation_hosts").json()["entries"]] == ["siem.corp"]
    # The settings hold which list they read, and nothing else of it.
    with SessionLocal() as db:
        doc = db.get(Setting, 1).doc
        assert doc["iocAllowlist"] == {"list": "ioc_allowlist"} and "keywords" not in doc
        assert doc["mail"] == {
            "orgDomains": {"list": "internal_domains"},
            "trustedAuthServers": {"list": "mail_trusted_auth_servers"},
        }
        assert db.get(Setting, 2).doc["hosts"] == {"list": "automation_hosts"}
        assert state.read(db)["hosts"] == ["siem.corp"]

    # Read the old way, they are what they were.
    shown = admin.get("/api/settings").json()
    assert shown["iocAllowlist"] == ["corp.example", "10.0.0.0/8"]
    assert shown["businessHours"] == {"startHour": 9, "endHour": 17, "flagWeekends": False, "tz": "UTC"}
    assert "keywords" not in shown
    assert shown["mail"] == {"orgDomains": ["corp.example"], "trustedAuthServers": ["mx.corp.example"]}
    # Written the old way, the list takes it.
    shown["iocAllowlist"] = ["corp.example", "partner.example"]
    assert admin.put("/api/settings", json=shown).status_code == 200
    assert [item["key"] for item in admin.get("/api/lists/ioc_allowlist").json()["entries"]] == [
        "corp.example",
        "partner.example",
    ]
    # And changed as a list, the setting follows.
    assert admin.post("/api/lists/ioc_allowlist/items", json={"key": "192.0.2.0/24"}).status_code == 201
    lists.clear_cache()
    assert admin.get("/api/settings").json()["iocAllowlist"][-1] == "192.0.2.0/24"


def test_a_server_never_configured_gets_the_factory_lists(admin: TestClient):
    assert seed() == 5
    shown = admin.get("/api/settings").json()
    assert shown["iocAllowlist"] == list(DEFAULT_ALLOWLIST)
    assert shown["businessHours"] == DEFAULT_BUSINESS_HOURS
    assert "keywords" not in shown
    assert shown["mail"] == {"orgDomains": [], "trustedAuthServers": []}
    with SessionLocal() as db:
        assert state.read(db)["hosts"] == [] and db.get(Setting, 1) is None  # nothing to point: the default is read


def test_a_list_is_made_filled_exported_imported_and_deleted(admin: TestClient):
    made = make(admin, "vip_users", label="VIP users", itemType="user", description="Handle with care")
    assert (made["kind"], made["label"], made["items"], made["builtin"]) == ("values", "VIP users", 0, False)
    assert admin.post("/api/lists", json={"name": "vip_users"}).status_code == 409
    assert admin.post("/api/lists", json={"name": "Bad Name"}).status_code == 400
    assert admin.post("/api/lists", json={"name": "other", "kind": "table"}).status_code == 400

    assert admin.post("/api/lists/vip_users/items", json={"key": " anna ", "note": "CFO"}).status_code == 201
    again = admin.post("/api/lists/vip_users/items", json={"key": "anna", "note": "the CFO"}).json()
    assert [(item["key"], item["note"]) for item in again["entries"]] == [("anna", "the CFO")]
    replaced = admin.put("/api/lists/vip_users/items", json={"entries": ["bruno", {"key": "anna"}, "bruno", "carla"]})
    assert [item["key"] for item in replaced.json()["entries"]] == ["bruno", "anna", "carla"]  # in order, once each
    assert replaced.json()["entries"][1]["note"] == "the CFO"  # what it was known of an item stays
    assert admin.delete("/api/lists/vip_users/items", params={"key": "carla"}).status_code == 200
    assert admin.delete("/api/lists/vip_users/items", params={"key": "carla"}).status_code == 404
    assert admin.put("/api/lists/vip_users/items", json={"entries": [""]}).status_code == 400

    # Files.
    as_csv = admin.get("/api/lists/vip_users/export", params={"format": "csv"})
    assert as_csv.headers["content-type"].startswith("text/csv")
    assert as_csv.text.splitlines() == ["key,note", "bruno,", "anna,the CFO"]
    assert admin.get("/api/lists/vip_users/export").json()["entries"][1] == {
        "key": "anna",
        "value": None,
        "note": "the CFO",
    }
    loaded = admin.post("/api/lists/vip_users/import", json={"format": "csv", "text": "dora\n=evil()\n\nelio\n"})
    assert [item["key"] for item in loaded.json()["entries"]] == ["dora", "=evil()", "elio"]
    # A cell a spreadsheet would run is written so that it does not.
    assert "'=evil()" in admin.get("/api/lists/vip_users/export", params={"format": "csv"}).text
    loaded = admin.post(
        "/api/lists/vip_users/import", json={"format": "json", "text": '{"entries": [{"key": "fede", "note": "n"}]}'}
    )
    assert [(item["key"], item["note"]) for item in loaded.json()["entries"]] == [("fede", "n")]
    assert admin.post("/api/lists/vip_users/import", json={"format": "json", "text": "{"}).status_code == 400

    # Keys with values, and a document.
    make(admin, "owners", kind="key_value")
    assert admin.post("/api/lists/owners/items", json={"key": "srv-01", "value": {"team": "infra"}}).status_code == 201
    owners = admin.put("/api/lists/owners/items", json={"entries": [{"key": "srv-02", "value": "web"}]}).json()
    assert [(item["key"], item["value"]) for item in owners["entries"]] == [("srv-02", "web")]
    assert admin.get("/api/lists/owners/export", params={"format": "csv"}).text.splitlines() == [
        "key,value,note",
        "srv-02,web,",
    ]
    make(admin, "shifts", kind="json")
    shifts = admin.put("/api/lists/shifts/items", json={"document": {"night": ["anna"]}}).json()
    assert shifts["document"] == {"night": ["anna"]} and shifts["entries"] == [] and shifts["items"] is None
    assert admin.post("/api/lists/shifts/items", json={"key": "x"}).status_code == 400

    # What it is called changes; its name and its kind do not.
    changed = admin.put("/api/lists/owners", json={"label": "Owners", "writableByAutomation": True, "kind": "json"})
    assert (changed.json()["label"], changed.json()["kind"], changed.json()["writableByAutomation"]) == (
        "Owners",
        "key_value",
        True,
    )
    assert admin.put("/api/lists/owners", json={"itemType": "planet"}).status_code == 400

    # Who may: reading for whoever reads incidents, changing for whoever manages lists.
    viewer = make_key(admin, label="v", roles=["viewer"])
    analyst = make_key(admin, label="a", roles=["analyst"])
    builder = make_key(admin, label="p", roles=["playbooks"])
    assert admin.get("/api/lists/vip_users", headers=viewer).status_code == 200
    assert admin.post("/api/lists/vip_users/items", headers=analyst, json={"key": "x"}).status_code == 403
    assert admin.post("/api/lists/vip_users/items", headers=builder, json={"key": "x"}).status_code == 201

    assert admin.delete("/api/lists/shifts").status_code == 204
    assert admin.get("/api/lists/shifts").status_code == 404
    seed()
    refused = admin.delete("/api/lists/ioc_allowlist")
    assert refused.status_code == 409 and "cannot be deleted" in refused.json()["detail"]


def test_a_feature_reads_the_list_that_is_chosen_for_it(admin: TestClient):
    seed()
    make(admin, "strict_allowlist")
    admin.put("/api/lists/strict_allowlist/items", json={"entries": ["only.example"]})
    make(admin, "a_document", kind="json")
    pointers = admin.get("/api/lists").json()["pointers"]
    assert pointers["iocAllowlist"] == {"list": "ioc_allowlist", "default": "ioc_allowlist", "kind": "values"}

    chosen = admin.put("/api/lists/pointers", json={"pointers": {"iocAllowlist": "strict_allowlist"}})
    assert chosen.status_code == 200 and chosen.json()["pointers"]["iocAllowlist"]["list"] == "strict_allowlist"
    assert admin.get("/api/settings").json()["iocAllowlist"] == ["only.example"]
    found = by_name(admin)
    assert found["strict_allowlist"]["usedBy"] == ["Settings → Indicators → Allowlist"]
    assert found["ioc_allowlist"]["usedBy"] == []
    # What a list holds is written as its items are: a domain in lower case, a host that is one.
    assert admin.post("/api/lists/internal_domains/items", json={"key": " Corp.Example. "}).status_code == 201
    assert admin.get("/api/lists/internal_domains").json()["entries"][0]["key"] == "corp.example"
    assert admin.post("/api/lists/automation_hosts/items", json={"key": "http://not a host"}).status_code == 400
    assert admin.post("/api/lists/automation_hosts/items", json={"key": "Intel.Example.org:8443"}).status_code == 201
    assert admin.get("/api/lists/automation_hosts").json()["entries"][0]["key"] == "intel.example.org:8443"
    # A list in use is not deleted; one of another kind is not chosen; nor one that does not exist.
    assert admin.delete("/api/lists/strict_allowlist").status_code == 409
    assert admin.put("/api/lists/pointers", json={"pointers": {"iocAllowlist": "a_document"}}).status_code == 400
    assert admin.put("/api/lists/pointers", json={"pointers": {"iocAllowlist": "nope"}}).status_code == 400
    assert admin.put("/api/lists/pointers", json={"pointers": {"colour": "strict_allowlist"}}).status_code == 400
    # Written the old way, the chosen list takes it.
    shown = admin.get("/api/settings").json()
    shown["iocAllowlist"] = ["only.example", "also.example"]
    assert admin.put("/api/settings", json=shown).status_code == 200
    assert admin.get("/api/lists/strict_allowlist").json()["items"] == 2
    # The hosts of the automation, the same way.
    make(admin, "soc_hosts")
    admin.put("/api/lists/soc_hosts/items", json={"entries": ["soar.corp:8443"]})
    assert admin.put("/api/lists/pointers", json={"pointers": {"state.hosts": "soc_hosts"}}).status_code == 200
    with SessionLocal() as db:
        assert state.read(db)["hosts"] == ["soar.corp:8443"]


def test_a_read_made_while_a_choice_is_being_saved_does_not_keep_the_old_one(admin: TestClient):
    """Another request of the process reads between the write and its commit: what it caches then is
    the old choice, and it must not be served once the choice is saved."""
    seed()
    make(admin, "strict_allowlist")
    with SessionLocal() as writing:
        lists.point(writing, "iocAllowlist", "strict_allowlist")
        with SessionLocal() as reading:
            assert lists.pointers_of(reading)["iocAllowlist"] == "ioc_allowlist"  # not committed yet
        writing.commit()
    with SessionLocal() as db:
        assert lists.pointers_of(db)["iocAllowlist"] == "strict_allowlist"
    assert by_name(admin)["strict_allowlist"]["usedBy"] == ["Settings → Indicators → Allowlist"]
    # And the same for what a list holds.
    with SessionLocal() as writing:
        row = lists.find(writing, "strict_allowlist")
        lists.set_items(writing, row, [{"key": "late.example"}], "admin")
        with SessionLocal() as reading:
            assert lists.values(reading, "strict_allowlist") == []
        writing.commit()
    with SessionLocal() as db:
        assert lists.values(db, "strict_allowlist") == ["late.example"]


def test_what_is_in_a_list(admin: TestClient):
    make(admin, "nets", itemType="cidr")
    admin.put("/api/lists/nets/items", json={"entries": ["10.0.0.0/8", "2001:db8::/32", "Evil.Example", "not/a/net"]})
    make(admin, "doc", kind="json")
    admin.put("/api/lists/doc/items", json={"document": {"a": 1}})
    with SessionLocal() as db:
        assert lists.contains(db, "nets", "10.20.30.40") and lists.contains(db, "nets", "2001:db8::1")
        assert not lists.contains(db, "nets", "192.0.2.1")
        assert lists.contains(db, "nets", "evil.example") and lists.contains(db, "nets", " Evil.Example ")
        assert not lists.contains(db, "nets", "") and not lists.contains(db, "nets", None)
        assert not lists.contains(db, "nope", "x")
        assert lists.contains(db, "doc", "a") and not lists.contains(db, "doc", "b")
        assert lists.get(db, "doc") == {"a": 1} and lists.get(db, "nets")[0] == "10.0.0.0/8"

    # An item with a time is dropped when the time is over.
    admin.post("/api/lists/nets/items", json={"key": "198.51.100.7", "expiresAt": T0 + 60})
    with SessionLocal() as db:
        assert lists.prune(db, T0) == 0 and lists.prune(db, T0 + 61) == 1
        db.commit()
        assert not lists.contains(db, "nets", "198.51.100.7")

    # A watch list of the Indicators page is read here too, and changed where indicators are.
    made = admin.post("/api/iocs/lists", json={"name": "Campaign Q4"})
    assert made.status_code == 201, made.text
    added = admin.post(
        f"/api/iocs/lists/{made.json()['id']}/items",
        json={"items": [{"type": "domain", "value": "bad.example"}]},
    )
    assert added.status_code in (200, 201), added.text
    lists.clear_cache()
    shown = admin.get("/api/lists/campaign_q4").json()
    assert (shown["kind"], shown["readOnly"], shown["label"]) == ("indicators", True, "Campaign Q4")
    assert [(item["key"], item["value"]) for item in shown["entries"]] == [("bad.example", {"type": "domain"})]
    assert by_name(admin)["campaign_q4"]["items"] == 1
    assert admin.post("/api/lists/campaign_q4/items", json={"key": "x"}).status_code == 409
    with SessionLocal() as db:
        assert lists.contains(db, "campaign_q4", "BAD.example")


def test_a_playbook_reads_and_writes_lists_and_asks_whether_a_value_is_in_one(admin: TestClient):
    make(admin, "vip_users", writableByAutomation=True)
    admin.put("/api/lists/vip_users/items", json={"entries": ["anna"]})
    make(admin, "locked")
    nodes = [
        node("read", "action", action="list.get", args={"list": "vip_users"}),
        node("has", "action", action="list.contains", args={"list": "vip_users", "value": "ANNA"}),
        node("add", "action", action="list.add", args={"list": "vip_users", "value": "bruno", "note": "new"}),
        node("again", "action", action="list.add", args={"list": "vip_users", "value": "bruno"}),
        node("drop", "action", action="list.remove", args={"list": "vip_users", "value": "anna"}),
        echo("say", "{{ read.items | in_list('vip_users') }} {{ run.playbook | in_list('vip_users') }}"),
        node(
            "check", "condition", all=[{"left": "{{ run.playbook | in_list('vip_users') }}", "op": "eq", "right": True}]
        ),
        node("no", "action", action="list.add", args={"list": "locked", "value": "x"}),
    ]
    edges = [
        edge("start", "read"),
        edge("read", "has"),
        edge("has", "add"),
        edge("add", "again"),
        edge("again", "say"),
        edge("say", "drop"),
        edge("drop", "check"),
        edge("check", "no", "no"),
    ]
    pb = playbook(admin, "Lists", nodes, edges)
    dry = go(admin, pb, dryRun=True)
    assert steps(dry)["add"]["output"] == {"added": False, "count": 0}
    assert admin.get("/api/lists/vip_users").json()["items"] == 1  # a dry run writes nothing

    run = go(admin, pb)
    found = steps(run)
    assert found["read"]["output"] == {"items": ["anna"], "count": 1}
    assert found["has"]["output"] == {"found": True}
    assert found["add"]["output"] == {"added": True, "count": 2}
    assert found["again"]["output"]["added"] is False
    assert found["drop"]["output"] == {"removed": True}
    assert found["say"]["output"]["text"] == "true false"
    assert found["check"]["port"] == "no"
    # A list playbooks may not write to stays as it is.
    assert found["no"]["status"] == "failed" and "may not write to the list" in found["no"]["error"]
    assert [item["key"] for item in admin.get("/api/lists/vip_users").json()["entries"]] == ["bruno"]
    assert by_name(admin)["vip_users"]["usedBy"] == ["Playbook Lists"]

    made = make(admin, "plan", kind="json", writableByAutomation=True)
    assert made["kind"] == "json"
    setter = playbook(
        admin,
        "Sets",
        [
            node("set", "action", action="list.set", args={"list": "plan", "items": {"step": 1}}),
            node("missing", "action", action="list.get", args={"list": "nope"}),
        ],
        [edge("start", "set"), edge("set", "missing")],
    )
    run = go(admin, setter)
    assert steps(run)["set"]["output"] == {"count": 1}
    assert steps(run)["missing"]["error"] == 'There is no list called "nope"'
    assert admin.get("/api/lists/plan").json()["document"] == {"step": 1}
