"""The Sigma rules Nik keeps (7.0): saving them through the worker, listing, switching, resetting, the set
handed to the worker and its digest, the rules Nik ships, and the check that is made again.

The worker is not there: ``tests/sigma_double.py`` answers for it.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import AuditEntry, SigmaRule
from app.main import app as fastapi_app
from app.sigma import checking, recheck, rules, ruleset, seed, worker
from tests.conftest import make_key
from tests.sigma_double import FakeSigma, rule_text

ID_A = "11111111-1111-4111-8111-111111111111"
ID_B = "22222222-2222-4222-8222-222222222222"
ID_C = "33333333-3333-4333-8333-333333333333"
URL = "/api/sigma/rules"


@pytest.fixture()
def fake(monkeypatch) -> FakeSigma:
    return FakeSigma(monkeypatch)


def save(admin: TestClient, text: str, **more):
    return admin.post(URL, json={"source": text, **more})


def row(rule_id: str) -> SigmaRule:
    with SessionLocal() as db:
        found = db.get(SigmaRule, rule_id)
        db.expunge(found)
        return found


# --------------------------------------------------------------------------- #
# Saving                                                                       #
# --------------------------------------------------------------------------- #
def test_a_rule_is_read_by_the_worker_then_saved_as_what_it_said(admin: TestClient, fake: FakeSigma):
    text = rule_text(ID_A, title="Security log cleared", level="high", tags=["attack.t1070.001"])
    made = save(admin, text)
    assert made.status_code == 201, made.text
    (shown,) = made.json()["rules"]
    assert shown["id"] == ID_A and shown["title"] == "Security log cleared" and shown["author"] == "Tester"
    assert (shown["level"], shown["levelName"], shown["status"], shown["kind"]) == (4, "high", "stable", "rule")
    assert (shown["product"], shown["service"], shown["tags"]) == ("windows", "security", ["attack.t1070.001"])
    assert shown["enabled"] is True and shown["supported"] is True and shown["checked"] is True
    assert shown["pack"] == "" and shown["edited"] is False and shown["source"].strip() == text.strip()
    assert shown["createdBy"] == "admin" and row(ID_A).engine == "1"
    assert fake.of("/sigma/check") == [{"documents": [{"source": text}]}]
    # The list has it without its text; the rule alone has it.
    listed = admin.get(URL).json()
    assert listed["total"] == 1 and "source" not in listed["rules"][0]
    assert admin.get(f"{URL}/{ID_A}").json()["source"].strip() == text.strip()
    assert admin.get(f"{URL}/nope").status_code == 404
    with SessionLocal() as db:
        assert [e.action for e in db.scalars(select(AuditEntry))][-1] == "sigma.add"


def test_a_text_with_several_documents_saves_each_rule_or_none(admin: TestClient, fake: FakeSigma):
    both = rule_text(ID_A, title="One") + "---\n" + rule_text(ID_B, title="Two", event=104, service="system")
    made = save(admin, both)
    assert made.status_code == 201 and [r["id"] for r in made.json()["rules"]] == [ID_A, ID_B]
    # One document that is not a rule: nothing is saved, and the answer says where.
    bad = rule_text(ID_C, title="Three") + "---\ntitle: No id\ndetection:\n  selection: {EventID: 1}\n"
    refused = save(admin, bad)
    assert refused.status_code == 400
    assert refused.json()["errors"] == [{"line": 1, "column": 1, "message": "a rule needs an id (a UUID)"}]
    assert "This is not a Sigma rule" in refused.json()["detail"] and "line 1" in refused.json()["detail"]
    assert admin.get(f"{URL}/{ID_C}").status_code == 404 and admin.get(URL).json()["total"] == 2
    # Broken YAML says its line.
    broken = save(admin, "title: x\n  bad: [\n")
    assert broken.status_code == 400 and broken.json()["errors"][0]["line"] >= 1
    # Two documents with one id, an id that is here, an empty text.
    assert save(admin, rule_text(ID_C) + "---\n" + rule_text(ID_C)).status_code == 400
    assert save(admin, rule_text(ID_A)).status_code == 409
    assert save(admin, "  ").status_code == 400
    assert save(admin, rule_text("bad id with spaces")).status_code == 400


def test_without_the_worker_a_rule_cannot_be_saved_and_says_why(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    refused = save(admin, rule_text(ID_A))
    assert refused.status_code == 503 and "FORENSICS_URL" in refused.json()["detail"]
    assert admin.post(f"{URL}/validate", json={"source": rule_text(ID_A)}).status_code == 503
    assert admin.get(URL).json()["total"] == 0


def test_a_rule_the_worker_cannot_run_is_listed_with_why_and_is_not_switched_on(admin: TestClient, fake: FakeSigma):
    made = save(admin, rule_text(ID_A, product="linux", service="", category="network_connection", title="Auditd"))
    (shown,) = made.json()["rules"]
    assert shown["supported"] is False and shown["enabled"] is False
    assert shown["reason"] == "Nik reads no records of this log source: linux/network_connection"
    refused = admin.patch(f"{URL}/{ID_A}", json={"enabled": True})
    assert refused.status_code == 409 and "linux/network_connection" in refused.json()["detail"]
    # Asked to be on when saved, it still is not.
    again = save(admin, rule_text(ID_B, product="linux", service="", category="network_connection"), enabled=True)
    assert again.json()["rules"][0]["enabled"] is False
    assert admin.post(f"{URL}/bulk", json={"enabled": True, "ids": [ID_A]}).json() == {"matched": 0, "changed": 0}


def test_validate_says_what_the_worker_read_and_saves_nothing(admin: TestClient, fake: FakeSigma):
    save(admin, rule_text(ID_A))
    ok = admin.post(f"{URL}/validate", json={"source": rule_text(ID_A, title="Same id") + "---\n" + rule_text(ID_B)})
    body = ok.json()
    assert ok.status_code == 200 and body["ok"] is True and body["engine"] == "1" and body["errors"] == []
    assert [(r["id"], r["exists"]) for r in body["rules"]] == [(ID_A, True), (ID_B, False)]
    assert body["rules"][0]["line"] == 1 and "source" not in body["rules"][0]
    bad = admin.post(f"{URL}/validate", json={"source": "title: x\nlevel: high\n"}).json()
    assert bad["ok"] is False and bad["rules"] == [] and bad["errors"][0]["message"].startswith("a rule needs")
    assert admin.get(URL).json()["total"] == 1


def test_a_text_is_changed_but_its_id_is_not(admin: TestClient, fake: FakeSigma):
    save(admin, rule_text(ID_A, title="Before"))
    changed = admin.put(f"{URL}/{ID_A}", json={"source": rule_text(ID_A, title="After", level="low")})
    assert changed.status_code == 200 and (changed.json()["title"], changed.json()["level"]) == ("After", 2)
    assert admin.put(f"{URL}/{ID_A}", json={"source": rule_text(ID_B)}).status_code == 400
    assert admin.put(f"{URL}/{ID_A}", json={"source": rule_text(ID_A) + "---\n" + rule_text(ID_B)}).status_code == 400
    assert admin.put(f"{URL}/{ID_B}", json={"source": rule_text(ID_B)}).status_code == 404
    assert admin.put(f"{URL}/{ID_A}", json={"source": "nonsense: [", "enabled": False}).status_code == 400
    off = admin.put(f"{URL}/{ID_A}", json={"source": rule_text(ID_A), "enabled": False})
    assert off.json()["enabled"] is False


def test_a_rule_written_here_is_deleted_and_the_deletion_is_audited(admin: TestClient, fake: FakeSigma):
    save(admin, rule_text(ID_A))
    assert admin.delete(f"{URL}/{ID_A}").status_code == 204
    assert admin.delete(f"{URL}/{ID_A}").status_code == 404
    with SessionLocal() as db:
        assert "sigma.delete" in [e.action for e in db.scalars(select(AuditEntry))]


# --------------------------------------------------------------------------- #
# Listing and switching                                                        #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def many(admin: TestClient, fake: FakeSigma) -> list[str]:
    ids = [f"00000000-0000-4000-8000-00000000000{n}" for n in range(1, 8)]
    texts = [
        rule_text(ids[0], title="Alpha cleared", level="critical", event=1),
        rule_text(ids[1], title="Beta service", level="high", event=2, service="system", author="Sigma HQ"),
        rule_text(ids[2], title="Gamma logon", level="medium", event=3, status="test", service="security"),
        rule_text(ids[3], title="Delta low", level="low", event=4, status="experimental"),
        rule_text(ids[4], title="Epsilon info", level="informational", event=5),
        rule_text(ids[5], title="Zeta process", level="high", event=6, category="process_creation", service=""),
        rule_text(
            ids[6],
            title="Eta auditd",
            level="high",
            event=7,
            product="linux",
            service="",
            category="network_connection",
        ),
    ]
    assert save(admin, "---\n".join(texts)).status_code == 201
    return ids


def titles(admin: TestClient, **params) -> list[str]:
    answer = admin.get(URL, params=params)
    assert answer.status_code == 200, answer.text
    return [item["title"] for item in answer.json()["rules"]]


def test_the_list_is_paged_ordered_and_filtered(admin: TestClient, many):
    page = admin.get(URL, params={"limit": 3, "offset": 2}).json()
    assert (page["total"], page["limit"], page["offset"]) == (7, 3, 2)
    assert [r["title"] for r in page["rules"]] == ["Delta low", "Epsilon info", "Eta auditd"]
    assert titles(admin, order="-level", limit=3) == ["Alpha cleared", "Beta service", "Eta auditd"]
    assert titles(admin, order="level", limit=2) == ["Epsilon info", "Delta low"]
    assert titles(admin, level=4, order="title") == ["Alpha cleared", "Beta service", "Eta auditd", "Zeta process"]
    assert titles(admin, q="sigma hq") == ["Beta service"]  # the author
    assert titles(admin, q="GAMMA") == ["Gamma logon"] and titles(admin, q=many[5]) == ["Zeta process"]
    assert titles(admin, status="test") == ["Gamma logon"]
    assert titles(admin, supported=False) == ["Eta auditd"] and titles(admin, enabled=False) == ["Eta auditd"]
    assert titles(admin, product="linux") == ["Eta auditd"] and titles(admin, category="process_creation") == [
        "Zeta process"
    ]
    assert titles(admin, service="system") == ["Beta service"] and titles(admin, kind="correlation") == []
    assert titles(admin, pack="-", level=5) == ["Alpha cleared"] and titles(admin, pack="nik") == []
    assert admin.get(URL, params={"order": "sideways"}).status_code == 400
    assert (
        admin.get(URL, params={"limit": 501}).status_code == 422
        and admin.get(URL, params={"level": 6}).status_code == 422
    )
    assert admin.get(f"{URL}/summary").json() == {
        "total": 7,
        "enabled": 6,
        "supported": 6,
        "unchecked": 0,
        "engine": "1",
        "byLevel": {"1": 1, "2": 1, "3": 1, "4": 3, "5": 1},
        "products": {"windows": 6, "linux": 1},
        "packs": [{"id": "", "name": "Written here", "total": 7, "enabled": 6}],
        "workerConfigured": True,
    }


def test_rules_are_switched_one_by_one_by_ids_and_by_a_filter(admin: TestClient, many):
    off = admin.patch(f"{URL}/{many[0]}", json={"enabled": False})
    assert off.status_code == 200 and off.json()["enabled"] is False
    assert admin.patch(f"{URL}/{many[0]}", json={"enabled": True}).json()["enabled"] is True
    assert admin.patch(f"{URL}/nope", json={"enabled": True}).status_code == 404
    done = admin.post(f"{URL}/bulk", json={"enabled": False, "ids": many[:3] + ["unknown"]})
    assert done.json() == {"matched": 3, "changed": 3}
    assert titles(admin, enabled=False) == ["Alpha cleared", "Beta service", "Eta auditd", "Gamma logon"]
    # By a filter: the ones that say high or more, and that can run.
    done = admin.post(f"{URL}/bulk", json={"enabled": True, "filters": {"level": 4}})
    assert done.json() == {"matched": 3, "changed": 2}  # the auditd rule cannot be switched on
    assert titles(admin, enabled=True, level=4) == ["Alpha cleared", "Beta service", "Zeta process"]
    assert admin.post(f"{URL}/bulk", json={"enabled": False, "filters": {"q": "zeta"}}).json()["changed"] == 1
    # Ids or filters, one of them.
    assert admin.post(f"{URL}/bulk", json={"enabled": True}).status_code == 400
    assert admin.post(f"{URL}/bulk", json={"enabled": True, "ids": [], "filters": {}}).status_code == 400
    with SessionLocal() as db:
        actions = [e.action for e in db.scalars(select(AuditEntry))]
    assert "sigma.disable" in actions and "sigma.enable" in actions and "sigma.bulk" in actions


def test_listing_is_for_readers_and_changing_is_for_rules_managers(admin: TestClient, fake: FakeSigma):
    save(admin, rule_text(ID_A))
    viewer = TestClient(fastapi_app)
    reader = make_key(admin, label="v", roles=["viewer"])
    manager = make_key(admin, label="m", roles=["rules"])
    analyst = make_key(admin, label="a", roles=["analyst"])
    assert viewer.get(URL, headers=reader).status_code == 200
    assert viewer.get(f"{URL}/{ID_A}", headers=reader).status_code == 200
    assert viewer.get(f"{URL}/summary", headers=reader).status_code == 200
    for headers in (reader, analyst):
        assert viewer.post(URL, headers=headers, json={"source": rule_text(ID_B)}).status_code == 403
        assert viewer.patch(f"{URL}/{ID_A}", headers=headers, json={"enabled": False}).status_code == 403
        assert viewer.post(f"{URL}/bulk", headers=headers, json={"enabled": False, "ids": [ID_A]}).status_code == 403
        assert viewer.delete(f"{URL}/{ID_A}", headers=headers).status_code == 403
    assert viewer.get(URL, headers=manager).status_code == 200
    assert viewer.post(URL, headers=manager, json={"source": rule_text(ID_B)}).status_code == 201


# --------------------------------------------------------------------------- #
# The set the worker is given                                                  #
# --------------------------------------------------------------------------- #
def test_the_set_is_the_enabled_and_supported_rules_with_a_digest_that_follows_them(admin: TestClient, many):
    with SessionLocal() as db:
        first = ruleset.current(db)
        assert first is not None and first.count == 6 and first is ruleset.current(db)  # kept
        lines = [json.loads(line) for line in first.body.decode().splitlines()]
    assert [line["id"] for line in lines] == sorted(many[:6]) and set(lines[0]) == {
        "id",
        "title",
        "level",
        "kind",
        "product",
        "category",
        "service",
        "source",
    }
    assert first.digest == hashlib.sha256(first.body).hexdigest() and first.meta[many[0]]["level"] == 5
    assert first.meta[many[1]] == {
        "title": "Beta service",
        "author": "Sigma HQ",
        "level": 4,
        "tags": ["attack.defense-evasion", "attack.t1070.001"],
    }
    # Any change makes another set, in this process or in another (the generation is in the database).
    admin.patch(f"{URL}/{many[0]}", json={"enabled": False})
    with SessionLocal() as db:
        second = ruleset.current(db)
        assert second.count == 5 and second.digest != first.digest
    admin.patch(f"{URL}/{many[0]}", json={"enabled": True})
    with SessionLocal() as db:
        assert ruleset.current(db).digest == first.digest  # the same rules, the same bytes
    admin.put(f"{URL}/{many[0]}", json={"source": rule_text(many[0], title="Alpha changed", level="critical", event=1)})
    with SessionLocal() as db:
        assert ruleset.current(db).digest != first.digest
    assert ruleset.body_of(first.digest) == first.body


def test_no_enabled_rule_is_no_set_and_the_worker_is_given_the_set_it_asks_for(admin: TestClient, fake: FakeSigma):
    with SessionLocal() as db:
        assert ruleset.current(db) is None
    save(admin, rule_text(ID_A))
    with SessionLocal() as db:
        found = ruleset.current(db)
    assert ruleset.give(found.digest) is None and fake.sets[found.digest] == found.body
    assert (
        ruleset.give("0" * 64) == "The rules of this reading changed while it began: it is read again with the new ones"
    )
    fake.refuse_sets = True
    assert ruleset.give(found.digest) == "The worker has no room for rules"


def test_the_hours_are_the_business_hours_read_in_the_zone_of_the_incident(admin: TestClient):
    from app.core.models import Incident

    admin.post("/api/incidents", json={"id": "h-1", "data": {}})
    with SessionLocal() as db:
        incident = db.get(Incident, "h-1")
        assert ruleset.hours(db, incident) == {
            "tz": "UTC",
            "days": [1, 2, 3, 4, 5],
            "start": "08:00",
            "end": "18:00",
        }
        incident.tz = "Europe/Rome"
        assert ruleset.hours(db, incident)["tz"] == "Europe/Rome"
        assert ruleset.hours(db, None)["tz"] == "UTC"
    admin.put("/api/settings", json={"businessHours": {"startHour": 6, "endHour": 24, "flagWeekends": False}})
    with SessionLocal() as db:
        assert ruleset.hours(db, None) == {"tz": "UTC", "days": [1, 2, 3, 4, 5, 6, 7], "start": "06:00", "end": "24:00"}


# --------------------------------------------------------------------------- #
# The rules Nik ships                                                          #
# --------------------------------------------------------------------------- #
def test_the_rules_nik_ships_are_seeded_as_the_pack_nik_and_follow_a_release(
    admin: TestClient, fake: FakeSigma, tmp_path, monkeypatch
):
    shipped = seed.shipped()
    # The files of backend/app/sigma/pack (60) and of pack_chains (16), one rule each.
    assert len(shipped) == 76
    with SessionLocal() as db:
        assert seed.seed(db) == 76
        db.commit()
        assert seed.seed(db) == 0  # once
    listed = admin.get(URL, params={"pack": "nik", "order": "title", "limit": 100}).json()
    shown = [r["title"] for r in listed["rules"]]
    assert len(shown) == 60
    expected = {"New Service Installed", "Windows Security Event Log Cleared", "Windows System Event Log Cleared"}
    assert expected <= set(shown)
    assert all(r["pack"] == "nik" and r["enabled"] and r["supported"] and not r["edited"] for r in listed["rules"])
    assert fake.of("/sigma/check") and len(fake.of("/sigma/check")[0]["documents"]) == 76
    cleared = next(r for r in listed["rules"] if r["title"] == "Windows Security Event Log Cleared")
    assert (cleared["level"], cleared["author"], cleared["service"]) == (4, "Nik", "security")
    assert "attack.t1070.001" in cleared["tags"]
    # A pack rule is switched off, not deleted.
    assert admin.delete(f"{URL}/{cleared['id']}").status_code == 409
    assert admin.patch(f"{URL}/{cleared['id']}", json={"enabled": False}).json()["enabled"] is False
    packs = admin.get(f"{URL}/summary").json()["packs"]
    assert [(pack["id"], pack["name"], pack["total"]) for pack in packs] == [
        ("nik", "Nik", 60),
        ("nik-process-chains", "Nik process chains", 16),
    ]
    # The chain pack is Nik's too: its rules are on, supported, in the log source of the chains, and not edited.
    chains = admin.get(URL, params={"pack": "nik-process-chains", "limit": 100}).json()["rules"]
    assert len(chains) == 16 and all(r["enabled"] and r["supported"] and not r["edited"] for r in chains)
    assert {(r["product"], r["service"]) for r in chains} == {("nik", "process-chain")}
    assert {r["author"] for r in chains} == {"Nik"} and all(r["tags"] and r["level"] >= 3 for r in chains)

    # A release improves one rule and drops another: the one nobody changed follows, the other goes.
    folder = tmp_path / "pack"
    folder.mkdir()
    installed = next(r for r in listed["rules"] if r["title"] == "New Service Installed")
    for rule_id, text in shipped.items():
        if rule_id not in (cleared["id"], installed["id"]):
            (folder / f"{rule_id}.yml").write_text(text, encoding="utf-8")
    (folder / "new.yml").write_text(rule_text(ID_C, title="A new rule of Nik", author="Nik"), encoding="utf-8")
    monkeypatch.setattr(seed, "FOLDERS", {**seed.FOLDERS, "nik": folder})
    with SessionLocal() as db:
        assert seed.seed(db) == 3  # one added, two gone
        db.commit()
    after = titles(admin, pack="nik")
    assert len(after) == 59 and "A new rule of Nik" in after and "Windows System Event Log Cleared" in after
    assert "New Service Installed" not in after and "Windows Security Event Log Cleared" not in after


def test_a_rule_of_the_pack_a_person_changed_keeps_their_text_and_can_be_reset(
    admin: TestClient, fake: FakeSigma, tmp_path, monkeypatch
):
    with SessionLocal() as db:
        seed.seed(db)
        db.commit()
    of_pack = admin.get(URL, params={"pack": "nik"}).json()["rules"]
    target = next(r for r in of_pack if r["title"] == "Windows Security Event Log Cleared")
    rule_id = target["id"]
    pack_text = admin.get(f"{URL}/{rule_id}").json()["source"]
    mine = rule_text(rule_id, title="My own idea of it", level="low", event=1102, author="Me")
    edited = admin.put(f"{URL}/{rule_id}", json={"source": mine}).json()
    assert edited["edited"] is True and edited["pack"] == "nik" and edited["updatedBy"] == "admin"
    assert edited["original"] == pack_text and edited["title"] == "My own idea of it"
    # The release changes the file: their text stays, and Reset has the new one.
    new_text = pack_text.replace("level: high", "level: critical")
    folder = tmp_path / "pack"
    folder.mkdir()
    for other_id, text in seed.shipped().items():
        (folder / f"{other_id}.yml").write_text(new_text if other_id == rule_id else text, encoding="utf-8")
    monkeypatch.setattr(seed, "FOLDERS", {**seed.FOLDERS, "nik": folder})
    with SessionLocal() as db:
        assert seed.seed(db) == 1
        db.commit()
    now = admin.get(f"{URL}/{rule_id}").json()
    assert now["title"] == "My own idea of it" and now["original"].strip() == new_text.strip()
    back = admin.post(f"{URL}/{rule_id}/reset")
    assert back.status_code == 200
    assert back.json()["edited"] is False and back.json()["original"] is None and back.json()["level"] == 5
    assert back.json()["source"].strip() == new_text.strip() and back.json()["updatedBy"] == "nik"
    assert admin.post(f"{URL}/{rule_id}/reset").status_code == 409  # as the pack says it
    # Written back by hand as the pack says it, it is the pack's again.
    admin.put(f"{URL}/{rule_id}", json={"source": mine})
    again = admin.put(f"{URL}/{rule_id}", json={"source": new_text})
    assert again.json()["edited"] is False
    save(admin, rule_text(ID_A))
    assert admin.post(f"{URL}/{ID_A}/reset").status_code == 409  # nothing to go back to


# --------------------------------------------------------------------------- #
# Without the worker, and when it changes                                       #
# --------------------------------------------------------------------------- #
def test_rules_stored_while_the_worker_was_away_are_checked_when_it_answers(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    with SessionLocal() as db:
        assert seed.seed(db) == 76
        db.commit()
    unchecked = admin.get(URL, params={"limit": 100}).json()["rules"]
    assert [r["checked"] for r in unchecked] == [False] * 76 and [r["supported"] for r in unchecked] == [False] * 76
    assert all(r["reason"] == rules.NOT_CHECKED for r in unchecked)
    with SessionLocal() as db:
        assert ruleset.current(db) is None  # a rule not checked is not run
        assert recheck.run_once() == 0
    fake = FakeSigma(monkeypatch, engine="7")
    assert recheck.run_once() == 76
    checked = admin.get(URL, params={"limit": 100}).json()["rules"]
    assert all(r["checked"] and r["supported"] and r["enabled"] for r in checked)
    assert row(checked[0]["id"]).engine == "7" and admin.get(f"{URL}/summary").json()["engine"] == "7"
    assert recheck.run_once() == 0  # nothing to do twice
    with SessionLocal() as db:
        assert ruleset.current(db).count == 60  # the 16 rules of chains are run over processes, not given with a file
    # The worker is updated: every rule is checked again, and one of them can no longer be run.
    fake.engine = "8"
    worker.forget()
    original = fake.info

    def narrower(doc, source, number):
        found = original(doc, source, number)
        if found["title"] == "New Service Installed":
            found.update(supported=False, reason="The modifier |x is not run by Nik")
        return found

    monkeypatch.setattr(fake, "info", narrower)
    assert recheck.run_once() == 76
    after = {r["title"]: r for r in admin.get(URL, params={"limit": 100}).json()["rules"]}
    assert after["New Service Installed"]["supported"] is False and after["New Service Installed"]["reason"].startswith(
        "The modifier"
    )
    assert after["Windows System Event Log Cleared"]["supported"] is True
    assert row(after["New Service Installed"]["id"]).engine == "8"
    assert after["New Service Installed"]["enabled"] is True  # a person's choice stays; the set leaves it out
    with SessionLocal() as db:
        assert ruleset.current(db).count == 59


def test_a_rule_never_checked_that_turns_out_unsupported_is_switched_off(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    with SessionLocal() as db:
        info = rules.quick(rule_text(ID_A, product="linux", service="", category="network_connection"))
        rules.add(db, info, "", "tester")
        db.commit()
    assert admin.get(f"{URL}/{ID_A}").json()["enabled"] is True  # as it will be when it can run
    FakeSigma(monkeypatch)
    assert recheck.run_once() == 1
    shown = admin.get(f"{URL}/{ID_A}").json()
    assert shown["supported"] is False and shown["enabled"] is False and "linux/network_connection" in shown["reason"]


def test_the_recheck_route_starts_the_check_and_needs_the_worker(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    assert admin.post(f"{URL}/recheck").status_code == 503
    FakeSigma(monkeypatch)
    started = []
    monkeypatch.setattr(recheck, "run_once", lambda: started.append(1))
    assert admin.post(f"{URL}/recheck").status_code == 202


def test_levels_come_as_numbers_or_names():
    assert [checking.level_of(value) for value in ("informational", "LOW", "medium", "high", "critical")] == [
        1,
        2,
        3,
        4,
        5,
    ]
    assert [checking.level_of(value) for value in (1, 5, 0, 9, None, True, "odd")] == [1, 5, 3, 3, 3, 3, 3]


def test_a_rule_read_by_a_plain_yaml_scan_is_not_judged():
    held = rules.quick(rule_text(ID_A, title="T", level="high", tags=["attack.t1059"], name="by-name"))
    assert (held["id"], held["name"], held["title"], held["level"], held["product"]) == (
        ID_A,
        "by-name",
        "T",
        "high",
        "windows",
    )
    assert held["supported"] is False and held["reason"] == rules.NOT_CHECKED
    assert rules.quick("title: no id\n") is None and rules.quick("- a list\n") is None and rules.quick("a: [") is None
    assert rules.quick("correlation:\n  type: event_count\nid: x\n")["kind"] == "correlation"
