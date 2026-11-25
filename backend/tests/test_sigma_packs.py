"""Sigma rules in a content pack (7.0): the kind ``sigma_rules``, its folder ``sigma/``, the notice of the
pack, and a pack of thousands of rules that is checked in batches and written in chunks.

The worker is not there: ``tests/sigma_double.py`` answers for it.
"""

from __future__ import annotations

import io
import time
import zipfile

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import packs
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import Pack, PackItem, SigmaRule
from app.sigma import checking, pack_items, recheck, rules, ruleset
from tests.sigma_double import FakeSigma, rule_text
from tests.test_packs import MANIFEST, inspect, raw_zip

ID_A = "11111111-1111-4111-8111-111111111111"
ID_B = "22222222-2222-4222-8222-222222222222"
SIGMA = {
    **MANIFEST,
    "id": "sigmahq",
    "name": "SigmaHQ rules",
    "version": "1.0.0",
    "notice": "DRL 1.1 - the authors keep them",
}


def generated(count: int) -> dict[str, str]:
    """``count`` rules by id: a fifth of each shape (see ``ENABLED``)."""
    found = {}
    for number in range(count):
        rule_id = f"{number:08x}-0000-4000-8000-000000000000"
        kind = number % 5
        found[rule_id] = rule_text(
            rule_id,
            title=f"Rule {number}",
            event=number % 50,
            status=("stable", "test", "experimental", "stable", "stable")[kind],
            level=("high", "medium", "high", "low", "high")[kind],
            product="linux" if kind == 4 else "windows",
            service="auditd" if kind == 4 else "security",
        )
    return found


def enabled_of(count: int) -> int:
    return sum(1 for number in range(count) if number % 5 in (0, 1))


def pack_of(texts: dict[str, str], manifest: dict | None = None) -> bytes:
    return packs.write(manifest or SIGMA, [packs.Item("sigma_rules", rule_id, text) for rule_id, text in texts.items()])


def install(admin: TestClient, data: bytes) -> dict:
    found = inspect(admin, data)
    done = admin.post("/api/packs/import", json={"token": found["token"]})
    assert done.status_code == 200, done.text
    return done.json()


def stored() -> dict[str, SigmaRule]:
    with SessionLocal() as db:
        found = {row.id: row for row in db.scalars(select(SigmaRule))}
        db.expunge_all()
        return found


@pytest.fixture()
def fake(monkeypatch) -> FakeSigma:
    return FakeSigma(monkeypatch)


# --------------------------------------------------------------------------- #
# The file                                                                     #
# --------------------------------------------------------------------------- #
def test_a_pack_carries_rules_as_files_in_a_folder_and_a_notice(admin: TestClient):
    texts = {ID_A: rule_text(ID_A, title="One"), ID_B: rule_text(ID_B, title="Two")}
    data = pack_of(texts)
    assert data == pack_of(dict(reversed(texts.items())))  # the same pack, the same bytes
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert sorted(archive.namelist()) == ["pack.yml", f"sigma/{ID_A}.yml", f"sigma/{ID_B}.yml"]
        assert yaml.safe_load(archive.read("pack.yml"))["notice"] == SIGMA["notice"]
        assert archive.read(f"sigma/{ID_A}.yml").decode() == texts[ID_A]
    back = packs.read(data)
    assert [(item.kind, item.name, item.data) for item in back.items] == [
        ("sigma_rules", ID_A, texts[ID_A]),
        ("sigma_rules", ID_B, texts[ID_B]),
    ]
    assert back.manifest["notice"] == SIGMA["notice"]
    # Folders are read to any depth, as the sets of a vendor are laid out.
    nested = packs.read(raw_zip({"sigma/rules/windows/one.yml": texts[ID_A], "sigma/two.yaml": texts[ID_B]}))
    assert [item.name for item in nested.items] == [ID_A, ID_B]
    assert packs.read(raw_zip({"sigma/one.yml": texts[ID_A]}, {**MANIFEST, "notice": ""})).manifest["notice"] == ""


def test_a_file_of_a_pack_that_is_not_one_rule_is_refused_with_its_name():
    def refused(files: dict[str, str]) -> str:
        with pytest.raises(packs.PackError) as error:
            packs.read(raw_zip(files))
        return error.value.message

    assert "sigma/x.yml is not a rule: a rule needs an id" in refused({"sigma/x.yml": "title: no id\n"})
    assert "more than one document" in refused({"sigma/x.yml": rule_text(ID_A) + "---\n" + rule_text(ID_B)})
    assert "sigma/x.json is not a .yml file" in refused({"sigma/x.json": "{}"})
    assert "twice" in refused({"sigma/a.yml": rule_text(ID_A), "sigma/b.yml": rule_text(ID_A)})
    assert "longer than" in refused({"sigma/a.yml": rule_text(ID_A) + "# " + "x" * pack_items.TEXT_MAX})
    assert "is not text" in refused({"sigma/a.yml": b"\xff\xfe\x00"})
    assert "5000 files at most" in refused({f"sigma/f{index}.yml": "id: x\n" for index in range(5001)})


def test_the_id_of_a_rule_is_found_by_a_scan_of_its_lines_not_by_reading_the_yaml():
    assert pack_items.name_of("title: x\nid: 'abc-1'\n") == "abc-1"
    assert pack_items.name_of("---\ntitle: x\nid: abc-2   # a comment\n") == "abc-2"
    assert pack_items.name_of('id: "abc.3"\n') == "abc.3"
    for text, why in (("title: x\n", "needs an id"), ("  id: nested\n", "needs an id"), ("id: bad id\n", "")):
        if why:
            with pytest.raises(ValueError, match=why):
                pack_items.name_of(text)
    with pytest.raises(ValueError):
        pack_items.name_of("id: " + "x" * 65 + "\n")


# --------------------------------------------------------------------------- #
# Installing                                                                   #
# --------------------------------------------------------------------------- #
def test_a_pack_of_rules_is_inspected_without_the_worker_then_applied_with_its_defaults(
    admin: TestClient, fake: FakeSigma
):
    texts = generated(25)
    found = inspect(admin, pack_of(texts))
    assert fake.of("/sigma/check") == []  # looking at a pack asks the worker nothing
    assert found["counts"]["add"] == 25 and found["pack"]["notice"] == SIGMA["notice"]
    assert {item["action"] for item in found["items"]} == {"add"} and found["items"][0]["label"] == "Sigma rule"
    done = admin.post("/api/packs/import", json={"token": found["token"]})
    assert done.status_code == 200 and (done.json()["added"], done.json()["updated"]) == (25, 0)
    held = stored()
    assert len(held) == 25 and {row.pack for row in held.values()} == {"sigmahq"}
    # Enabled when supported, stable or test, medium or more: the other four fifths wait to be switched on.
    assert sum(row.enabled for row in held.values()) == enabled_of(25)
    assert [row.id for row in held.values() if not row.supported] == [
        i for i in sorted(held) if int(i[:8], 16) % 5 == 4
    ]
    assert all(
        row.engine == "1" and row.updated_by == "pack:sigmahq" and row.created_by == "admin" for row in held.values()
    )
    shown = done.json()["installed"]
    assert shown["notice"] == SIGMA["notice"] and len(shown["items"]) == 25
    assert all(item["there"] and not item["changed"] and item["kind"] == "sigma_rules" for item in shown["items"])
    with SessionLocal() as db:
        assert ruleset.current(db).count == enabled_of(25)
        assert db.get(PackItem, ("sigma_rules", next(iter(texts)))).pack_id == "sigmahq"
    # The same pack again: nothing to do, and nothing asked of the worker.
    fake.calls.clear()
    again = inspect(admin, pack_of(texts))
    assert {item["action"] for item in again["items"]} == {"same"}
    assert admin.post("/api/packs/import", json={"token": again["token"]}).json()["same"] == 25
    assert fake.of("/sigma/check") == []


def test_a_pack_of_450_rules_is_checked_in_three_calls(admin: TestClient, fake: FakeSigma):
    install(admin, pack_of(generated(450)))
    assert [len(call["documents"]) for call in fake.of("/sigma/check")] == [200, 200, 50]
    assert len(stored()) == 450


def test_a_pack_of_2700_rules_does_not_make_2700_calls_nor_take_minutes(admin: TestClient, fake: FakeSigma):
    texts = generated(2700)
    data = pack_of(texts)
    began = time.monotonic()
    found = inspect(admin, data)
    inspected = time.monotonic() - began
    assert found["counts"]["add"] == 2700 and fake.of("/sigma/check") == []
    began = time.monotonic()
    done = admin.post("/api/packs/import", json={"token": found["token"]})
    applied = time.monotonic() - began
    assert done.status_code == 200 and done.json()["added"] == 2700
    assert len(fake.of("/sigma/check")) == 14 and sum(len(c["documents"]) for c in fake.of("/sigma/check")) == 2700
    assert inspected < 60 and applied < 60, (inspected, applied)
    held = stored()
    assert len(held) == 2700 and sum(row.enabled for row in held.values()) == enabled_of(2700)
    # Listing the pack, planning it again and uninstalling it are not a query for each rule either.
    began = time.monotonic()
    listed = admin.get("/api/packs").json()["packs"]
    again = inspect(admin, data)
    gone = admin.delete("/api/packs/sigmahq", params={"remove": "true"})
    assert time.monotonic() - began < 60
    assert next(p for p in listed if p["id"] == "sigmahq")["items"].__len__() == 2700
    assert {item["action"] for item in again["items"]} == {"same"}
    assert gone.status_code == 200 and stored() == {}


def test_a_rule_the_worker_refuses_is_stored_not_supported_with_why_and_does_not_stop_the_pack(
    admin: TestClient, fake: FakeSigma
):
    broken = "title: Broken\nid: " + ID_B + "\nlevel: high\nstatus: stable\n"  # no detection: the worker refuses
    install(admin, pack_of({ID_A: rule_text(ID_A), ID_B: broken}))
    held = stored()
    assert held[ID_A].supported and held[ID_A].enabled
    assert (held[ID_B].supported, held[ID_B].enabled, held[ID_B].engine) == (False, False, "1")
    assert held[ID_B].reason.startswith("Not a valid rule: a rule needs a detection (line 2)")
    assert (held[ID_B].title, held[ID_B].level) == ("Broken", 4)


def test_without_the_worker_a_pack_is_stored_not_checked_and_checked_when_it_answers(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    install(admin, pack_of(generated(10)))
    held = stored()
    assert (
        len(held) == 10
        and {row.engine for row in held.values()} == {""}
        and not any(row.supported for row in held.values())
    )
    # Switched on as the status and the level say; what turns out not to run is switched off when it is checked.
    assert sum(row.enabled for row in held.values()) == enabled_of(10) + 2
    with SessionLocal() as db:
        assert ruleset.current(db) is None
    FakeSigma(monkeypatch)
    assert recheck.run_once() == 10
    held = stored()
    assert all(row.engine == "1" for row in held.values())
    assert sum(row.enabled for row in held.values()) == enabled_of(10)  # the two that cannot run were switched off
    assert sum(row.supported and row.enabled for row in held.values()) == enabled_of(10)


# --------------------------------------------------------------------------- #
# Updating, conflicts, leaving                                                  #
# --------------------------------------------------------------------------- #
def test_an_update_changes_the_rules_nobody_touched_and_keeps_the_text_of_the_ones_a_person_changed(
    admin: TestClient, fake: FakeSigma
):
    texts = {ID_A: rule_text(ID_A, title="One"), ID_B: rule_text(ID_B, title="Two")}
    install(admin, pack_of(texts))
    admin.put(f"/api/sigma/rules/{ID_B}", json={"source": rule_text(ID_B, title="Mine")})
    newer = {ID_A: rule_text(ID_A, title="One, better"), ID_B: rule_text(ID_B, title="Two, better")}
    found = inspect(admin, pack_of(newer, {**SIGMA, "version": "1.1.0"}))
    by_name = {item["name"]: item for item in found["items"]}
    assert by_name[ID_A]["action"] == "update" and "+title: One, better" in by_name[ID_A]["diff"]
    assert by_name[ID_B]["action"] == "same" and "changed here" in by_name[ID_B]["note"]
    done = admin.post("/api/packs/import", json={"token": found["token"]}).json()
    assert (done["added"], done["updated"], done["same"]) == (0, 1, 1)
    held = stored()
    assert held[ID_A].title == "One, better" and held[ID_A].updated_by == "pack:sigmahq"
    assert held[ID_B].title == "Mine" and held[ID_B].updated_by == "admin"
    assert held[ID_B].original.strip() == newer[ID_B].strip()  # what Reset puts back
    assert admin.post(f"/api/sigma/rules/{ID_B}/reset").json()["title"] == "Two, better"
    # What a person switched off stays off when the rule is updated.
    admin.patch(f"/api/sigma/rules/{ID_A}", json={"enabled": False})
    newest = {ID_A: rule_text(ID_A, title="One, best"), ID_B: newer[ID_B]}
    install(admin, pack_of(newest, {**SIGMA, "version": "1.2.0"}))
    assert (stored()[ID_A].title, stored()[ID_A].enabled) == ("One, best", False)


def test_a_rule_written_here_with_the_id_is_a_conflict_that_can_be_skipped(admin: TestClient, fake: FakeSigma):
    admin.post("/api/sigma/rules", json={"source": rule_text(ID_A, title="Written here")})
    found = inspect(admin, pack_of({ID_A: rule_text(ID_A), ID_B: rule_text(ID_B)}))
    by_name = {item["name"]: item for item in found["items"]}
    assert by_name[ID_A]["action"] == "conflict" and "written here" in by_name[ID_A]["why"]
    refused = admin.post("/api/packs/import", json={"token": found["token"]})
    assert refused.status_code == 409 and "Skip it" in refused.json()["detail"]
    done = admin.post("/api/packs/import", json={"token": found["token"], "choices": {f"sigma_rules/{ID_A}": "skip"}})
    assert done.status_code == 200 and done.json()["added"] == 1 and done.json()["skipped"] == 1
    assert stored()[ID_A].pack == "" and stored()[ID_B].pack == "sigmahq"


def test_the_rules_of_a_pack_that_another_pack_gives_last_are_that_packs(admin: TestClient, fake: FakeSigma):
    install(admin, pack_of({ID_A: rule_text(ID_A, title="First")}))
    other = {**SIGMA, "id": "other-rules", "name": "Other rules"}
    found = inspect(admin, pack_of({ID_A: rule_text(ID_A, title="Second")}, other))
    assert found["items"][0]["from"] == "sigmahq" and found["items"][0]["action"] == "update"
    admin.post("/api/packs/import", json={"token": found["token"]})
    assert (stored()[ID_A].pack, stored()[ID_A].title) == ("other-rules", "Second")
    with SessionLocal() as db:
        assert db.get(PackItem, ("sigma_rules", ID_A)).pack_id == "other-rules"


def test_uninstalling_a_pack_takes_its_rules_unless_a_person_changed_one(admin: TestClient, fake: FakeSigma):
    install(admin, pack_of({ID_A: rule_text(ID_A, title="One"), ID_B: rule_text(ID_B, title="Two")}))
    admin.put(f"/api/sigma/rules/{ID_B}", json={"source": rule_text(ID_B, title="Mine")})
    plan = admin.get("/api/packs/sigmahq/uninstall").json()
    assert {item["name"]: item["action"] for item in plan["items"]} == {ID_A: "remove", ID_B: "keep"}
    assert [item["why"] for item in plan["items"] if item["action"] == "keep"] == ["It was changed here"]
    done = admin.delete("/api/packs/sigmahq", params={"remove": "true"})
    assert done.status_code == 200 and [item["name"] for item in done.json()["removed"]] == [ID_A]
    held = stored()
    # What stays is no pack's any more: a rule written here, which can be deleted.
    assert list(held) == [ID_B] and held[ID_B].title == "Mine" and held[ID_B].pack == "" and held[ID_B].original is None
    with SessionLocal() as db:
        assert db.get(Pack, "sigmahq") is None and db.scalars(select(PackItem)).all() == []
        assert ruleset.current(db).count == 1
    assert admin.delete(f"/api/sigma/rules/{ID_B}").status_code == 204


def test_taking_a_pack_off_the_list_leaves_its_rules_as_written_here(admin: TestClient, fake: FakeSigma):
    install(admin, pack_of({ID_A: rule_text(ID_A)}))
    assert admin.delete("/api/packs/sigmahq").status_code == 204
    assert stored()[ID_A].pack == "" and admin.delete(f"/api/sigma/rules/{ID_A}").status_code == 204


def test_changed_says_a_rule_was_edited_in_the_list_of_a_packs_items(admin: TestClient, fake: FakeSigma):
    install(admin, pack_of({ID_A: rule_text(ID_A), ID_B: rule_text(ID_B)}))
    admin.put(f"/api/sigma/rules/{ID_B}", json={"source": rule_text(ID_B, title="Mine")})
    listed = next(p for p in admin.get("/api/packs").json()["packs"] if p["id"] == "sigmahq")
    assert {item["name"]: (item["there"], item["changed"]) for item in listed["items"]} == {
        ID_A: (True, False),
        ID_B: (True, True),
    }


def test_rules_written_here_go_into_a_pack_and_come_back_as_they_were(admin: TestClient, fake: FakeSigma):
    text = rule_text(ID_A, title="Mine")
    admin.post("/api/sigma/rules", json={"source": text})
    with SessionLocal() as db:
        assert packs.names(db, "sigma_rules") == [{"name": ID_A, "label": "Mine", "builtin": False}]
        assert packs.current(db, "sigma_rules", ID_A).strip() == text.strip()
        data = packs.export(db, {**SIGMA, "id": "mine"}, [("sigma_rules", ID_A)])
    back = packs.read(data)
    assert [(item.kind, item.name, item.data.strip()) for item in back.items] == [("sigma_rules", ID_A, text.strip())]
    assert back.manifest["notice"] == SIGMA["notice"]


def test_the_levels_a_pack_gives_a_rule_decide_what_is_on(admin: TestClient):
    info = {"status": "stable", "level": "high", "supported": True}
    assert rules.default_enabled(info, "1", "sigmahq") is True
    assert rules.default_enabled({**info, "status": "experimental"}, "1", "sigmahq") is False
    assert rules.default_enabled({**info, "level": "low"}, "1", "sigmahq") is False
    assert rules.default_enabled({**info, "supported": False}, "1", "sigmahq") is False
    assert rules.default_enabled({**info, "supported": False}, "", "sigmahq") is True  # not checked: as it will be
    # The rules of Nik and the ones written here are on when they can run, whatever their level.
    assert rules.default_enabled({**info, "level": "low", "status": "experimental"}, "1", "nik") is True
    assert rules.default_enabled({**info, "level": "low"}, "1", "") is True
    assert rules.default_enabled({**info, "supported": False}, "1", "") is False
    assert checking.BATCH == 200
