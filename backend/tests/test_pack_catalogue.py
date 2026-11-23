"""The packs of vendors' products: the catalogue they are read from, and what installing, updating and
uninstalling one does."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import lists as named_lists
from app import mapping, pack_build, packs, preprocess
from app import pack_catalogue as catalogue
from app.core.db import SessionLocal
from app.core.models import (
    Connection,
    Connector,
    IncidentType,
    Pack,
    PackItem,
    Playbook,
    PlaybookVersion,
    PreprocessRule,
    Run,
    Script,
    Setting,
)
from app.main import app
from tests import vendor
from tests.conftest import make_key
from tests.test_connectors_api import ACME, connect
from tests.test_packs import LIST, MANIFEST, SCRIPT, actions, inspect, items, node

# A key of the tests: the base64 of 32 bytes.
PRIVATE = base64.b64encode(bytes(range(32))).decode("ascii")
BASE = "/n36l3c7/Nik/releases/download/packs/"
NO_LOGO = {"malwarebazaar", "urlhaus", "threatfox", "rdap"}
# The packs of 6.0 came from connectors that had no README of their own.
BEFORE_READMES = {
    "bitbucket-cloud", "bitbucket-datacenter", "checkpoint-management", "checkpoint-sase", "confluence-cloud",
    "confluence-datacenter", "jira-cloud", "jira-datacenter", "sentinelone", "sentinelone-sdl", "servicenow",
    "zscaler-zia",
}  # fmt: skip


@pytest.fixture()
def published(outside, monkeypatch):
    """The packs of the repository, published as the workflow publishes them, signed with the key of the tests."""
    index, files = pack_build.build(vendor.REPO_PACKS)
    monkeypatch.setattr(catalogue, "NIK_KEY", pack_build.public_of(PRIVATE))
    monkeypatch.setattr(catalogue.app_settings, "PACKS_CATALOGUE", "https://github.com" + BASE + "index.json")
    outside.host("github.com")
    outside.host("objects.githubusercontent.com")
    outside.answer("github.com", body=index, path=BASE + "index.json")
    outside.answer("github.com", body=pack_build.sign(index, PRIVATE), path=BASE + "index.json.sig")
    for name, data in files.items():
        # As GitHub does: the file of a release is answered from another host.
        outside.answer(
            "github.com", status=302, headers={"location": f"https://objects.githubusercontent.com/x/{name}"},
            path=BASE + name,
        )  # fmt: skip
        outside.answer("objects.githubusercontent.com", body=data, path=f"/x/{name}")
    outside.index, outside.files = index, files
    return outside


def test_every_pack_of_the_repository_is_a_pack_a_new_nik_installs_whole(admin: TestClient):
    folders = vendor.folders()
    assert len(folders) >= 12
    # Reading it as a new Nik would: with what Nik ships in place.
    for folder in folders:
        data = packs.folder_bytes(folder)
        assert data == packs.folder_bytes(folder), folder.name  # the same folder, the same bytes
        pack = packs.read(data)
        manifest = pack.manifest
        assert manifest["id"] == folder.name
        ranges = (">=6.0", ">=6.5", ">=6.6", ">=6.10", ">=6.11")
        assert manifest["vendor"] and manifest["category"] and manifest["nik"] in ranges, folder.name
        assert 40 < len(manifest["description"]) <= 2000, folder.name
        connectors = [item for item in pack.items if item.kind == "connectors"]
        assert connectors, folder.name
        # Every connector has the mark of its product, but the four whose vendor publishes none (packs/README.md).
        if folder.name not in NO_LOGO:
            assert all(item.extras.get("logo") for item in connectors), folder.name
        assert all(item.extras.get("readme") for item in connectors) or folder.name in BEFORE_READMES, folder.name
        found = inspect(admin, data)
        assert found["problems"] == [] and set(actions(found).values()) == {"add"}, (folder.name, found)


def test_the_catalogue_is_read_only_when_its_signature_is_right(admin: TestClient, published):
    empty = admin.get("/api/packs/catalogue").json()
    assert empty["read"] is False and empty["packs"] == [] and published.requests == []
    assert empty["address"] == "https://github.com" + BASE + "index.json" and empty["custom"] is False
    read = admin.post("/api/packs/catalogue/refresh")
    assert read.status_code == 200, read.text
    listed = {entry["id"]: entry for entry in read.json()["packs"]}
    assert set(listed) == {folder.name for folder in vendor.folders()}
    jira = listed["jira-cloud"]
    assert (jira["vendor"], jira["category"], jira["installed"], jira["update"]) == (
        "Atlassian",
        "Ticketing",
        None,
        False,
    )
    assert jira["contents"]["connectors"] == 1 and jira["contents"]["commands"] > 5 and jira["contents"]["mappers"] == 1
    assert jira["needsNik"] == ""
    # What its pack.yml says of it, and the names of its connectors, came in the signed index.
    assert jira["tags"] == ["ticketing"] and jira["connectors"] == ["Jira Cloud"]
    # Opening the page again does not go out.
    sent = len(published.requests)
    assert admin.get("/api/packs/catalogue").json()["read"] is True and len(published.requests) == sent

    # An index that was changed on the way, or signed by someone else, is not read: what was read stays.
    changed = published.index.replace(b"Jira Cloud", b"Jira Clown")
    published.answer("github.com", body=changed, path=BASE + "index.json")
    refused = admin.post("/api/packs/catalogue/refresh")
    assert refused.status_code == 502 and "not signed with the key" in refused.json()["detail"]
    after = admin.get("/api/packs/catalogue").json()
    assert "not signed" in after["error"] and len(after["packs"]) == len(listed)
    assert "Jira Clown" not in json.dumps(after)
    other = base64.b64encode(bytes(range(1, 33))).decode("ascii")
    published.answer("github.com", body=pack_build.sign(changed, other), path=BASE + "index.json.sig")
    assert admin.post("/api/packs/catalogue/refresh").status_code == 502


def test_a_nik_with_no_catalogue_says_so_and_goes_nowhere(admin: TestClient):
    shown = admin.get("/api/packs/catalogue").json()
    assert (shown["address"], shown["read"], shown["packs"]) == ("", False, [])
    refused = admin.post("/api/packs/catalogue/refresh")
    assert refused.status_code == 409 and "No catalogue is set" in refused.json()["detail"]


def test_an_index_keeps_only_what_is_a_pack_with_a_file():
    good = {
        "id": "acme", "name": "Acme", "version": "1.0.0", "file": "acme-1.0.0.nikpack", "sha256": "a" * 64, "size": 10,
        "contents": {"connectors": 1, "commands": 3, "weapons": 9},
    }  # fmt: skip
    kept = catalogue.clean_entry(good)
    assert kept["contents"] == {"connectors": 1, "commands": 3} and kept["logo"] is None
    for wrong in (
        {**good, "file": "../../etc/passwd"},
        {**good, "file": "https://elsewhere.example/acme.nikpack"},
        {**good, "sha256": "zz"},
        {**good, "size": packs.MAX_BYTES + 1},
        {**good, "id": "Not An Id"},
        {**good, "version": "one"},
        "acme",
    ):
        assert catalogue.clean_entry(wrong) is None, wrong
    # The pack that is Nik itself is never taken from a catalogue.
    index = json.dumps({"packs": [good, {**good, "id": "nik"}]}).encode()
    assert [entry["id"] for entry in catalogue.clean_index(index)] == ["acme"]
    with pytest.raises(catalogue.CatalogueError):
        catalogue.clean_index(b"[]")


def test_a_pack_is_installed_from_the_catalogue_then_updated(admin: TestClient, published, monkeypatch):
    assert admin.post("/api/packs/catalogue/refresh").status_code == 200
    found = admin.post("/api/packs/catalogue/servicenow/inspect")
    assert found.status_code == 200, found.text
    assert set(actions(found.json()).values()) == {"add"} and found.json()["installed"] is None
    done = admin.post("/api/packs/import", json={"token": found.json()["token"]})
    assert done.status_code == 200, done.text
    installed = done.json()["installed"]
    assert (installed["source"], installed["vendor"], installed["version"]) == ("catalogue", "ServiceNow", "1.1.0")
    assert {item["kind"] for item in installed["items"]} == {"connectors", "mappers", "playbooks"}
    assert not any(item["changed"] for item in installed["items"])
    here = {entry["id"]: entry for entry in admin.get("/api/packs/catalogue").json()["packs"]}
    assert (here["servicenow"]["installed"], here["servicenow"]["update"]) == ("1.1.0", False)
    # A new instance starts with the classifier its pack gave.
    with SessionLocal() as db:
        assert "servicenow" in (mapping.state_defaults(db))

    # A newer version in the catalogue is an update: the difference is shown before anything changes.
    newer, files = dict(json.loads(published.index)), published.files
    line = next(entry for entry in newer["packs"] if entry["id"] == "servicenow")
    line["version"] = "1.2.0"
    index = json.dumps(newer).encode()
    published.answer("github.com", body=index, path=BASE + "index.json")
    published.answer("github.com", body=pack_build.sign(index, PRIVATE), path=BASE + "index.json.sig")
    again = admin.post("/api/packs/catalogue/refresh").json()
    assert next(entry for entry in again["packs"] if entry["id"] == "servicenow")["update"] is True

    # A file that is not the one the index lists is not read.
    published.answer(
        "objects.githubusercontent.com",
        body=files["jira-cloud-1.1.0.nikpack"] + b"x",
        path="/x/jira-cloud-1.1.0.nikpack",
    )
    refused = admin.post("/api/packs/catalogue/jira-cloud/inspect")
    assert refused.status_code == 502 and "not the one the catalogue lists" in refused.json()["detail"]
    assert admin.post("/api/packs/catalogue/nothing/inspect").status_code == 404


def test_where_the_catalogue_is_belongs_to_the_admin(admin: TestClient, published):
    manager = make_key(admin, label="m", roles=["analyst", "playbooks", "connectors"])
    other = TestClient(app)
    body = {"address": "https://packs.example.com/nik/index.json", "key": pack_build.public_of(PRIVATE)}
    assert other.put("/api/packs/catalogue/address", json=body, headers=manager).status_code == 403
    for wrong in (
        {"address": "http://packs.example.com/index.json"},
        {"address": "https://user:pw@packs.example.com/index.json"},
        {"address": "https://packs.example.com/index.json?x=1"},
        {"address": "https://packs.example.com/index.json", "key": "not-a-key"},
    ):
        assert admin.put("/api/packs/catalogue/address", json=wrong).status_code == 400, wrong
    assert admin.post("/api/packs/catalogue/refresh").status_code == 200
    set_to = admin.put("/api/packs/catalogue/address", json=body)
    assert set_to.status_code == 200, set_to.text
    # What was read from the other address is forgotten.
    assert set_to.json() | {"packs": []} == set_to.json() and set_to.json()["custom"] is True
    published.host("packs.example.com")
    published.answer("packs.example.com", body=published.index, path="/nik/index.json")
    published.answer("packs.example.com", body=pack_build.sign(published.index, PRIVATE), path="/nik/index.json.sig")
    assert len(admin.post("/api/packs/catalogue/refresh").json()["packs"]) == len(vendor.folders())
    back = admin.put("/api/packs/catalogue/address", json={})
    assert back.json()["custom"] is False and back.json()["address"].startswith("https://github.com/")


def acme_pack(version: str = "1.0.0") -> bytes:
    """A pack of one product: its connector, a script, and a playbook that uses both."""
    graph = {
        "nodes": [
            node("start", "trigger", manual=True),
            node("count", "script", script="CountWords", args={"text": "one two"}),
            node("ask", "action", action="acme.get-ticket", connection="", args={"number": "1"}),
        ],
        "edges": [{"from": "start", "to": "count"}, {"from": "count", "to": "ask"}],
    }
    playbook = {"app": "Nik", "type": "playbook", "version": 1, "playbook": {"name": "Acme triage", "graph": graph}}
    manifest = {**MANIFEST, "id": "acme", "name": "Acme Desk", "vendor": "Acme", "version": version}
    return packs.write(
        manifest,
        [
            packs.Item("scripts", "CountWords", SCRIPT),
            packs.Item("connectors", "acme", ACME),
            packs.Item("playbooks", "Acme triage", playbook),
        ],
    )


def install_acme(admin: TestClient) -> None:
    found = inspect(admin, acme_pack())
    done = admin.post("/api/packs/import", json={"token": found["token"]})
    assert done.status_code == 200, done.text


def test_uninstalling_removes_what_the_pack_gave(admin: TestClient):
    install_acme(admin)
    plan = admin.get("/api/packs/acme/uninstall").json()
    assert {item["action"] for item in plan["items"]} == {"remove"} and plan["held"] == []
    done = admin.delete("/api/packs/acme?remove=true")
    assert done.status_code == 200, done.text
    assert len(done.json()["removed"]) == 3 and done.json()["kept"] == []
    with SessionLocal() as db:
        assert db.get(Connector, "acme") is None and db.get(Pack, "acme") is None
        assert db.scalars(select(Script).where(Script.name == "CountWords")).first() is None
        assert db.scalars(select(Playbook).where(Playbook.name == "Acme triage")).first() is None
        assert db.scalars(select(PackItem)).all() == []
    assert any(entry["action"] == "pack.uninstall" for entry in admin.get("/api/audit").json()["entries"])


def held_by(admin: TestClient, pack_id: str = "acme") -> list[dict]:
    found = admin.get(f"/api/packs/{pack_id}/uninstall")
    assert found.status_code == 200, found.text
    return found.json()["held"]


def refused(admin: TestClient, pack_id: str = "acme") -> list[str]:
    """Uninstalling is refused by the server, whatever the page shows: what it says holds the pack."""
    answer = admin.delete(f"/api/packs/{pack_id}?remove=true")
    assert answer.status_code == 409, answer.text
    detail = answer.json()["detail"]
    assert "is in use and was not uninstalled" in detail["message"]
    with SessionLocal() as db:
        assert db.get(Pack, pack_id) is not None  # nothing of it was touched
    return [entry["what"] for entry in detail["held"]]


def test_what_was_only_changed_here_stays_and_is_no_packs_any_more(admin: TestClient):
    install_acme(admin)
    # The playbook of the pack is changed here: it is ours now, and it runs the script of the pack.
    with SessionLocal() as db:
        row = db.scalars(select(Playbook).where(Playbook.name == "Acme triage")).one()
        row.description = "Ours now"
        db.commit()
    found = admin.get("/api/packs/acme/uninstall").json()
    plan = {f"{item['kind']}/{item['name']}": item for item in found["items"]}
    assert found["held"] == []
    assert (plan["playbooks/Acme triage"]["action"], plan["playbooks/Acme triage"]["why"]) == (
        "keep",
        "It was changed here",
    )
    # What it needs of the pack stays with it; nothing of this is "in use", so the pack is uninstalled.
    assert plan["scripts/CountWords"]["action"] == "keep" and plan["connectors/acme"]["action"] == "keep"
    assert plan["scripts/CountWords"]["why"] == 'The playbook "Acme triage", which stays, needs it'
    listed = next(row for row in admin.get("/api/packs").json()["packs"] if row["id"] == "acme")
    assert {item["name"]: item["changed"] for item in listed["items"]}["Acme triage"] is True
    done = admin.delete("/api/packs/acme?remove=true")
    assert done.status_code == 200, done.text
    assert done.json()["removed"] == [] and len(done.json()["kept"]) == 3
    with SessionLocal() as db:
        # What stayed is no pack's any more, and is still here.
        assert db.get(Pack, "acme") is None and db.scalars(select(PackItem)).all() == []
        assert db.get(Connector, "acme") is not None
        assert db.scalars(select(Script).where(Script.name == "CountWords")).first() is not None


def test_a_pack_with_an_instance_of_its_connector_is_not_uninstalled(admin: TestClient):
    install_acme(admin)
    instance = connect(admin)
    held = held_by(admin)
    assert [(entry["kind"], entry["name"]) for entry in held] == [("connectors", "acme")]
    assert held[0]["what"] == 'The instance "Acme production" of its connector "acme" is turned on'
    assert held[0]["todo"].startswith("Delete the instance first")
    assert refused(admin) == [held[0]["what"]]
    # Turned off it still holds credentials that would go with the connector: it holds the pack all the same.
    with SessionLocal() as db:
        db.get(Connection, instance["id"]).enabled = False
        db.commit()
    assert refused(admin) == ['The instance "Acme production" of its connector "acme" is turned off']
    assert len(admin.get("/api/automation/instances").json()["instances"]) == 1
    # No option deletes it for you any more.
    assert admin.delete("/api/packs/acme?remove=true&instances=true").status_code == 409
    assert admin.delete(f"/api/automation/instances/{instance['id']}").status_code == 204
    assert held_by(admin) == []
    assert admin.delete("/api/packs/acme?remove=true").status_code == 200
    with SessionLocal() as db:
        assert db.get(Connector, "acme") is None and db.get(Pack, "acme") is None


def test_each_thing_in_use_holds_the_pack_and_says_what_to_do(admin: TestClient):
    found = inspect(admin, packs.write(MANIFEST, items()))
    assert admin.post("/api/packs/import", json={"token": found["token"]}).status_code == 200
    assert held_by(admin, "acme-soc") == []

    def only(change, expected: str, undo) -> None:
        """One thing is put in the way, the pack is refused for it alone, and it is taken away again."""
        with SessionLocal() as db:
            change(db)
            db.commit()
        named_lists._cache.clear()
        assert refused(admin, "acme-soc") == [expected]
        assert all(entry["todo"] for entry in held_by(admin, "acme-soc"))
        with SessionLocal() as db:
            undo(db)
            db.commit()
        named_lists._cache.clear()
        assert held_by(admin, "acme-soc") == []

    def the_playbook(db) -> Playbook:
        return db.scalars(select(Playbook).where(Playbook.name == "Count the words")).one()

    # A playbook of the pack that is turned on, or has a run in progress.
    only(
        lambda db: setattr(the_playbook(db), "enabled", True),
        'Its playbook "Count the words" is turned on',
        lambda db: setattr(the_playbook(db), "enabled", False),
    )
    only(
        lambda db: db.add(
            Run(
                id="r1", playbook_id=the_playbook(db).id, version=1, status="running", started_at="2026-11-19T10:00:00Z"
            )
        ),
        'A run of its playbook "Count the words" is in progress',
        lambda db: db.delete(db.get(Run, "r1")),
    )

    # A playbook of ours that runs its script, its connector, its playbook, or reads its list.
    def ours(*nodes: dict):
        def change(db) -> None:
            stamp = "2026-11-19T10:00:00Z"
            row = Playbook(id="ours", name="Ours", enabled=False, created_at=stamp, created_by="admin")
            row.updated_at, row.updated_by = stamp, "admin"
            db.add(row)
            db.flush()
            db.add(
                PlaybookVersion(
                    playbook_id="ours",
                    version=1,
                    graph={"nodes": list(nodes), "edges": []},
                    note="",
                    created_at=stamp,
                    created_by="admin",
                )  # fmt: skip
            )
            db.get(Playbook, "ours").current_version = 1

        return change

    def no_ours(db) -> None:
        db.delete(db.get(Playbook, "ours"))

    only(
        ours(node("count", "script", script="CountWords")),
        'The playbook "Ours" runs its script "CountWords"',
        no_ours,
    )
    only(
        ours(node("ask", "action", action="acme.get-ticket", args={})),
        'The playbook "Ours" uses its connector "acme"',
        no_ours,
    )
    only(
        ours(node("sub", "playbook", playbook="Count the words")),
        'The playbook "Ours" runs its playbook "Count the words"',
        no_ours,
    )
    only(
        ours(node("look", "action", action="list.contains", args={"list": "vip_users", "value": "x"})),
        'The playbook "Ours" reads its list "vip_users"',
        no_ours,
    )

    # A pre-processing rule of ours that runs its script.
    def rule(db) -> None:
        preprocess.save(db, {"name": "Count", "action": "run_script", "params": {"script": "CountWords"}}, "admin")

    only(
        rule,
        'The pre-processing rule "Count" runs its script "CountWords"',
        lambda db: db.delete(db.scalars(select(PreprocessRule).where(PreprocessRule.name == "Count")).one()),
    )

    # A setting that reads its list.
    def point(to):
        def change(db) -> None:
            row = db.get(Setting, 1) or Setting(id=1, doc={})
            db.add(row)
            row.doc = {**(row.doc or {}), "iocAllowlist": to}

        return change

    only(
        point({"list": "vip_users"}),
        'Its list "vip_users" is read by a setting: Settings → Indicators → Allowlist',
        point({"list": "ioc_allowlist"}),
    )

    # A type of ours that lists its field, or has its playbook.
    def our_type(**more):
        def change(db) -> None:
            stamp = "2026-11-19T10:00:00Z"
            row = IncidentType(id="ourtype", name="Our type", created_at=stamp, updated_at=stamp, fields=[], sla=[])
            row.close_reasons = ["Done"]
            for key, value in more.items():
                setattr(row, key, value(db) if callable(value) else value)
            db.add(row)

        return change

    def no_type(db) -> None:
        db.delete(db.get(IncidentType, "ourtype"))

    only(
        our_type(fields=[{"name": "customer", "required": False, "requiredOnClose": False}]),
        'The type "Our type" lists its field "customer"',
        no_type,
    )
    only(
        our_type(default_playbook_id=lambda db: the_playbook(db).id),
        'Its playbook "Count the words" is the playbook of the type "Our type"',
        no_type,
    )

    # Incidents of its type, and one that holds a value of its field.
    with SessionLocal() as db:
        type_id = db.scalars(select(IncidentType).where(IncidentType.name == "Customer case")).one().id
    made = admin.post(
        "/api/incidents", json={"id": "c1", "name": "A case", "data": {}, "type": type_id, "fields": {"customer": "X"}}
    )
    assert made.status_code == 201, made.text
    assert refused(admin, "acme-soc") == [
        '1 incident holds a value of its field "customer"',
        '1 incident is of its type "Customer case"',
    ]
    assert admin.delete("/api/incidents/c1").status_code in (200, 204)
    done = admin.delete("/api/packs/acme-soc?remove=true")
    assert done.status_code == 200, done.text
    assert len(done.json()["removed"]) == len(items()) and done.json()["kept"] == []


def needing_acme() -> bytes:
    return packs.write(
        {**MANIFEST, "id": "acme-extras", "name": "Acme extras", "requires": [{"pack": "acme", "version": "1.0.0"}]},
        [packs.Item("lists", "acme_queues", {"name": "acme_queues", "label": "Queues", "kind": "values"})],
    )


def test_a_pack_that_another_requires_and_the_pack_of_nik_are_not_uninstalled(admin: TestClient):
    install_acme(admin)
    found = inspect(admin, needing_acme())
    assert admin.post("/api/packs/import", json={"token": found["token"]}).status_code == 200
    assert refused(admin) == ['The pack "Acme extras" requires it']
    held = held_by(admin)
    assert (held[0]["kind"], held[0]["todo"]) == ("packs", "Uninstall that pack first.")
    with SessionLocal() as db:
        packs.register_builtin(db)
        db.commit()
    assert admin.delete("/api/packs/nik?remove=true").status_code == 409
    assert admin.get("/api/packs/nik/uninstall").status_code == 409
    # Without "remove" a pack is only taken off the list, as before 6.0.
    assert admin.delete("/api/packs/acme").status_code == 409  # still required
    assert admin.delete("/api/packs/acme-extras").status_code == 204
    assert admin.delete("/api/packs/acme").status_code == 204
    with SessionLocal() as db:
        assert db.get(Connector, "acme") is not None


def test_a_folder_of_packs_is_installed_at_start(admin: TestClient, tmp_path):
    (tmp_path / "acme-1.0.0.nikpack").write_bytes(acme_pack())
    (tmp_path / "notes.txt").write_text("not a pack")
    (tmp_path / "broken.nikpack").write_bytes(b"junk")
    folder = tmp_path / "acme-extras"
    folder.mkdir()
    (folder / "pack.yml").write_text(
        "id: acme-extras\nname: Extras\nversion: 1.0.0\nrequires:\n  - {pack: acme, version: 1.0.0}\n"
    )
    (folder / "lists").mkdir()
    (folder / "lists" / "acme_queues.json").write_text('{"name": "acme_queues", "label": "Queues", "kind": "values"}')
    with SessionLocal() as db:
        # The one that requires the other comes first by name, and is installed all the same.
        assert packs.install_folder(db, tmp_path) == 2
        assert packs.install_folder(db, tmp_path) == 0
        assert packs.install_folder(db, tmp_path / "missing") == 0
        assert {row.id: row.source for row in db.scalars(select(Pack))} == {"acme": "folder", "acme-extras": "folder"}
        # A newer file replaces what is installed; an older one does not.
        (tmp_path / "acme-1.0.0.nikpack").write_bytes(acme_pack("1.1.0"))
        assert packs.install_folder(db, tmp_path) == 1
        assert db.get(Pack, "acme").version == "1.1.0"


def test_the_index_is_built_from_the_folders_and_signed(tmp_path):
    index, files = pack_build.build(vendor.REPO_PACKS)
    listed = json.loads(index)["packs"]
    assert sorted(files) == sorted(entry["file"] for entry in listed)
    for entry in listed:
        assert catalogue.clean_entry(entry) is not None, entry["id"]
        assert len(files[entry["file"]]) == entry["size"]
    signature = pack_build.sign(index, PRIVATE)
    catalogue.verify(index, signature, pack_build.public_of(PRIVATE))
    with pytest.raises(catalogue.CatalogueError):
        catalogue.verify(index + b" ", signature, pack_build.public_of(PRIVATE))
    # The key Nik holds is a key.
    assert catalogue.clean_key(catalogue.NIK_KEY) == catalogue.NIK_KEY
    # As the workflow runs it.
    assert pack_build.main([str(vendor.REPO_PACKS), str(tmp_path / "out")]) == 0
    assert (tmp_path / "out" / "index.json").read_bytes() == index
    assert not (tmp_path / "out" / "index.json.sig").exists()  # no key was given
    empty = tmp_path / "empty"
    empty.mkdir()
    assert pack_build.main([str(empty), str(tmp_path / "out")]) == 1


# --------------------------------------------------------------------------- #
# Tags                                                                        #
# --------------------------------------------------------------------------- #
def test_the_tags_of_a_pack_are_checked_and_travel_with_it(admin: TestClient):
    cleaned = packs.clean_manifest({**MANIFEST, "tags": ["ticketing", "itsm", "ticketing"]})
    assert cleaned["tags"] == ["ticketing", "itsm"]
    assert packs.clean_manifest(MANIFEST)["tags"] == []
    for wrong in ("ticketing", ["Ticketing"], ["two words"], [7], ["x"], [f"tag-{n}" for n in range(9)]):
        with pytest.raises(packs.PackError):
            packs.clean_manifest({**MANIFEST, "tags": wrong})
    # They are written to the file, read back, and kept on the pack that is installed.
    data = packs.write({**MANIFEST, "tags": ["ticketing", "itsm"]}, [packs.Item("scripts", "CountWords", SCRIPT)])
    assert packs.read(data).manifest["tags"] == ["ticketing", "itsm"]
    found = inspect(admin, data)
    assert admin.post("/api/packs/import", json={"token": found["token"]}).status_code == 200
    listed = next(row for row in admin.get("/api/packs").json()["packs"] if row["id"] == "acme-soc")
    assert listed["tags"] == ["ticketing", "itsm"]
    # An index carries them, and one whose tags are not tags is not an entry.
    line = {"id": "acme", "name": "Acme", "version": "1.0.0", "file": "acme-1.0.0.nikpack", "sha256": "a" * 64}
    line.update(size=10, tags=["edr"], connectors=["Acme Desk", 7])
    kept = catalogue.clean_entry(line)
    assert kept["tags"] == ["edr"] and kept["connectors"] == ["Acme Desk"]
    assert catalogue.clean_entry({**line, "tags": ["Not A Tag"]}) is None


def test_every_pack_of_the_repository_has_tags_of_a_small_vocabulary():
    index, _files = pack_build.build(vendor.REPO_PACKS)
    listed = json.loads(index)["packs"]
    words: dict[str, int] = {}
    for entry in listed:
        assert 1 <= len(entry["tags"]) <= packs.TAGS_MAX, entry["id"]
        assert entry["connectors"] and all(isinstance(name, str) for name in entry["connectors"]), entry["id"]
        for tag in entry["tags"]:
            words[tag] = words.get(tag, 0) + 1
    assert len(words) <= 20, sorted(words)
    by_id = {entry["id"]: entry for entry in listed}
    assert by_id["servicenow"]["tags"] == ["ticketing", "itsm"]
    assert "threat-intelligence" in by_id["virustotal"]["tags"] and "edr" in by_id["sentinelone"]["tags"]


# --------------------------------------------------------------------------- #
# Several at once                                                             #
# --------------------------------------------------------------------------- #
def test_packs_are_put_in_the_order_of_what_they_require():
    needs = {"extras": ["base"], "base": [], "alone": [], "top": ["extras", "elsewhere"]}
    assert packs.in_order(needs) == ["alone", "base", "extras", "top"]
    assert packs.in_order(needs, reverse=True) == ["top", "extras", "base", "alone"]
    # By name where nothing decides; a circle does not hang.
    assert packs.in_order({"b": [], "a": []}, {"a": "Zed", "b": "Alpha"}) == ["b", "a"]
    assert sorted(packs.in_order({"a": ["b"], "b": ["a"], "c": []})) == ["a", "b", "c"]
    assert packs.in_order({"a": ["b"], "b": ["a"], "c": []})[0] == "c"


def bulk(admin: TestClient, step: str, action: str, chosen: list) -> list[dict]:
    body = {"action": action, "packs": [entry if isinstance(entry, dict) else {"id": entry} for entry in chosen]}
    answer = admin.post(f"/api/packs/bulk/{step}", json=body)
    assert answer.status_code == 200, answer.text
    return answer.json()["packs"]


def test_several_packs_are_installed_from_the_catalogue_each_on_its_own(admin: TestClient, published):
    assert admin.post("/api/packs/catalogue/refresh").status_code == 200
    # One of them is installed already: it is the one left out.
    found = admin.post("/api/packs/catalogue/jira-cloud/inspect").json()
    assert admin.post("/api/packs/import", json={"token": found["token"]}).status_code == 200
    plan = bulk(admin, "plan", "install", ["servicenow", "jira-cloud", "abuseipdb", "nothing"])
    assert [line["id"] for line in plan] == ["abuseipdb", "jira-cloud", "servicenow", "nothing"]  # by name
    by_id = {line["id"]: line for line in plan}
    assert by_id["abuseipdb"]["ok"] and by_id["abuseipdb"]["counts"]["add"] >= 1 and by_id["abuseipdb"]["token"]
    assert {item["action"] for item in by_id["servicenow"]["items"]} == {"add"}
    assert not by_id["jira-cloud"]["ok"] and "is installed already" in by_id["jira-cloud"]["why"]
    assert not by_id["nothing"]["ok"] and "no pack with this id" in by_id["nothing"]["why"]
    with SessionLocal() as db:
        assert db.get(Pack, "servicenow") is None  # a plan installs nothing

    # One that fails does not undo the others: the token of abuseipdb is spoilt, the other two go in or not.
    chosen = [
        {"id": "servicenow", "token": by_id["servicenow"]["token"]},
        {"id": "abuseipdb", "token": "not-the-token-of-anything"},
        {"id": "jira-cloud", "token": by_id["jira-cloud"]["token"]},
    ]
    done = {line["id"]: line for line in bulk(admin, "apply", "install", chosen)}
    assert done["servicenow"]["ok"] and done["servicenow"]["added"] >= 3
    assert not done["abuseipdb"]["ok"] and "inspected too long ago" in done["abuseipdb"]["why"]
    assert not done["jira-cloud"]["ok"] and "installed already" in done["jira-cloud"]["why"]
    with SessionLocal() as db:
        assert db.get(Pack, "servicenow").source == "catalogue" and db.get(Pack, "abuseipdb") is None
        assert db.get(Connector, "servicenow") is not None
    entries = [entry for entry in admin.get("/api/audit").json()["entries"] if entry["action"] == "pack.import"]
    assert {entry["target"] for entry in entries} == {"jira-cloud", "servicenow"}

    # Updating: only what is installed and older than the catalogue.
    with SessionLocal() as db:
        db.get(Pack, "servicenow").version = "0.9.0"
        db.commit()
    plan = {line["id"]: line for line in bulk(admin, "plan", "update", ["servicenow", "jira-cloud", "abuseipdb"])}
    assert plan["servicenow"]["ok"] and plan["servicenow"]["installed"] == "0.9.0"
    assert "not newer" in plan["jira-cloud"]["why"] and plan["abuseipdb"]["why"] == "It is not installed"
    done = bulk(admin, "apply", "update", [{"id": "servicenow", "token": plan["servicenow"]["token"]}])
    assert done[0]["ok"] and done[0]["same"] >= 2 and done[0]["added"] == 0
    with SessionLocal() as db:
        assert db.get(Pack, "servicenow").version == "1.1.0"
    assert (
        admin.post("/api/packs/bulk/plan", json={"action": "burn", "packs": [{"id": "servicenow"}]}).status_code == 400
    )
    assert admin.post("/api/packs/bulk/plan", json={"action": "install", "packs": []}).status_code == 422


def test_a_pack_installed_with_the_pack_it_requires_comes_after_it(admin: TestClient, monkeypatch):
    files = {"acme": acme_pack(), "acme-extras": needing_acme()}
    files["acme-clash"] = packs.write(
        {**MANIFEST, "id": "acme-clash", "name": "Acme clash"},
        [
            packs.Item("fields", "severity", {"name": "severity", "label": "Mine", "type": "text"}),
            packs.Item("lists", "clash_list", {"name": "clash_list", "label": "L", "kind": "values"}),
        ],
    )
    monkeypatch.setattr(catalogue, "download", lambda db, pack_id: files[pack_id])
    # Asked for in the wrong order: the one that is required goes first, and is not missing for the other.
    plan = bulk(admin, "plan", "install", ["acme-extras", "acme-clash", "acme"])
    assert [(line["id"], line["ok"]) for line in plan] == [("acme-clash", False), ("acme", True), ("acme-extras", True)]
    assert plan[0]["why"] == "1 of its items is in conflict: install it on its own to leave them out"
    assert plan[0]["counts"] == {"add": 1, "update": 0, "same": 0, "conflict": 1}
    # Alone, the one that requires is left out, with why.
    alone = bulk(admin, "plan", "install", ["acme-extras"])
    assert alone[0]["why"] == 'It requires the pack "acme", which is not installed'

    # The required pack fails (its file is not its own): the one that requires it fails for that, and the
    # pack in conflict is refused by the server even when asked for.
    tokens = {line["id"]: line["token"] for line in plan}
    spoilt = [
        {"id": "acme-extras", "token": tokens["acme-extras"]},
        {"id": "acme", "token": tokens["acme-clash"]},
        {"id": "acme-clash", "token": tokens["acme-clash"]},
    ]
    done = {line["id"]: line for line in bulk(admin, "apply", "install", spoilt)}
    assert "not the pack that was looked at" in done["acme"]["why"]
    assert done["acme-extras"]["why"] == 'It requires the pack "acme", which is not installed'
    assert "in conflict" in done["acme-clash"]["why"]
    with SessionLocal() as db:
        assert db.scalars(select(Pack)).all() == []

    plan = bulk(admin, "plan", "install", ["acme-extras", "acme"])
    done = bulk(admin, "apply", "install", [{"id": line["id"], "token": line["token"]} for line in reversed(plan)])
    assert [(line["id"], line["ok"]) for line in done] == [("acme", True), ("acme-extras", True)]


def test_several_packs_are_uninstalled_the_ones_in_use_left_with_why(admin: TestClient):
    install_acme(admin)
    for data in (needing_acme(), packs.write(MANIFEST, [packs.Item("lists", "vip_users", LIST)])):
        found = inspect(admin, data)
        assert admin.post("/api/packs/import", json={"token": found["token"]}).status_code == 200
    # Together, the pack that requires goes first and so does not hold the one it requires.
    plan = bulk(admin, "plan", "uninstall", ["acme", "acme-extras", "nik", "ghost"])
    assert [(line["id"], line["ok"]) for line in plan[:2]] == [("acme-extras", True), ("acme", True)]
    assert plan[1]["held"] == [] and plan[1]["counts"] == {"remove": 3, "keep": 0, "gone": 0}
    assert {line["id"]: line["why"] for line in plan[2:]} == {
        "nik": "It is not installed",
        "ghost": "It is not installed",
    }
    # Alone, it is held by it.
    alone = bulk(admin, "plan", "uninstall", ["acme"])[0]
    assert not alone["ok"] and alone["why"] == "It is in use"
    assert [entry["what"] for entry in alone["held"]] == ['The pack "Acme extras" requires it']

    # An instance holds one of them: it is left, with what holds it, and the others are uninstalled.
    connect(admin)
    done = bulk(admin, "apply", "uninstall", ["acme", "acme-soc", "acme-extras"])
    assert [(line["id"], line["ok"]) for line in done] == [("acme-soc", True), ("acme-extras", True), ("acme", False)]
    assert done[2]["held"][0]["what"] == 'The instance "Acme production" of its connector "acme" is turned on'
    assert (done[0]["removed"], done[0]["kept"]) == (1, 0)
    with SessionLocal() as db:
        assert [row.id for row in db.scalars(select(Pack))] == ["acme"]
        assert db.get(Connector, "acme") is not None
    entries = [entry for entry in admin.get("/api/audit").json()["entries"] if entry["action"] == "pack.uninstall"]
    assert {entry["target"] for entry in entries} == {"acme-soc", "acme-extras"}
    # Who does not manage content does neither.
    reader = make_key(admin, label="r", roles=["analyst"])
    body = {"action": "uninstall", "packs": [{"id": "acme"}]}
    assert TestClient(app).post("/api/packs/bulk/plan", json=body, headers=reader).status_code == 403
    assert TestClient(app).post("/api/packs/bulk/apply", json=body, headers=reader).status_code == 403
