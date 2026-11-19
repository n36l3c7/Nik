"""The packs of vendors' products: the catalogue they are read from, and what installing, updating and
uninstalling one does."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import mapping, pack_build, packs
from app import pack_catalogue as catalogue
from app.automation import connector_actions as ca
from app.automation import scripts as automation_scripts
from app.core.db import SessionLocal
from app.core.models import Connector, Pack, PackItem, Playbook, Script
from app.main import app
from tests import vendor
from tests.conftest import make_key
from tests.test_connectors_api import ACME, connect
from tests.test_packs import MANIFEST, SCRIPT, actions, inspect, node

# A key of the tests: the base64 of 32 bytes.
PRIVATE = base64.b64encode(bytes(range(32))).decode("ascii")
BASE = "/n36l3c7/Nik/releases/download/packs/"


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
    for folder in folders:
        data = packs.folder_bytes(folder)
        assert data == packs.folder_bytes(folder), folder.name  # the same folder, the same bytes
        pack = packs.read(data)
        manifest = pack.manifest
        assert manifest["id"] == folder.name
        assert manifest["vendor"] and manifest["category"] and manifest["nik"] == ">=6.0", folder.name
        assert 40 < len(manifest["description"]) <= 2000, folder.name
        connectors = [item for item in pack.items if item.kind == "connectors"]
        assert connectors and all(item.extras.get("logo") for item in connectors), folder.name
        found = inspect(admin, data)
        assert found["problems"] == [] and set(actions(found).values()) == {"add"}, (folder.name, found)
    # What a Nik older than 6.0 held as its own is written down as these same packs.
    assert {spec["id"] for spec in packs.legacy()} <= {folder.name for folder in folders}
    for spec in packs.legacy():
        held = packs.read(packs.folder_bytes(vendor.REPO_PACKS / spec["id"]))
        assert sorted(spec["playbooks"]) == sorted(item.name for item in held.items if item.kind == "playbooks")


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
    assert (installed["source"], installed["vendor"], installed["version"]) == ("catalogue", "ServiceNow", "1.0.0")
    assert {item["kind"] for item in installed["items"]} == {"connectors", "mappers", "playbooks"}
    assert not any(item["changed"] for item in installed["items"])
    here = {entry["id"]: entry for entry in admin.get("/api/packs/catalogue").json()["packs"]}
    assert (here["servicenow"]["installed"], here["servicenow"]["update"]) == ("1.0.0", False)
    # A new instance starts with the classifier its pack gave.
    with SessionLocal() as db:
        assert "servicenow" in (mapping.state_defaults(db))

    # A newer version in the catalogue is an update: the difference is shown before anything changes.
    newer, files = dict(json.loads(published.index)), published.files
    line = next(entry for entry in newer["packs"] if entry["id"] == "servicenow")
    line["version"] = "1.1.0"
    index = json.dumps(newer).encode()
    published.answer("github.com", body=index, path=BASE + "index.json")
    published.answer("github.com", body=pack_build.sign(index, PRIVATE), path=BASE + "index.json.sig")
    again = admin.post("/api/packs/catalogue/refresh").json()
    assert next(entry for entry in again["packs"] if entry["id"] == "servicenow")["update"] is True

    # A file that is not the one the index lists is not read.
    published.answer(
        "objects.githubusercontent.com",
        body=files["jira-cloud-1.0.0.nikpack"] + b"x",
        path="/x/jira-cloud-1.0.0.nikpack",
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
    assert {item["action"] for item in plan["items"]} == {"remove"} and plan["instances"] == 0
    done = admin.delete("/api/packs/acme?remove=true")
    assert done.status_code == 200, done.text
    assert len(done.json()["removed"]) == 3 and done.json()["kept"] == []
    with SessionLocal() as db:
        assert db.get(Connector, "acme") is None and db.get(Pack, "acme") is None
        assert db.scalars(select(Script).where(Script.name == "CountWords")).first() is None
        assert db.scalars(select(Playbook).where(Playbook.name == "Acme triage")).first() is None
        assert db.scalars(select(PackItem)).all() == []
    assert any(entry["action"] == "pack.uninstall" for entry in admin.get("/api/audit").json()["entries"])


def test_what_was_changed_or_is_in_use_stays_and_is_no_packs_any_more(admin: TestClient):
    install_acme(admin)
    # A script of the pack is changed here; a playbook of the team uses its connector; the connector has an instance.
    with SessionLocal() as db:
        row = db.scalars(select(Script).where(Script.name == "CountWords")).one()
        ours = automation_scripts.clean({**SCRIPT, "code": SCRIPT["code"].replace("len(", "0 * len(")})
        automation_scripts.add_version(db, row, ours, {"passed": True}, "admin")
        db.commit()
    connect(admin)
    plan = {f"{item['kind']}/{item['name']}": item for item in admin.get("/api/packs/acme/uninstall").json()["items"]}
    assert plan["scripts/CountWords"]["action"] == "keep" and plan["scripts/CountWords"]["why"] == "It was changed here"
    assert plan["connectors/acme"]["action"] == "keep" and plan["connectors/acme"]["why"] == "It has 1 instance"
    # The playbook of the pack is the only thing that uses them: it goes, and does not hold them.
    assert plan["playbooks/Acme triage"]["action"] == "remove"
    assert admin.get("/api/packs/acme/uninstall").json()["instances"] == 1
    listed = next(row for row in admin.get("/api/packs").json()["packs"] if row["id"] == "acme")
    assert {item["name"]: item["changed"] for item in listed["items"]}["CountWords"] is True

    # With the instances: the connector goes too, and its instance with it.
    with_them = {
        f"{item['kind']}/{item['name']}": item["action"]
        for item in admin.get("/api/packs/acme/uninstall?instances=true").json()["items"]
    }
    assert with_them["connectors/acme"] == "remove"
    done = admin.delete("/api/packs/acme?remove=true").json()
    assert [entry["name"] for entry in done["kept"]] == ["CountWords", "acme"] and done["instances"] == 0
    with SessionLocal() as db:
        # What stayed is no pack's any more, and is still here.
        assert db.get(Pack, "acme") is None and db.scalars(select(PackItem)).all() == []
        assert db.get(Connector, "acme") is not None
        assert db.scalars(select(Script).where(Script.name == "CountWords")).first() is not None
        assert db.scalars(select(Playbook).where(Playbook.name == "Acme triage")).first() is None
    assert len(admin.get("/api/automation/instances").json()["instances"]) == 1


def test_a_pack_that_another_requires_and_the_pack_of_nik_are_not_uninstalled(admin: TestClient):
    install_acme(admin)
    needing = packs.write(
        {**MANIFEST, "id": "acme-extras", "requires": [{"pack": "acme", "version": "1.0.0"}]},
        [packs.Item("lists", "acme_queues", {"name": "acme_queues", "label": "Queues", "kind": "values"})],
    )
    found = inspect(admin, needing)
    assert admin.post("/api/packs/import", json={"token": found["token"]}).status_code == 200
    refused = admin.delete("/api/packs/acme?remove=true")
    assert refused.status_code == 409 and "requires it" in refused.json()["detail"]
    assert admin.get("/api/packs/acme/uninstall").status_code == 409
    with SessionLocal() as db:
        packs.register_builtin(db)
        db.commit()
    assert admin.delete("/api/packs/nik?remove=true").status_code == 409
    # Without "remove" a pack is only taken off the list, as before 6.0.
    assert admin.delete("/api/packs/acme-extras").status_code == 204
    assert admin.delete("/api/packs/acme").status_code == 204
    with SessionLocal() as db:
        assert db.get(Connector, "acme") is not None


def test_what_a_nik_older_than_6_held_becomes_the_packs_it_is(admin: TestClient):
    texts = {connector.id: text for text, connector in vendor.connectors()}
    with SessionLocal() as db:
        # As 5.x left them: connectors of Nik, the mappers they came with, and one it had removed.
        for name in ("servicenow", "jira-cloud", "zscaler-zia"):
            ca.install(db, texts[name], "nik", builtin=True)
        body = {"connectorId": "servicenow", "direction": "incoming", "incidentType": mapping.ANY_TYPE}
        mapping.save_mapper(db, {**body, "rules": vendor.mappers()["servicenow"]["incoming"]}, "nik", builtin=True)
        db.commit()
        assert packs.adopt_legacy(db) == 3
        db.commit()
        assert packs.adopt_legacy(db) == 0  # the next start has nothing to do
        assert not db.get(Connector, "servicenow").builtin
    listed = {row["id"]: row for row in admin.get("/api/packs").json()["packs"]}
    assert set(listed) == {"servicenow", "jira-cloud", "zscaler-zia"}
    assert (listed["servicenow"]["source"], listed["servicenow"]["version"]) == ("nik-5", "0.9.0")
    assert {item["kind"] for item in listed["servicenow"]["items"]} == {"connectors", "mappers"}
    assert listed["jira-cloud"]["vendor"] == "Atlassian" and not listed["jira-cloud"]["builtin"]
    # The pack of the catalogue is newer, and brings the logo the connector of 5.x never had.
    pack = packs.read(packs.folder_bytes(vendor.REPO_PACKS / "jira-cloud"))
    with SessionLocal() as db:
        assert db.get(Connector, "jira-cloud").logo is None
        found = packs.plan(db, pack)
        assert found["installed"] == "0.9.0"
        assert {item["action"] for item in found["items"] if item["kind"] == "connectors"} == {"same"}
        packs.apply(db, pack, {}, "admin", source="catalogue")
        db.commit()
        assert db.get(Connector, "jira-cloud").logo and db.get(Pack, "jira-cloud").version == "1.0.0"
    # It is uninstalled like one that came from the catalogue.
    assert admin.delete("/api/packs/zscaler-zia?remove=true").status_code == 200
    with SessionLocal() as db:
        assert db.get(Connector, "zscaler-zia") is None
        # One uploaded by hand under the same id was never Nik's: it is left alone.
        ca.install(db, texts["checkpoint-sase"], "admin")
        db.commit()
        assert packs.adopt_legacy(db) == 0


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
