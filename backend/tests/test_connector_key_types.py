"""Shodan, Safe Browsing and GreyNoise take their key as credentials (6.6): the wire does not change, and
the key an instance held under the old name is kept.

Until 6.6 the three connectors asked for the key as a secret of their own (``api_key``) and wrote it into
every request by hand. They now say it once, as ``query`` or ``header`` credentials. The files as they
were (version 1.1.0 of their packs) are kept in ``tests/data/connectors_before_6_6`` to be compared with.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import packs
from app.automation import connector_actions as ca
from app.automation import connector_runtime as rt
from app.automation import connectors as cn
from app.automation import egress, instance_keys
from app.core.db import SessionLocal
from app.core.models import AuditEntry, Connection, Credential, Pack
from app.core.security import now_iso
from tests import vendor

BEFORE = Path(__file__).parent / "data" / "connectors_before_6_6"
THREE = ("shodan", "safebrowsing", "greynoise")
KEY = "the-key-0123456789"
# What each sends its key as, and to which hosts.
SENT_AS = {
    "shodan": ("query", "key", {"api.shodan.io", "trends.shodan.io"}),
    "safebrowsing": ("query", "key", {"safebrowsing.googleapis.com"}),
    "greynoise": ("header", "key", {"api.greynoise.io"}),
}


PUBLIC = ("greynoise", "get-public-rss-feed")


def before(name: str) -> str:
    return (BEFORE / f"{name}.yml").read_text(encoding="utf-8")


def now(name: str) -> str:
    return (vendor.REPO_PACKS / name / "connectors" / name / "connector.yml").read_text(encoding="utf-8")


class Wire:
    """Records what would leave, and answers an empty JSON object to everything."""

    def __init__(self):
        self.sent: list[dict] = []

    def __call__(self, policy, method, url, **kwargs):
        # A header the runtime names as secret is not sent on by a redirect to another host: that is
        # how it is carried, not what is sent.
        kwargs.pop("secret_headers", None)
        kwargs.pop("timeout", None)
        sent = {"method": method, "url": url, **{key: value for key, value in kwargs.items() if value}}
        if "query" in sent:
            sent["query"] = list(sent["query"].items())  # in the order they go in the address
        self.sent.append(sent)
        record = {"method": method, "host": "x", "path": url, "status": 200}
        return egress.Response(status=200, headers={"content-type": "application/json"}, body=b"{}", record=record)


def given(command: cn.Command) -> dict:
    """An argument of each kind for every argument of a command, so that every template is filled."""
    values = {"text": "x-1", "number": 3, "bool": True, "list": ["a", "b"], "object": {"a": 1}, "any": "x-1"}
    return {
        argument.name: (argument.choices[0] if argument.type == "choice" else values[argument.type])
        for argument in command.arguments
        if argument.type != "file"
    }


def requests_of(connector: cn.ConnectorFile, secrets: dict) -> dict[str, list[dict]]:
    """command → every request it sends, with these secrets."""
    found = {}
    for command in connector.commands:
        wire = Wire()
        policy = egress.Policy(mode="open", hosts=frozenset())
        runtime = rt.Runtime(connector, {}, secrets, policy, send=wire, clock=lambda: 1_800_000_000.0)
        try:
            runtime.run(command.name, given(command))
        except rt.CommandError:
            pass  # what it answered is not the point: what was sent before is
        found[command.name] = wire.sent
    return found


@pytest.mark.parametrize("name", THREE)
def test_the_requests_are_the_same_on_the_wire_with_a_key_and_without(name: str):
    old, new = cn.load(before(name)), cn.load(now(name))
    assert [command.name for command in old.commands] == [command.name for command in new.commands]
    assert new.version == old.version + 1
    # The key is said once, as credentials, and no command says it again but those on another host.
    kind, where, hosts = SENT_AS[name]
    assert (new.auth.type, new.auth.param if kind == "query" else new.auth.header) == (kind, where)
    assert old.auth is None and ca.secret_names(old) == ["api_key"] and ca.secret_names(new) == ["value"]
    assert now(name).count("{{ secret.") == (3 if name == "shodan" else 0)
    was, are = requests_of(old, {"api_key": KEY}), requests_of(new, {"value": KEY})
    assert sum(1 for sent in was.values() if sent) > len(old.commands) * 0.9  # nearly all of them send
    for command in old.commands:
        if (name, command.name) == PUBLIC:
            # The one request that differs: it went without the key, which it does not need, and has it
            # now, as every request to the host of an instance has the credentials of the instance.
            (bare,), (keyed,) = was[command.name], are[command.name]
            assert "headers" not in bare and keyed == {**bare, "headers": {"key": KEY}}
            continue
        assert are[command.name] == was[command.name], (name, command.name)
    # Without a key: the same requests, without it. (Safe Browsing has no request without a key: the old
    # file stopped before sending, the new one sends and Google refuses. Its key is required.)
    was, are = requests_of(old, {}), requests_of(new, {})
    if name == "safebrowsing":
        assert not any(was.values()) and all(are.values())
    else:
        assert are == was and sum(1 for sent in was.values() if sent) > len(old.commands) * 0.9
    assert KEY not in json.dumps(are, default=str)
    # And the key is where it was: in that parameter or that header, for those hosts and no other.
    carried: set[str] = set()
    for sent in (request for found in requests_of(new, {"value": KEY}).values() for request in found):
        host = sent["url"].split("/")[2]
        holds = dict(sent.get("query") or []).get(where) if kind == "query" else (sent.get("headers") or {}).get(where)
        assert (holds == KEY) == (host in hosts), sent
        assert KEY not in json.dumps({**sent, "query": None, "headers": None} if holds else sent)
        if holds:
            carried.add(host)
    assert carried == hosts


def instance(db, name: str, keys: int = 1) -> Connection:
    """An instance as the 1.1.0 connector made it: the key under ``api_key``."""
    row = Connection(
        id=f"{name}-old"[:32],
        name=f"{name} of the SOC",
        connector_id=name,
        config={},
        created_at=now_iso(),
        updated_at=now_iso(),
    )
    ca.store_secrets(row, {"api_key": KEY})
    if keys > 1:
        more = [{"name": f"Key {n}", "secrets": {"api_key": f"{KEY}-{n}"}} for n in range(2, keys + 1)]
        instance_keys.set_extra_keys(row, more, ["api_key"], [])
    db.add(row)
    return row


@pytest.mark.parametrize("name", THREE)
def test_an_instance_made_by_the_old_connector_keeps_its_keys(admin: TestClient, name: str):
    with SessionLocal() as db:
        ca.install(db, before(name), "admin")
        instance(db, name, keys=2)
        db.commit()
    with SessionLocal() as db:
        _row, connector = ca.install(db, now(name), "admin")
        db.commit()
        row = db.get(Connection, f"{name}-old")
        assert [key.secrets for key in instance_keys.keys_of(row)] == [{"value": KEY}, {"value": f"{KEY}-2"}]
        assert ca.usable_secrets(db, row) == {"value": KEY}
        # Installed again (a start of Nik, the same pack once more), nothing moves and nothing is said twice.
        ca.install(db, now(name), "admin")
        db.commit()
        said = [entry.details for entry in db.scalars(select(AuditEntry).where(AuditEntry.target == row.name))]
        assert said == [
            f'Kept the key of the instance "{row.name}" under the name version {connector.version} of '
            f"{connector.name} asks for it (api_key is value now)"
        ]
        assert KEY not in json.dumps(said)
    shown = admin.get("/api/automation/instances").json()["instances"][0]
    assert shown["secrets"] == {"value": True} and [key["secrets"] for key in shown["keys"]] == [{"value": True}] * 2


def test_a_key_that_names_a_credential_is_carried_as_the_name(admin: TestClient):
    with SessionLocal() as db:
        ca.install(db, before("greynoise"), "admin")
        row = instance(db, "greynoise")
        db.add(
            Credential(
                id="k" * 32,
                name="gn_key",
                kind="secret",
                secret=ca.vault.encrypt(KEY),
                created_at=now_iso(),
                updated_at=now_iso(),
            )
        )
        ca.store_secrets(row, {"api_key": "{{ credentials.gn_key }}"})
        db.commit()
    with SessionLocal() as db:
        ca.install(db, now("greynoise"), "admin")
        db.commit()
        row = db.get(Connection, "greynoise-old")
        assert ca.secrets_of(row) == {"value": "{{ credentials.gn_key }}"}
        assert ca.usable_secrets(db, row) == {"value": KEY}
    used = admin.get("/api/automation/credentials").json()["credentials"][0]["usedBy"]
    assert [(use["name"], use["fields"]) for use in used] == [("greynoise of the SOC", ["value"])]


def test_only_one_key_that_became_credentials_of_one_value_is_carried():
    def file(configuration: str) -> cn.ConnectorFile:
        return cn.load(
            "name: X\nid: xx\nversion: 1\nconfiguration:\n" + configuration + 'base_url: "https://x.example.com"\n'
            "commands:\n  - name: read\n    request: { method: GET, path: /x }\n"
        )

    one = file("  - { name: api_key, type: secret }\n")
    header = file("  - { name: api_key, type: header, header: X-Key }\n")
    assert ca.renamed_key(one, header) == ("api_key", "value")
    assert ca.renamed_key(one, file("  - { name: credentials, type: bearer }\n")) == ("api_key", "token")
    # Nothing else can be told to be the same secret: two secrets, credentials of two parts, a secret that
    # stays beside the credentials, credentials that were there already, or the way back.
    two = file("  - { name: api_key, type: secret }\n  - { name: other, type: secret }\n")
    assert ca.renamed_key(two, header) is None
    assert ca.renamed_key(one, file("  - { name: credentials, type: basic }\n")) is None
    assert ca.renamed_key(one, file("  - { name: api_key, type: secret }\n  - { name: c, type: bearer }\n")) is None
    assert ca.renamed_key(header, file("  - { name: credentials, type: query, param: key }\n")) is None
    assert ca.renamed_key(header, one) is None


def test_the_three_packs_are_for_the_nik_that_carries_the_keys():
    for name in THREE:
        manifest = packs.read(packs.folder_bytes(vendor.REPO_PACKS / name)).manifest
        # An older Nik would install the new file and leave the key under the name nothing reads any more.
        assert (manifest["version"], manifest["nik"]) == ("1.1.1", ">=6.6"), name


def test_updating_the_pack_carries_the_keys(admin: TestClient, tmp_path: Path, monkeypatch):
    # The pack of 1.1.0, made again from the file it had; then the one of the repository over it.
    monkeypatch.setattr(packs, "NIK_VERSION", max(packs.NIK_VERSION, (6, 6, 0)))
    folder = tmp_path / "shodan"
    (folder / "connectors" / "shodan").mkdir(parents=True)
    for path in (vendor.REPO_PACKS / "shodan").rglob("*"):
        if path.is_file():
            target = folder / path.relative_to(vendor.REPO_PACKS / "shodan")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    manifest = (folder / "pack.yml").read_text(encoding="utf-8")
    (folder / "pack.yml").write_text(manifest.replace("version: 1.1.1", "version: 1.1.0"), encoding="utf-8")
    (folder / "connectors" / "shodan" / "connector.yml").write_text(before("shodan"), encoding="utf-8", newline="\n")
    with SessionLocal() as db:
        packs.apply(db, packs.read(packs.folder_bytes(folder)), {}, "admin", source="folder")
        instance(db, "shodan")
        db.commit()
        assert db.get(Pack, "shodan").version == "1.1.0"
    with SessionLocal() as db:
        vendor.install_pack(db, "shodan")
        db.commit()
        assert db.get(Pack, "shodan").version == "1.1.1"
        row = db.get(Connection, "shodan-old")
        assert ca.secrets_of(row) == {"value": KEY}
        # A command goes with the key, in the address, as it did.
        wire = Wire()
        connector = ca.parsed(db.get(ca.Connector, "shodan"))
        runtime = ca.runtime_for(db, connector, row)
        runtime._send = wire
        runtime.run("get-api-info", {})
        assert wire.sent[0]["url"] == "https://api.shodan.io/api-info" and wire.sent[0]["query"] == [("key", KEY)]
