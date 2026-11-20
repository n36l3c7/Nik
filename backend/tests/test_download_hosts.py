"""The hosts the downloads of an instance may come from: what an administrator may write, what a
connector must say to ask for it, and what goes on the wire to such a host (nothing but the request).

The outside is the fake one of the tests, behind the real egress client: names that resolve, and
what answers there, redirects included.
"""

from __future__ import annotations

import textwrap

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import connector_actions as ca
from app.automation import connector_runtime as rt
from app.automation import connectors as cn
from app.automation import download_hosts, egress
from app.core.db import SessionLocal
from app.core.models import AuditEntry
from tests.test_shipped_connectors import Held

CONSOLE = "console.vendor.example.com"
STORE = "files.storage.vendor.example.net"
DEEP = "eu-1.bucket.storage.vendor.example.net"
FILE = b"collected: a harmless line\n"
KEY = "console-key-123456"

LINKED = """\
name: Linked
id: linked
version: 1
description: A console that hands its files over as links.
configuration:
  - { name: url, type: url, required: true }
  - { name: credentials, type: header, header: x-apikey }
@ENTRY@
@OPT_IN@
base_url: "{{ config.url }}"
headers: { X-Client: nik-linked }
commands:
  - name: download
    description: Keep a file the console gives a link to.
    arguments: [{ name: id, type: text, required: true }]
    steps:
      - name: link
        request: { method: GET, path: "/files/{{ args.id }}/link" }
      - name: file
        request:
          method: GET
          path: "{{ steps.link.response.url }}"
          headers: { X-Asked-By: "{{ args.id }}" }
          answer: file
  - name: peek
    description: Read what a link holds, as text.
    arguments: [{ name: link, type: text, required: true }]
    request: { method: GET, path: "{{ args.link }}", answer: text }
"""
ENTRY = "  - { name: download_hosts, type: hosts, label: Hosts downloads may come from }"
OPT_IN = "download_hosts_from: download_hosts"


def written(entry: str = ENTRY, opt_in: str = OPT_IN) -> str:
    return LINKED.replace("@ENTRY@", entry).replace("@OPT_IN@", opt_in)


def linked(entry: str = ENTRY, opt_in: str = OPT_IN) -> cn.ConnectorFile:
    return cn.load(written(entry, opt_in))


def runtime(connector: cn.ConnectorFile, hosts: str = "", mode: str = "listed") -> tuple[rt.Runtime, Held]:
    """A runtime over the real egress client: the playbook reaches the console and nothing else."""
    rt.forget_tokens()
    config = {"url": f"https://{CONSOLE}/api", **({"download_hosts": hosts} if hosts else {})}
    policy = egress.Policy(mode=mode, hosts=frozenset({CONSOLE}))
    live = rt.Runtime(connector, config, {"value": KEY}, policy)
    live.store = Held({})
    return live, live.store


@pytest.fixture()
def world(outside):
    outside.host(CONSOLE, "93.184.215.40")
    outside.host(STORE, "93.184.215.41")
    outside.host(DEEP, "93.184.215.42")
    return outside


def link_to(world, address: str) -> None:
    world.answer(CONSOLE, json={"url": address}, path="/api/files/7/link")


def to(world, host: str) -> list[dict]:
    return [sent for sent in world.requests if sent["host"] == host]


# --------------------------------------------------------------------------- #
# What may be written                                                       #
# --------------------------------------------------------------------------- #
def test_a_list_of_hosts_is_names_and_patterns_under_a_name_and_nothing_else():
    assert download_hosts.patterns(" Files.Example.com,\n*.storage.example.com ; files.example.com\n") == [
        "files.example.com",
        "*.storage.example.com",
    ]
    assert download_hosts.patterns("") == [] and download_hosts.patterns(None) == []
    for typed, why in (
        ("*", "a * stands only at the start"),
        ("*.com", "is not the name of a host"),
        ("files.*.example.com", "a * stands only at the start"),
        ("*files.example.com", "a * stands only at the start"),
        ("https://files.example.com", "is an address: write the name of the host alone, without https://"),
        ("files.example.com/downloads", "has a path or is a range"),
        ("10.0.0.0/8", "has a path or is a range"),
        ("files.example.com:8443", "has a port or is an address"),
        ("203.0.113.9", "is an address: a host is written by its name"),
        ("[2001:db8::1]", "has a port or is an address"),
        ("fileserver", "is not the name of a host"),
        ("files.corp", "is an internal name"),
        ("*.internal", "is not the name of a host"),
        ("nas.home.local", "is an internal name"),
        ("under_score.example.com", "is not the name of a host"),
    ):
        with pytest.raises(
            ValueError, match='^"' + typed.replace("*", r"\*").replace("[", r"\[").replace("]", r"\]")
        ) as refused:
            download_hosts.patterns(f"files.example.com, {typed}")
        assert why in str(refused.value), typed
    with pytest.raises(ValueError, match="40 hosts at most"):
        download_hosts.patterns(", ".join(f"h{index}.example.com" for index in range(41)))
    # A name, or what is under a name: the name itself is not under itself.
    listed = ("files.example.com", "*.storage.example.com")
    assert download_hosts.matches(listed, "FILES.example.com") and download_hosts.matches(
        listed, "a.b.storage.example.com"
    )
    assert not download_hosts.matches(listed, "storage.example.com")
    assert not download_hosts.matches(listed, "evilstorage.example.com")
    assert not download_hosts.matches(listed, "files.example.com.evil.net") and not download_hosts.matches(
        (), "x.example.com"
    )
    # What is read when a request is built opens nothing when it is not a list any more.
    assert download_hosts.tolerant("https://not-a-list") == ()


def test_a_connector_asks_for_the_list_by_naming_the_entry_of_its_instance():
    asked = linked()
    assert asked.download_hosts_from == "download_hosts" and cn.summary(asked)["downloadHostsFrom"] == "download_hosts"
    assert cn.summary(linked(entry="", opt_in=""))["downloadHostsFrom"] is None

    def problems(text: str) -> str:
        with pytest.raises(cn.ConnectorError) as refused:
            cn.load(text)
        return " | ".join(problem.message for problem in refused.value.problems)

    # The entry and the key go together, and are for a connector that keeps a file.
    assert '"download_hosts" is a list of hosts: "download_hosts_from" names it' in problems(written(ENTRY, ""))
    assert '"download_hosts_from" names the one configuration entry of type hosts' in problems(written("", OPT_IN))
    assert '"download_hosts_from" names the one configuration entry of type hosts' in problems(
        written("  - { name: download_hosts, type: text }", OPT_IN)
    )
    no_file = written(ENTRY, OPT_IN).replace("          answer: file\n", "")
    assert "is for a connector with a command whose answer is a file" in problems(no_file)


# --------------------------------------------------------------------------- #
# What goes on the wire                                                       #
# --------------------------------------------------------------------------- #
def test_a_connector_that_does_not_ask_and_an_instance_that_lists_nothing_are_as_before(world):
    link_to(world, f"https://{STORE}/a/file.bin?X-Signature=abc")
    world.answer(STORE, body=FILE, path="/a/file.bin")
    # Not asked for by the connector: the refusal of always, word for word.
    plain, held = runtime(linked(entry="", opt_in=""))
    with pytest.raises(rt.CommandError) as refused:
        plain.run("download", {"id": "7"})
    assert refused.value.message == f"A request of this connector goes to {STORE}, not to its instance"
    # Asked for, and the instance lists nothing: the same refusal, and where the host is written.
    asking, held = runtime(linked())
    with pytest.raises(rt.CommandError) as refused:
        asking.run("download", {"id": "7"})
    assert refused.value.message == (
        f"A request of this connector goes to {STORE}, not to its instance: add it under Hosts downloads may "
        "come from in the instance if it is the vendor's storage"
    )
    # Listed, but another host: still refused.
    other, held = runtime(linked(), hosts="other.storage.vendor.example.net")
    with pytest.raises(rt.CommandError, match="not to its instance: add it under"):
        other.run("download", {"id": "7"})
    assert to(world, STORE) == [] and held.kept == []


@pytest.mark.parametrize(
    ("hosts", "host"),
    [(STORE, STORE), ("*.storage.vendor.example.net", STORE), ("*.storage.vendor.example.net", DEEP)],
)
def test_a_link_to_a_listed_host_is_followed_with_nothing_of_the_connector(world, hosts, host):
    link_to(world, f"https://{host}/a/file.bin?X-Signature=abc")
    world.answer(
        host, body=FILE, headers={"content-disposition": 'attachment; filename="file.bin"'}, path="/a/file.bin"
    )
    live, held = runtime(linked(), hosts=hosts)
    answer = live.run("download", {"id": "7"})
    assert answer.outputs["name"] == "file.bin" and [item["data"] for item in held.kept] == [FILE]
    # The console was asked with the key and the headers of the connector…
    (asked,) = to(world, CONSOLE)
    assert asked["headers"]["x-apikey"] == KEY and asked["headers"]["X-Client"] == "nik-linked"
    # …and the storage host with the address alone: no key, no header of the file, none of the request.
    (fetched,) = to(world, host)
    assert fetched["path"] == "/a/file.bin?X-Signature=abc" and fetched["scheme"] == "https"
    assert {name.lower() for name in fetched["headers"]} == {"user-agent", "accept"}
    assert KEY not in str(fetched)


def test_a_redirect_is_followed_through_the_console_and_the_storage_and_no_further(world):
    # The console answers the link itself with a redirect to the storage, which sends on to a bucket.
    link_to(world, f"https://{CONSOLE}/api/dl/7")
    world.answer(CONSOLE, 302, headers={"location": f"https://{STORE}/hop?sig=1"}, path="/api/dl/7")
    world.answer(STORE, 302, headers={"location": f"https://{DEEP}/final.bin?sig=2"}, path="/hop")
    world.answer(DEEP, body=FILE, path="/final.bin")
    live, held = runtime(linked(), hosts=f"{STORE}, *.bucket.storage.vendor.example.net")
    live.run("download", {"id": "7"})
    assert [item["data"] for item in held.kept] == [FILE]
    link, redirected = to(world, CONSOLE)
    # On the console the download is a request like the others, with its key.
    assert redirected["path"] == "/api/dl/7" and redirected["headers"]["x-apikey"] == KEY
    assert redirected["headers"]["X-Asked-By"] == "7"
    for host in (STORE, DEEP):
        (sent,) = to(world, host)
        assert {name.lower() for name in sent["headers"]} == {"user-agent", "accept"}, host

    # One hop too far: a host nobody listed ends it, and the step says where it would be listed.
    world.requests.clear()
    world.host("elsewhere.example.org")
    world.answer(DEEP, 302, headers={"location": "https://elsewhere.example.org/x"}, path="/final.bin")
    live, held = runtime(linked(), hosts=f"{STORE}, *.bucket.storage.vendor.example.net")
    with pytest.raises(rt.CommandError) as refused:
        live.run("download", {"id": "7"})
    assert refused.value.message == (
        "elsewhere.example.org is not among the hosts this playbook may reach: add it under Hosts downloads may "
        "come from in the instance if it is the vendor's storage"
    )
    assert to(world, "elsewhere.example.org") == [] and held.kept == []


def test_only_https_only_a_file_and_never_an_address_inside_the_network(world):
    world.answer(STORE, body=FILE, path="/a/file.bin")
    # Plain http to a listed host is refused, as a link and as a redirect.
    link_to(world, f"http://{STORE}/a/file.bin")
    live, held = runtime(linked(), hosts=STORE)
    with pytest.raises(rt.CommandError, match="not to its instance"):
        live.run("download", {"id": "7"})
    link_to(world, f"https://{CONSOLE}/api/dl/7")
    world.answer(CONSOLE, 302, headers={"location": f"http://{STORE}/a/file.bin"}, path="/api/dl/7")
    live, held = runtime(linked(), hosts=STORE)
    with pytest.raises(rt.CommandError) as refused:
        live.run("download", {"id": "7"})
    assert refused.value.message in (
        f"A file is downloaded from {STORE} over https only",
        "Plain http is refused: use https, or allow http on the instance",
    )
    assert to(world, STORE) == []

    # A command whose answer is not a file does not go there, listed or not.
    live, held = runtime(linked(), hosts=STORE)
    with pytest.raises(rt.CommandError) as refused:
        live.run("peek", {"link": f"https://{STORE}/a/file.bin"})
    assert refused.value.message == f"A request of this connector goes to {STORE}, not to its instance"
    assert to(world, STORE) == []

    # A listed name that resolves inside the network is refused, whatever the playbook may reach.
    world.host("files.inside.vendor.example.net", "10.20.0.9")
    link_to(world, "https://files.inside.vendor.example.net/a/file.bin")
    for mode in ("listed", "any"):
        live, held = runtime(linked(), hosts="files.inside.vendor.example.net", mode=mode)
        with pytest.raises(rt.CommandError, match="is an address inside the network"):
            live.run("download", {"id": "7"})
    assert to(world, "files.inside.vendor.example.net") == [] and held.kept == []

    # A playbook that may reach any host follows the link as before; the host being listed still strips the request.
    link_to(world, f"https://{STORE}/a/file.bin")
    live, held = runtime(linked(), hosts=STORE, mode="any")
    live.run("download", {"id": "7"})
    assert {name.lower() for name in to(world, STORE)[-1]["headers"]} == {"user-agent", "accept"}


def test_a_dry_run_says_the_host_it_would_ask_and_asks_nobody(world):
    live, _held = runtime(linked(), hosts=STORE)
    would = live.would_send("download", {"id": "7"})
    assert would["host"] == CONSOLE and would["keeps"] == "a file, as an artifact" and world.requests == []


# --------------------------------------------------------------------------- #
# The instance                                                                #
# --------------------------------------------------------------------------- #
def test_the_hosts_are_saved_with_the_instance_checked_and_written_in_the_audit_log(admin: TestClient):
    with SessionLocal() as db:
        ca.install(db, written(ENTRY, OPT_IN), "admin")
        db.commit()
    shown = admin.get("/api/automation/connectors/linked").json()
    entry = next(item for item in shown["configuration"] if item["name"] == "download_hosts")
    # The form draws the field from the file: its type, and the label an administrator reads.
    assert (entry["type"], entry["label"], entry["required"]) == ("hosts", "Hosts downloads may come from", False)

    body = {
        "name": "Console",
        "connector": "linked",
        "config": {"url": f"https://{CONSOLE}/api"},
        "secrets": {"value": KEY},
    }
    made = admin.post("/api/automation/instances", json=body)
    assert made.status_code == 201, made.text
    url = f"/api/automation/instances/{made.json()['id']}"
    assert "download_hosts" not in made.json()["config"]  # optional: empty is what it was before

    def save(hosts: str):
        return admin.put(url, json={"config": {"url": f"https://{CONSOLE}/api", "download_hosts": hosts}})

    for typed, why in (
        ("https://files.example.net", "is an address: write the name of the host alone, without https://"),
        ("*", "a * stands only at the start"),
        ("10.0.0.0/8", "has a path or is a range"),
        ("files.corp", "is an internal name"),
    ):
        refused = save(typed)
        assert refused.status_code == 400, typed
        assert (
            refused.json()["detail"].startswith("Hosts downloads may come from: ") and why in refused.json()["detail"]
        )
    saved = save(f"  {STORE.upper()}\n*.bucket.storage.vendor.example.net, {STORE}")
    assert saved.status_code == 200, saved.text
    # It is configuration, shown as it is kept: lower case, each once.
    assert saved.json()["config"]["download_hosts"] == f"{STORE}, *.bucket.storage.vendor.example.net"
    emptied = save("")
    assert emptied.status_code == 200 and "download_hosts" not in emptied.json()["config"]
    with SessionLocal() as db:
        said = [row.details for row in db.scalars(select(AuditEntry).where(AuditEntry.action == "connection.update"))]
    assert any(
        f"hosts downloads may come from: none → {STORE}, *.bucket.storage.vendor.example.net" in line for line in said
    )
    assert any(
        f"hosts downloads may come from: {STORE}, *.bucket.storage.vendor.example.net → none" in line for line in said
    )


def test_the_text_of_the_format_is_what_the_tests_load():
    assert "download_hosts_from: download_hosts" in textwrap.dedent(written(ENTRY, OPT_IN))
