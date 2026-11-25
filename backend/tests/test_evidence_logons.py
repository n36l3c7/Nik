"""The logons of host evidence (7.0): the ``logon`` lines become rows, the screens page through them, and the graph
of lateral movement is made by the database.

The worker is not there: ``parse._events`` says what it would send.
"""

# ruff: noqa: F811 - the fixture ``incident`` is imported, and each test names it as its argument
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, insert, select

from app.core.db import SessionLocal
from app.core.models import EvidenceLogon
from app.evidence import lateral, parse
from tests.test_evidence_parse import (  # noqa: F401 - incident is a fixture
    SOURCE,
    a_source,
    end,
    incident,
    record,
    source_of,
    worker_says,
)

BASE = "/api/incidents/ev-parse/evidence"
T0 = 1_700_000_000_000


def logon(number: int, host: str, **more: Any) -> dict:
    """The ``logon`` line of the record ``record(number)`` makes."""
    return {
        "t": "logon",
        "key": f"evtx:WKS-042:Security:{number}",
        "ts": T0 + number * 1000,
        "host": host,
        "user": "alice",
        "domain": "CORP",
        "logon_type": 3,
        "logon_id": "0x3e7",
        "outcome": "success",
        "method": "NTLM",
        **more,
    }


def read(incident: str, monkeypatch, lines: list[dict], data: bytes = b"ElfFile\x00 logons") -> str:
    """A file whose records are one for each line, in order (the first line is the record 1)."""
    source_id = a_source(incident, data)
    events: list[dict] = [SOURCE]
    for number, line in enumerate(lines, 1):
        events += [record(number), {**line, "key": f"evtx:WKS-042:Security:{number}", "ts": T0 + number * 1000}]
    worker_says(monkeypatch, [*events, end(len(lines), len(lines))])
    parse.read(source_id)
    return source_id


def stored() -> list[EvidenceLogon]:
    with SessionLocal() as db:
        return list(db.scalars(select(EvidenceLogon).order_by(EvidenceLogon.id)))


def lines_of_a_week() -> list[dict]:
    """WKS-1 reaches SRV-1 (5 logons, 2 failures); an address that is no host fails against SRV-1 three times;
    SRV-1 reaches DC-1; and the logons that are nobody's movement."""
    out = [logon(0, "SRV-1", source_host="WKS-1", source_ip="10.0.0.5") for _ in range(5)]
    out += [
        logon(0, "SRV-1", source_host="wks-1", user="bob", outcome="failure", status="0xc000006d") for _ in range(2)
    ]
    out += [
        logon(0, "SRV-1", source_ip="10.0.0.9", user="admin", outcome="failure", logon_type=10, method="Negotiate")
        for _ in range(3)
    ]
    out += [logon(0, "DC-1", source_host="SRV-1", user="svc-backup", method="Kerberos") for _ in range(4)]
    # Nobody's movement: the machine itself, a service, a logoff, a privilege, a host reaching itself.
    out += [
        logon(0, "SRV-1", source_ip="-", logon_type=2),
        logon(0, "SRV-1", source_ip="127.0.0.1", logon_type=2),
        logon(0, "SRV-1", source_ip="::1", logon_type=5),
        logon(0, "SRV-1", logon_type=5),
        logon(0, "SRV-1", source_host="WKS-1", outcome="logoff"),
        logon(0, "SRV-1", source_host="WKS-1", outcome="privileged"),
        logon(0, "SRV-1", source_host="srv-1"),
    ]
    return out


@pytest.fixture()
def week(incident, monkeypatch):
    return read(incident, monkeypatch, lines_of_a_week())


# --------------------------------------------------------------------------- #
# Keeping                                                                     #
# --------------------------------------------------------------------------- #
def test_the_logons_a_file_gives_are_kept_with_their_record_and_counted_in_the_report(incident, monkeypatch):
    source_id = read(
        incident,
        monkeypatch,
        [
            logon(0, "SRV-1", source_host="WKS-1", source_ip="10.0.0.5", logon_type="10", method="NTLM"),
            logon(0, "SRV-1", outcome="failure", status="0xc000006d", logon_type=None),
            logon(0, "SRV-1", outcome="bogus"),  # not one of the outcomes: left out
            logon(0, "", user="u" * 400),  # no host of its own: the file's
        ],
    )
    first, second, third = stored()
    assert (first.host, first.source_host, first.source_ip, first.logon_type, first.method) == (
        "SRV-1",
        "WKS-1",
        "10.0.0.5",
        10,
        "NTLM",
    )
    assert (first.username, first.domain, first.logon_id, first.outcome, first.ts) == (
        "alice",
        "CORP",
        "0x3e7",
        "success",
        T0 + 1000,
    )
    assert (second.outcome, second.status, second.logon_type) == ("failure", "0xc000006d", None)
    assert third.host == "WKS-042" and len(third.username) == 255
    assert first.source_id == source_id and first.record_id and first.incident_id == incident
    assert source_of(source_id).report["logons"] == 3 and "processes" not in source_of(source_id).report


def test_a_record_another_file_held_first_gives_no_second_logon(incident, monkeypatch):
    read(incident, monkeypatch, [logon(0, "SRV-1")])
    second = read(incident, monkeypatch, [logon(0, "SRV-1"), logon(0, "SRV-2")], b"ElfFile\x00 more")
    assert [(row.host, row.source_id) for row in stored()][1:] == [("SRV-2", second)]
    assert source_of(second).report["logons"] == 1


def test_reading_a_file_again_replaces_its_logons(incident, monkeypatch):
    from app.core.models import EvidenceSource

    source_id = read(incident, monkeypatch, [logon(0, "SRV-1"), logon(0, "SRV-2")])
    worker_says(monkeypatch, [SOURCE, record(1), logon(1, "SRV-3"), end(1, 1)])
    with SessionLocal() as db:
        parse.again(db, db.get(EvidenceSource, source_id))
        db.commit()
    parse.read(source_id)
    assert [row.host for row in stored()] == ["SRV-3"]


# --------------------------------------------------------------------------- #
# The list                                                                    #
# --------------------------------------------------------------------------- #
def test_the_list_pages_by_key_and_says_what_each_logon_is(week, admin: TestClient):
    page = admin.get(f"{BASE}/logons", params={"limit": 4}).json()
    assert len(page["logons"]) == 4 and (page["count"], page["countCapped"]) == (21, False) and page["next"]
    first = page["logons"][0]
    assert first["host"] == "SRV-1" and first["sourceHost"] == "WKS-1" and first["sourceIp"] == "10.0.0.5"
    assert (first["user"], first["domain"], first["logonType"], first["outcome"], first["method"], first["ts"]) == (
        "alice",
        "CORP",
        3,
        "success",
        "NTLM",
        T0 + 1000,
    )
    assert first["recordId"] and first["sourceId"] == week and first["status"] == ""
    seen = [item["id"] for item in page["logons"]]
    cursor = page["next"]
    while cursor:
        more = admin.get(f"{BASE}/logons", params={"limit": 4, "cursor": cursor}).json()
        assert more["count"] is None
        seen += [item["id"] for item in more["logons"]]
        cursor = more["next"]
    assert len(seen) == len(set(seen)) == 21
    newest = admin.get(f"{BASE}/logons", params={"order": "-time", "limit": 1}).json()["logons"][0]
    assert newest["ts"] == T0 + 21_000


def test_the_list_filters(week, admin: TestClient):
    def count(**params: Any) -> int:
        return admin.get(f"{BASE}/logons", params=params).json()["count"]

    assert count(host="DC-1") == 4 and count(user="bob") == 2 and count(sourceIp="10.0.0.9") == 3
    assert count(sourceHost="SRV-1") == 4 and count(outcome="failure") == 5 and count(outcome="failure,logoff") == 6
    assert count(logonType="10") == 3 and count(logonType="2,5") == 4 and count(logonType=["2", "5"]) == 4
    assert count(q="svc-back") == 4 and count(q="10.0.0") == 8 and count(q="no-such") == 0
    assert count(**{"from": T0 + 10_000, "to": T0 + 12_000}) == 3
    assert admin.get(f"{BASE}/logons", params={"outcome": "nope"}).status_code == 400
    assert admin.get(f"{BASE}/logons", params={"logonType": "x"}).status_code == 400
    assert admin.get(f"{BASE}/logons", params={"cursor": "zz"}).status_code == 400
    assert admin.get(f"{BASE}/logons", params={"order": "x"}).status_code == 400


def test_the_failed_ones_say_why(week, admin: TestClient):
    failed = admin.get(f"{BASE}/logons", params={"outcome": "failure", "user": "bob"}).json()["logons"]
    assert [item["status"] for item in failed] == ["0xc000006d"] * 2


def test_the_summary_counts_the_logons_of_each_section(week, admin: TestClient):
    assert admin.get(f"{BASE}/summary").json()["kinds"]["eventlog"]["logons"] == 21


# --------------------------------------------------------------------------- #
# The graph                                                                   #
# --------------------------------------------------------------------------- #
def edges_of(answer: dict) -> dict[tuple[str, str], dict]:
    return {(edge["from"], edge["to"]): edge for edge in answer["edges"]}


def test_the_graph_is_made_of_where_logons_came_from_and_the_host_they_reached(week, admin: TestClient):
    answer = admin.get(f"{BASE}/logons/graph").json()
    edges = edges_of(answer)
    assert set(edges) == {("host:wks-1", "host:srv-1"), ("address:10.0.0.9", "host:srv-1"), ("host:srv-1", "host:dc-1")}
    wks = edges[("host:wks-1", "host:srv-1")]
    assert (wks["count"], wks["failed"], wks["users"], wks["types"]) == (7, 2, ["alice", "bob"], [3])
    assert (wks["firstTs"], wks["lastTs"]) == (T0 + 1000, T0 + 7000)
    address = edges[("address:10.0.0.9", "host:srv-1")]
    assert (address["count"], address["failed"], address["users"], address["types"]) == (3, 3, ["admin"], [10])
    assert edges[("host:srv-1", "host:dc-1")]["users"] == ["svc-backup"]
    nodes = {node["id"]: node for node in answer["nodes"]}
    assert set(nodes) == {"host:wks-1", "host:srv-1", "host:dc-1", "address:10.0.0.9"}
    assert (nodes["host:srv-1"]["logonsIn"], nodes["host:srv-1"]["logonsOut"], nodes["host:srv-1"]["failed"]) == (
        10,
        4,
        5,
    )
    assert (nodes["host:wks-1"]["logonsOut"], nodes["host:wks-1"]["logonsIn"]) == (7, 0)
    assert nodes["host:wks-1"]["label"].lower() == "wks-1"
    assert (nodes["address:10.0.0.9"]["kind"], nodes["address:10.0.0.9"]["label"]) == ("address", "10.0.0.9")
    # The incident holds logons of SRV-1 and DC-1, not of WKS-1 or of the address.
    assert {node_id: node["inEvidence"] for node_id, node in nodes.items()} == {
        "host:srv-1": True,
        "host:dc-1": True,
        "host:wks-1": False,
        "address:10.0.0.9": False,
    }
    assert answer["cut"] is False and answer["caps"] == {"nodes": 300, "edges": 1500}
    # The same ids in every call; the busiest node first.
    again = admin.get(f"{BASE}/logons/graph").json()
    assert [node["id"] for node in again["nodes"]] == [node["id"] for node in answer["nodes"]]
    assert answer["nodes"][0]["id"] == "host:srv-1"


def test_an_explicit_logon_with_a_target_is_an_edge_from_the_host_to_the_target(incident, monkeypatch, admin):
    read(
        incident,
        monkeypatch,
        [
            logon(0, "WKS-1", outcome="explicit", user="admin", logon_type=None, target_host="SRV-2"),
            logon(0, "WKS-1", outcome="explicit", user="admin", logon_type=None, target_host="srv-2"),
            # The log knows an address the logon was made from, and no target: as before, an edge into the host.
            logon(0, "WKS-1", outcome="explicit", user="bob", logon_type=None, source_ip="10.1.1.1"),
            # No source and no target: no edge.
            logon(0, "WKS-1", outcome="explicit", user="carol", logon_type=None),
            # A target that is the host itself: no edge.
            logon(0, "WKS-1", outcome="explicit", user="dave", logon_type=None, target_host="wks-1"),
        ],
    )
    assert [row.target_host for row in stored()] == ["SRV-2", "srv-2", "", "", "wks-1"]
    answer = admin.get(f"{BASE}/logons/graph").json()
    edges = edges_of(answer)
    assert set(edges) == {("host:wks-1", "host:srv-2"), ("address:10.1.1.1", "host:wks-1")}
    assert (edges[("host:wks-1", "host:srv-2")]["count"], edges[("host:wks-1", "host:srv-2")]["users"]) == (
        2,
        ["admin"],
    )
    nodes = {node["id"]: node for node in answer["nodes"]}
    assert nodes["host:wks-1"]["logonsOut"] == 2 and nodes["host:srv-2"]["logonsIn"] == 2
    assert nodes["host:srv-2"]["label"] in ("SRV-2", "srv-2")
    listed = admin.get(f"{BASE}/logons", params={"outcome": "explicit"}).json()["logons"]
    assert sorted(item["targetHost"] for item in listed) == ["", "", "SRV-2", "srv-2", "wks-1"]


def test_a_host_that_has_a_file_or_processes_is_in_the_evidence(week, admin: TestClient, incident):
    from app.core.models import EvidenceProcess

    with SessionLocal() as db:
        db.execute(
            insert(EvidenceProcess.__table__),
            [
                {
                    "incident_id": incident,
                    "source_id": week,
                    "host": "Wks-1",
                    "guid": "g",
                    "image": "a.exe",
                    "command_line": "",
                    "username": "",
                    "logon_id": "",
                    "integrity": "",
                    "parent_image": "",
                    "parent_command_line": "",
                    "hashes": {},
                }
            ],
        )
        db.commit()
    nodes = {node["id"]: node for node in admin.get(f"{BASE}/logons/graph").json()["nodes"]}
    assert nodes["host:wks-1"]["inEvidence"] is True and nodes["address:10.0.0.9"]["inEvidence"] is False


def test_the_graph_filters(week, admin: TestClient):
    def edges(**params: Any) -> set[tuple[str, str]]:
        return set(edges_of(admin.get(f"{BASE}/logons/graph", params=params).json()))

    assert edges(minCount=4) == {("host:wks-1", "host:srv-1"), ("host:srv-1", "host:dc-1")}
    assert edges(user="admin") == {("address:10.0.0.9", "host:srv-1")}
    assert edges(logonType="10") == {("address:10.0.0.9", "host:srv-1")}
    assert edges(outcome="failure") == {("host:wks-1", "host:srv-1"), ("address:10.0.0.9", "host:srv-1")}
    assert edges(**{"from": T0 + 13_000}) == {("host:srv-1", "host:dc-1")}
    assert edges(**{"to": T0 + 7_000}) == {("host:wks-1", "host:srv-1")}
    assert edges(outcome="logoff") == set() == edges(user="nobody")
    only = edges_of(admin.get(f"{BASE}/logons/graph", params={"outcome": "failure"}).json())
    assert only[("host:wks-1", "host:srv-1")]["count"] == 2
    assert admin.get(f"{BASE}/logons/graph", params={"outcome": "logoff"}).status_code == 200
    assert admin.get(f"{BASE}/logons/graph", params={"outcome": "nope"}).status_code == 400
    assert admin.get(f"{BASE}/logons/graph", params={"logonType": "a"}).status_code == 400


def test_the_graph_keeps_the_busiest_edges_and_says_it_was_cut(week, admin: TestClient, monkeypatch):
    monkeypatch.setattr(lateral, "NODES_MAX", 3)
    answer = admin.get(f"{BASE}/logons/graph").json()
    assert len(answer["nodes"]) <= 3 and answer["cut"] is True
    assert ("host:wks-1", "host:srv-1") in edges_of(answer)  # the busiest
    monkeypatch.setattr(lateral, "NODES_MAX", 300)
    monkeypatch.setattr(lateral, "EDGES_MAX", 1)
    answer = admin.get(f"{BASE}/logons/graph").json()
    assert [(e["from"], e["to"]) for e in answer["edges"]] == [("host:wks-1", "host:srv-1")] and answer["cut"] is True


def test_a_large_graph_is_aggregated_by_the_database_and_capped(incident, admin: TestClient):
    """Four thousand hosts each reaching one server twice: the graph holds the busiest 300 nodes and says it was cut."""
    source_id = a_source(incident, b"ElfFile\x00 many")
    with SessionLocal() as db:
        db.execute(
            insert(EvidenceLogon.__table__),
            [
                {
                    "incident_id": incident,
                    "source_id": source_id,
                    "ts": T0 + number,
                    "host": "SRV-1",
                    "source_host": f"H{number % 4000}",
                    "source_ip": "",
                    "username": "u",
                    "domain": "",
                    "logon_type": 3,
                    "logon_id": "",
                    "outcome": "success",
                    "method": "",
                    "status": "",
                }
                for number in range(8000)
            ],
        )
        db.commit()
    answer = admin.get(f"{BASE}/logons/graph").json()
    assert len(answer["nodes"]) == 300 and len(answer["edges"]) == 299 and answer["cut"] is True
    assert {edge["to"] for edge in answer["edges"]} == {"host:srv-1"} and all(
        edge["count"] == 2 for edge in answer["edges"]
    )
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EvidenceLogon)) == 8000


def test_an_incident_with_no_logons_has_an_empty_graph(incident, admin: TestClient):
    answer = admin.get(f"{BASE}/logons/graph").json()
    assert answer == {"nodes": [], "edges": [], "cut": False, "caps": {"nodes": 300, "edges": 1500}}
    assert admin.get(f"{BASE}/logons").json()["logons"] == []
    assert admin.get("/api/incidents/nope/evidence/logons/graph").status_code == 404
