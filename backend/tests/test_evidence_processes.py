"""The processes of host evidence (7.0): the ``proc`` and ``proc_end`` lines become rows, are linked into trees,
the chain rules run over them, and the screens read them.

The worker is not there: ``parse._events`` says what it would send, and ``tests/sigma_double.py`` answers for its
rule routes (the log source ``nik/process-chain`` included).
"""

# ruff: noqa: F811 - the fixture ``incident`` is imported, and each test names it as its argument
from __future__ import annotations

import os
import time
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import func, insert, select

from app.core.db import SessionLocal, engine
from app.core.models import EvidenceDetection, EvidenceProcess, EvidenceRecord, EvidenceSource
from app.evidence import chains, parse, processes, trees
from app.sigma import seed
from tests.sigma_double import FakeSigma
from tests.test_evidence_parse import (  # noqa: F401 - incident is a fixture
    SOURCE,
    a_source,
    end,
    incident,
    record,
    records_of,
    source_of,
    worker_says,
)

BASE = "/api/incidents/ev-parse/evidence"
T0 = 1_700_000_000_000
HOST = "WKS-042"


def proc(number: int, image: str, pid: int, ppid: int, host: str = HOST, **more: Any) -> dict:
    """The ``proc`` line of the record ``record(number)`` makes."""
    return {
        "t": "proc",
        "key": f"evtx:WKS-042:Security:{number}",
        "ts": T0 + number * 1000,
        "host": host,
        "pid": pid,
        "ppid": ppid,
        "image": image,
        "command_line": image,
        "user": "alice",
        **more,
    }


def stop(pid: int, number: int, **more: Any) -> dict:
    return {
        "t": "proc_end",
        "key": f"evtx:WKS-042:Security:{number}",
        "ts": T0 + number * 1000,
        "host": HOST,
        "pid": pid,
        **more,
    }


def read(incident: str, monkeypatch, events: list[dict], data: bytes = b"ElfFile\x00 procs") -> str:
    source_id = a_source(incident, data)
    worker_says(monkeypatch, events)
    parse.read(source_id)
    return source_id


def rows() -> list[EvidenceProcess]:
    with SessionLocal() as db:
        return list(db.scalars(select(EvidenceProcess).order_by(EvidenceProcess.start_ts, EvidenceProcess.id)))


def by_image(*names: str) -> dict[str, EvidenceProcess]:
    found = {row.image: row for row in rows()}
    return {name: found[name] for name in names}


@pytest.fixture()
def no_start(monkeypatch):
    """A removal or a re-reading does not start a thread of its own: the tests run the linking themselves."""
    monkeypatch.setattr(processes, "start", lambda incident_id, _params=None: True)


# --------------------------------------------------------------------------- #
# Keeping                                                                     #
# --------------------------------------------------------------------------- #
def test_the_processes_a_file_gives_are_kept_with_their_record_linked_and_counted_in_the_report(incident, monkeypatch):
    source_id = read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(
                1,
                "C:\\Windows\\explorer.exe",
                100,
                4,
                parent_image="C:\\Windows\\System32\\userinit.exe",
                integrity="Medium",
            ),
            record(2),
            proc(
                2,
                "C:\\Office\\winword.exe",
                200,
                100,
                command_line="winword.exe /n a.docx",
                hashes={"SHA256": "ab" * 32},
            ),
            record(3),
            proc(3, "C:\\Windows\\System32\\cmd.exe", 300, 200),
            record(4),
            stop(300, 4),
            end(4, in_file=4),
        ],
    )
    explorer, word, cmd = by_image(
        "C:\\Windows\\explorer.exe", "C:\\Office\\winword.exe", "C:\\Windows\\System32\\cmd.exe"
    ).values()
    records = {record.key: record for record in records_of(source_id)}
    assert explorer.record_id == records["evtx:WKS-042:Security:1"].id and explorer.source_id == source_id
    assert (explorer.host, explorer.pid, explorer.ppid, explorer.integrity, explorer.username) == (
        HOST,
        100,
        4,
        "Medium",
        "alice",
    )
    assert explorer.guid == f"{HOST}|100|{T0 + 1000}" and explorer.start_ts == T0 + 1000
    assert word.command_line == "winword.exe /n a.docx" and word.hashes == {"SHA256": "ab" * 32}
    # The parent is the process of that pid; the log's parent of the first one is not in the evidence: a ghost.
    assert (word.parent_id, cmd.parent_id) == (explorer.id, word.id)
    assert explorer.parent_id is None and explorer.parent_image == "C:\\Windows\\System32\\userinit.exe"
    assert cmd.end_ts == T0 + 4000 and word.end_ts is None  # the end of the process of pid 300
    report = source_of(source_id).report
    assert report["processes"] == 3 and "logons" not in report


def test_a_file_without_processes_says_nothing_of_them_and_a_line_that_names_no_record_is_left_out(
    incident, monkeypatch
):
    source_id = read(incident, monkeypatch, [SOURCE, record(1), proc(9, "a.exe", 1, 0), end(1, 1)])
    assert rows() == [] and "processes" not in source_of(source_id).report


def test_text_is_cut_to_the_columns_and_numbers_that_are_texts_are_read(incident, monkeypatch):
    read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(1, "x" * 2000, "55", "4", command_line="c" * 9000, user="u" * 400, guid="g" * 120),
            end(1, 1),
        ],
    )
    (row,) = rows()
    assert len(row.image) == 1000 and len(row.command_line) == 8000 and len(row.username) == 255 and len(row.guid) == 80
    assert (row.pid, row.ppid) == (55, 4)


def test_a_process_with_a_sysmon_guid_is_linked_by_guid_not_by_the_pid(incident, monkeypatch):
    read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(1, "old.exe", 500, 4, guid="{A}"),
            record(2),
            proc(2, "new.exe", 500, 4, guid="{B}"),  # the same pid, later: the pid was used again
            record(3),
            proc(3, "child.exe", 600, 500, guid="{C}", parent_guid="{A}"),
            record(4),
            proc(4, "orphan.exe", 700, 500, guid="{D}", parent_guid="{Z}", parent_image="gone.exe"),
            end(4, 4),
        ],
    )
    found = by_image("old.exe", "new.exe", "child.exe", "orphan.exe")
    assert found["child.exe"].parent_id == found["old.exe"].id  # the guid says so, the latest pid 500 is another
    assert found["orphan.exe"].parent_id is None and found["orphan.exe"].parent_image == "gone.exe"
    assert found["old.exe"].guid == "{A}"


def test_the_parent_by_pid_is_the_latest_one_that_had_not_ended(incident, monkeypatch):
    read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(1, "first.exe", 500, 4),
            record(2),
            stop(500, 2),
            record(3),
            proc(3, "second.exe", 500, 4),
            record(4),
            proc(4, "child-of-second.exe", 600, 500),
            record(5),
            stop(500, 5),
            record(6),
            proc(6, "late-child.exe", 601, 500),  # the second ended: no parent, a ghost
            end(6, 6),
        ],
    )
    found = by_image("first.exe", "second.exe", "child-of-second.exe", "late-child.exe")
    assert found["first.exe"].end_ts == T0 + 2000 and found["second.exe"].end_ts == T0 + 5000
    assert found["child-of-second.exe"].parent_id == found["second.exe"].id
    assert found["late-child.exe"].parent_id is None


def test_an_end_that_comes_before_its_start_is_matched_at_the_end_of_the_file(incident, monkeypatch):
    monkeypatch.setattr(parse, "BATCH", 1)  # the end is written before the process it ends is read
    read(
        incident,
        monkeypatch,
        [SOURCE, record(1), stop(500, 5, guid="{A}"), record(2), proc(2, "a.exe", 500, 4, guid="{A}"), end(2, 2)],
    )
    (row,) = rows()
    assert row.end_ts == T0 + 5000


def test_another_file_with_the_same_records_gives_no_second_process_and_ends_what_the_first_started(
    incident, monkeypatch
):
    first = read(incident, monkeypatch, [SOURCE, record(1), proc(1, "a.exe", 500, 4), end(1, 1)])
    second = read(
        incident,
        monkeypatch,
        [SOURCE, record(1), proc(1, "a.exe", 500, 4), record(2), stop(500, 2), end(2, 2)],
        b"ElfFile\x00 another",
    )
    (row,) = rows()
    assert row.source_id == first and row.end_ts == T0 + 2000
    assert "processes" not in source_of(second).report


def test_reading_a_file_again_replaces_its_processes_and_links_the_ones_of_other_files_again(incident, monkeypatch):
    base = read(
        incident, monkeypatch, [SOURCE, record(1), proc(1, "parent.exe", 500, 4), end(1, 1)], b"ElfFile\x00 base"
    )
    other = read(
        incident,
        monkeypatch,
        [SOURCE, record(2), proc(2, "child.exe", 600, 500), end(1, 1)],
        b"ElfFile\x00 other",
    )
    found = by_image("parent.exe", "child.exe")
    assert found["child.exe"].parent_id == found["parent.exe"].id
    # The base file is read again and no longer holds the parent: the child of the other file has a ghost.
    worker_says(monkeypatch, [SOURCE, record(1), end(1, 1)])
    with SessionLocal() as db:
        parse.again(db, db.get(EvidenceSource, base))
        db.commit()
    parse.read(base)
    (child,) = rows()
    assert child.image == "child.exe" and child.source_id == other and child.parent_id is None


def test_removing_a_file_takes_its_processes_and_the_parent_of_the_others_goes(
    incident, admin: TestClient, monkeypatch, no_start
):
    base = read(
        incident, monkeypatch, [SOURCE, record(1), proc(1, "parent.exe", 500, 4), end(1, 1)], b"ElfFile\x00 base"
    )
    read(incident, monkeypatch, [SOURCE, record(2), proc(2, "child.exe", 600, 500), end(1, 1)], b"ElfFile\x00 other")
    assert admin.delete(f"{BASE}/sources/{base}").status_code == 200
    (child,) = rows()
    assert child.image == "child.exe" and child.parent_id is None
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.source_id == base)) == 0


def test_linking_again_changes_nothing_and_a_host_is_linked_apart_from_the_others(incident, monkeypatch):
    read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(1, "a.exe", 500, 4),
            record(2),
            proc(2, "b.exe", 600, 500),
            record(3),
            proc(3, "other-host.exe", 600, 500, host="SRV-1"),
            end(3, 3),
        ],
    )
    found = by_image("a.exe", "b.exe", "other-host.exe")
    assert found["b.exe"].parent_id == found["a.exe"].id and found["other-host.exe"].parent_id is None
    assert processes.link_host(incident, HOST) == {"processes": 2, "linked": 1, "changed": 0}
    assert processes.link_host(incident, "SRV-1")["linked"] == 0


# --------------------------------------------------------------------------- #
# Linking a host of many processes                                            #
# --------------------------------------------------------------------------- #
def test_a_host_of_two_hundred_thousand_processes_is_linked_in_chunks(incident, monkeypatch, capsys):
    source_id = a_source(incident, b"ElfFile\x00 big")
    total = int(os.environ.get("NIK_LINK_TOTAL", "200000"))  # 2000000 is the size a host may have
    for first in range(1, total + 1, 50_000):
        rows_ = [
            {
                "incident_id": incident,
                "source_id": source_id,
                "host": HOST,
                "guid": f"g{number}",
                # The odd ones name the guid of the process before them; the even ones are found by pid.
                "parent_guid": f"g{number - 1}" if number % 2 and number > 2 else "",
                "pid": 1000 + number,
                "ppid": 1000 + number // 2 if number % 2 == 0 else 1000 + number - 1,
                "image": f"p{number}.exe",
                "command_line": "",
                "username": "u",
                "logon_id": "",
                "integrity": "",
                "start_ts": T0 + number,
                "parent_image": "",
                "parent_command_line": "",
                "hashes": {},
            }
            for number in range(first, min(first + 50_000, total + 1))
        ]
        with SessionLocal() as db:
            db.execute(insert(EvidenceProcess.__table__), rows_)
            db.commit()
    monkeypatch.setattr(processes, "CHUNK", 7_000)
    began = time.monotonic()
    done = processes.link_host(incident, HOST)
    seconds = time.monotonic() - began
    with capsys.disabled():
        print(f"\n[link] {total} processes of one host linked in {seconds:.1f} s on {engine.dialect.name}")
    assert done == {"processes": total, "linked": total - 1, "changed": total - 1}
    assert seconds < 60 * (total // 100_000 + 1)
    with SessionLocal() as db:
        wanted = {
            number: db.scalar(select(EvidenceProcess.parent_id).where(EvidenceProcess.image == f"p{number}.exe"))
            for number in (4, 9, 10, total)
        }
        ids = {
            number: db.scalar(select(EvidenceProcess.id).where(EvidenceProcess.image == f"p{number}.exe"))
            for number in (2, 5, 8, total // 2)
        }
    assert wanted[4] == ids[2] and wanted[10] == ids[5] and wanted[total] == ids[total // 2]  # by pid
    assert wanted[9] == ids[8]  # by guid
    # Run again: nothing to write.
    assert processes.link_host(incident, HOST)["changed"] == 0


# --------------------------------------------------------------------------- #
# The routes                                                                  #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def tree(incident, monkeypatch):
    """explorer > winword > cmd > whoami (host WKS-042, with the end of cmd), a loner on SRV-1."""
    return read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(
                1, "C:\\Windows\\explorer.exe", 100, 4, parent_image="userinit.exe", parent_command_line="userinit.exe"
            ),
            record(2),
            proc(2, "C:\\Office\\winword.exe", 200, 100, command_line="winword.exe /n mal.docx"),
            record(3),
            proc(3, "C:\\Windows\\System32\\cmd.exe", 300, 200, command_line="cmd.exe /c whoami"),
            record(4),
            proc(4, "C:\\Windows\\System32\\whoami.exe", 400, 300),
            record(5),
            proc(5, "/usr/bin/sleep", 77, 1, host="SRV-1", user="bob"),
            end(5, 5),
        ],
    )


def test_the_list_pages_by_key_and_filters(tree, admin: TestClient):
    page = admin.get(f"{BASE}/processes", params={"limit": 2}).json()
    assert [item["name"] for item in page["processes"]] == ["explorer.exe", "winword.exe"]
    assert (page["count"], page["countCapped"]) == (5, False) and page["next"]
    more = admin.get(f"{BASE}/processes", params={"limit": 2, "cursor": page["next"]}).json()
    assert [item["name"] for item in more["processes"]] == ["cmd.exe", "whoami.exe"] and more["count"] is None
    last = admin.get(f"{BASE}/processes", params={"limit": 2, "cursor": more["next"]}).json()
    assert [item["name"] for item in last["processes"]] == ["sleep"] and last["next"] is None
    backwards = admin.get(f"{BASE}/processes", params={"order": "-time", "limit": 1}).json()
    assert backwards["processes"][0]["name"] == "sleep"

    def names(**params: Any) -> list[str]:
        return [item["name"] for item in admin.get(f"{BASE}/processes", params=params).json()["processes"]]

    assert names(host="SRV-1") == ["sleep"] and names(user="bob") == ["sleep"]
    assert names(q="mal.docx") == ["winword.exe"] and names(q="WHOAMI") == ["cmd.exe", "whoami.exe"]
    assert names(image="cmd.exe") == ["cmd.exe"] and names(image="C:\\Office\\winword.exe") == ["winword.exe"]
    assert names(roots="true") == ["explorer.exe", "sleep"]
    assert names(**{"from": T0 + 3000, "to": T0 + 4000}) == ["cmd.exe", "whoami.exe"]
    assert admin.get(f"{BASE}/processes", params={"cursor": "nonsense"}).status_code == 400
    assert admin.get(f"{BASE}/processes", params={"order": "file"}).status_code == 400
    assert admin.get(f"{BASE}/processes", params={"cursor": page["next"], "order": "-time"}).status_code == 400


def test_an_item_says_its_parent_children_and_detections(tree, admin: TestClient):
    items = {item["name"]: item for item in admin.get(f"{BASE}/processes").json()["processes"]}
    explorer, word, cmd = items["explorer.exe"], items["winword.exe"], items["cmd.exe"]
    assert explorer["parentId"] is None and explorer["parent"] == {
        "image": "userinit.exe",
        "commandLine": "userinit.exe",
    }
    assert word["parentId"] == explorer["id"] and word["parent"] is None
    assert (explorer["children"], word["children"], items["whoami.exe"]["children"]) == (1, 1, 0)
    assert (cmd["host"], cmd["pid"], cmd["ppid"], cmd["user"], cmd["commandLine"]) == (
        HOST,
        300,
        200,
        "alice",
        "cmd.exe /c whoami",
    )
    assert cmd["recordId"] and cmd["level"] is None and cmd["detections"] == 0 and cmd["startTs"] == T0 + 3000
    one = admin.get(f"{BASE}/processes", params={"parentId": word["id"]}).json()["processes"]
    assert [item["name"] for item in one] == ["cmd.exe"]


def test_the_tree_of_a_process_goes_up_to_the_root_and_down_with_depths(tree, admin: TestClient):
    cmd = next(item for item in admin.get(f"{BASE}/processes").json()["processes"] if item["name"] == "cmd.exe")
    answer = admin.get(f"{BASE}/processes/{cmd['id']}/tree").json()
    assert answer["node"]["name"] == "cmd.exe"
    assert [item["name"] for item in answer["ancestors"]] == ["explorer.exe", "winword.exe"]
    assert answer["ghost"] == {"image": "userinit.exe", "commandLine": "userinit.exe"}
    assert [(item["name"], item["depth"]) for item in answer["descendants"]] == [("whoami.exe", 1)]
    assert answer["cut"] is False and answer["caps"] == {"up": 32, "down": 6, "nodes": 500}
    top = admin.get(f"{BASE}/processes/{answer['ancestors'][0]['id']}/tree", params={"down": 1}).json()
    assert [item["name"] for item in top["descendants"]] == ["winword.exe"] and top["cut"] is True  # cmd is below
    short = admin.get(f"{BASE}/processes/{cmd['id']}/tree", params={"up": 1}).json()
    assert [item["name"] for item in short["ancestors"]] == ["winword.exe"] and short["cut"] is True
    assert admin.get(f"{BASE}/processes/999999/tree").status_code == 404


def test_a_tree_has_a_cap_on_its_nodes_and_says_it_was_cut(tree, admin: TestClient, monkeypatch):
    monkeypatch.setattr(trees, "NODES_MAX", 2)
    first = next(item for item in admin.get(f"{BASE}/processes").json()["processes"] if item["name"] == "explorer.exe")
    answer = admin.get(f"{BASE}/processes/{first['id']}/tree").json()
    assert [item["name"] for item in answer["descendants"]] == ["winword.exe", "cmd.exe"] and answer["cut"] is True


def test_the_hosts_with_processes_have_counts_and_a_time_span(tree, admin: TestClient):
    answer = admin.get(f"{BASE}/processes/hosts").json()
    assert answer["cut"] is False
    assert answer["hosts"] == [
        {
            "host": HOST,
            "processes": 4,
            "firstTs": T0 + 1000,
            "lastTs": T0 + 4000,
            "roots": 1,
            "detections": 0,
            "level": None,
        },
        {
            "host": "SRV-1",
            "processes": 1,
            "firstTs": T0 + 5000,
            "lastTs": T0 + 5000,
            "roots": 1,
            "detections": 0,
            "level": None,
        },
    ]


def test_the_summary_counts_the_processes_of_each_section(tree, admin: TestClient):
    kinds = admin.get(f"{BASE}/summary").json()["kinds"]
    assert kinds["eventlog"]["processes"] == 5 and kinds["eventlog"]["logons"] == 0


def test_another_incident_sees_none_of_them(tree, admin: TestClient):
    admin.post("/api/incidents", json={"id": "ev-empty", "data": {}})
    other = "/api/incidents/ev-empty/evidence"
    assert admin.get(f"{other}/processes").json()["processes"] == []
    assert admin.get(f"{other}/processes/hosts").json()["hosts"] == []
    first = admin.get(f"{BASE}/processes").json()["processes"][0]["id"]
    assert admin.get(f"{other}/processes/{first}/tree").status_code == 404
    assert admin.get("/api/incidents/nope/evidence/processes").status_code == 404


def test_a_reader_may_read_them_and_a_key_without_the_permission_may_not(tree, admin: TestClient):
    from tests.conftest import make_key

    reader = make_key(admin, roles=["viewer"])
    for path in ("processes", "processes/hosts", "logons", "logons/graph"):
        assert admin.get(f"{BASE}/{path}", headers=reader).status_code == 200
    blind = make_key(admin, roles=["connectors"])
    for path in ("processes", "processes/hosts", "processes/1/tree", "logons", "logons/graph"):
        assert admin.get(f"{BASE}/{path}", headers=blind).status_code == 403, path


# --------------------------------------------------------------------------- #
# The chain rules                                                             #
# --------------------------------------------------------------------------- #
def chain_rule(rule_id: str, title: str, level: str, detection: dict[str, Any], condition: str = "selection") -> str:
    return yaml.safe_dump(
        {
            "title": title,
            "id": rule_id,
            "status": "test",
            "author": "Nik",
            "tags": ["attack.execution"],
            "logsource": {"product": "nik", "service": "process-chain"},
            "detection": {**detection, "condition": condition},
            "level": level,
        },
        sort_keys=False,
    )


WORD_CMD = "11111111-1111-4111-8111-111111111111"
DEEP = "22222222-2222-4222-8222-222222222222"
OTHER = "33333333-3333-4333-8333-333333333333"


@pytest.fixture()
def chain_rules(admin: TestClient, incident, monkeypatch) -> FakeSigma:
    fake = FakeSigma(monkeypatch)
    texts = [
        chain_rule(
            WORD_CMD,
            "Word starts cmd",
            "high",
            {"selection": {"ParentImage|endswith": "\\winword.exe", "Image|endswith": "\\cmd.exe"}},
        ),
        chain_rule(
            DEEP,
            "A shell far below explorer",
            "critical",
            {
                "selection": {"Ancestors|contains": "explorer.exe", "GrandParentImage|endswith": "\\winword.exe"},
                "shell": {"Image|endswith": ["\\whoami.exe", "\\net.exe"]},
            },
            "selection and shell",
        ),
    ]
    for text in texts:
        assert admin.post("/api/sigma/rules", json={"source": text}).status_code == 201
    return fake


def a_chain(incident, monkeypatch, data: bytes = b"ElfFile\x00 chain") -> str:
    return read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(1, "C:\\Windows\\explorer.exe", 100, 4),
            record(2),
            proc(2, "C:\\Office\\winword.exe", 200, 100),
            record(3),
            proc(3, "C:\\Windows\\System32\\cmd.exe", 300, 200),
            record(4),
            proc(4, "C:\\Windows\\System32\\whoami.exe", 400, 300),
            end(4, 4),
        ],
        data,
    )


def test_a_chain_rule_that_matches_is_a_detection_on_the_record_of_the_process_and_gives_it_a_level(
    incident, chain_rules, admin: TestClient, monkeypatch
):
    source_id = a_chain(incident, monkeypatch)
    found = by_image("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\whoami.exe", "C:\\Office\\winword.exe")
    cmd, whoami, word = found.values()
    assert (cmd.level, whoami.level, word.level) == (4, 5, None)
    with SessionLocal() as db:
        rule_rows = {(d.record_id, d.rule_id): d for d in db.scalars(select(EvidenceDetection))}
        record_levels = {
            r.id: r.level for r in db.scalars(select(EvidenceRecord).where(EvidenceRecord.source_id == source_id))
        }
    assert set(rule_rows) == {(cmd.record_id, WORD_CMD), (whoami.record_id, DEEP)}
    detection = rule_rows[(cmd.record_id, WORD_CMD)]
    assert (detection.rule_title, detection.rule_author, detection.level, detection.tags) == (
        "Word starts cmd",
        "Nik",
        4,
        ["attack.execution"],
    )
    assert (
        record_levels[cmd.record_id] == 4
        and record_levels[whoami.record_id] == 5
        and record_levels[word.record_id] is None
    )
    # What the worker was given: one synthetic record per process, with the fields of the design.
    (call,) = chain_rules.of("/sigma/try")
    given = {item["data"]["Image"].rsplit("\\", 1)[-1]: item for item in call["records"]}
    assert {item["kind"] for item in call["records"]} == {"process-chain"} and [
        line["service"] for line in call["rules"]
    ] == ["process-chain"] * 2
    who = given["whoami.exe"]["data"]
    assert (
        who["ParentImage"] == "C:\\Windows\\System32\\cmd.exe" and who["GrandParentImage"] == "C:\\Office\\winword.exe"
    )
    assert who["Ancestors"] == [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Office\\winword.exe",
        "C:\\Windows\\explorer.exe",
    ]
    assert (who["Depth"], who["Host"], who["Platform"], who["User"], who["CommandLine"]) == (
        3,
        HOST,
        "windows",
        "alice",
        who["Image"],
    )
    assert given["explorer.exe"]["data"]["Ancestors"] == [] and given["explorer.exe"]["data"]["Depth"] == 0
    # The screens: the level of the process, the detections of its record, the records filtered by rule.
    items = {item["name"]: item for item in admin.get(f"{BASE}/processes", params={"level": 5}).json()["processes"]}
    assert list(items) == ["whoami.exe"] and items["whoami.exe"]["detections"] == 1
    assert admin.get(f"{BASE}/records", params={"rule": WORD_CMD}).json()["count"] == 1
    assert admin.get(f"{BASE}/processes/hosts").json()["hosts"][0]["level"] == 5


def test_a_file_is_not_done_before_its_chains_ran_and_what_they_found_is_in_its_report_its_line_and_its_event(
    incident, chain_rules, monkeypatch
):
    from app.core.models import AutomationEvent, WarRoomEntry

    seen: list[tuple[str, str]] = []
    ask = chain_rules.ask

    def watching(route, body=None, **more):
        if route == "/sigma/try":
            with SessionLocal() as db:
                row = db.scalars(select(EvidenceSource)).one()
                lines = db.scalars(select(WarRoomEntry)).all()
                events = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "evidence.detected")).all()
                seen.append((row.state, f"{len(lines)} lines, {len(events)} events"))
        return ask(route, body, **more)

    monkeypatch.setattr(chains.worker, "ask", watching)
    source_id = a_chain(incident, monkeypatch)
    # While the chains were asked, the file was still being read: no line of the War Room, no event, yet.
    assert seen == [("parsing", "0 lines, 0 events")]
    row = source_of(source_id)
    assert row.state == "done" and row.read == "complete"
    assert row.report["detections"] == {
        "total": 2,
        "byLevel": {"1": 0, "2": 0, "3": 0, "4": 1, "5": 1},
        "rules": [
            {"id": DEEP, "title": "A shell far below explorer", "level": 5, "count": 1},
            {"id": WORD_CMD, "title": "Word starts cmd", "level": 4, "count": 1},
        ],
    }
    with SessionLocal() as db:
        texts = [e.body["text"] for e in db.scalars(select(WarRoomEntry))]
        (event,) = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "evidence.detected")).all()
    assert texts[0].endswith("read: 4 records kept.") and texts[-1].startswith(
        "Security.evtx: 2 detections (1 critical, 1 high)."
    )
    assert (event.payload["data"]["count"], event.payload["data"]["levelNumber"]) == (2, 5)
    # Reading it again: the chains are made again, the totals are the same, there is one more event.
    parse.read(source_id)
    assert source_of(source_id).report["detections"]["total"] == 2 and source_of(source_id).state == "done"


def test_a_file_read_earlier_has_its_totals_counted_again_when_another_file_of_the_host_gives_the_chains_a_match(
    incident, chain_rules, monkeypatch
):
    first = read(
        incident,
        monkeypatch,
        [SOURCE, record(1), proc(1, "C:\\Office\\winword.exe", 200, 4), end(1, 1)],
        b"ElfFile\x00 one",
    )
    assert "detections" not in source_of(first).report
    second = read(
        incident,
        monkeypatch,
        [SOURCE, record(2), proc(2, "C:\\Windows\\System32\\cmd.exe", 300, 200), end(1, 1)],
        b"ElfFile\x00 two",
    )
    assert source_of(second).report["detections"]["total"] == 1
    # The first file's report does not change: the match is on a record of the second.
    assert "detections" not in source_of(first).report


def test_a_process_has_the_level_of_its_record_whichever_rule_found_it(incident, chain_rules, monkeypatch):
    a_chain(incident, monkeypatch)
    explorer = by_image("C:\\Windows\\explorer.exe")["C:\\Windows\\explorer.exe"]
    assert explorer.level is None
    # A rule that read the file (not a chain rule) matched the record of the explorer.
    with SessionLocal() as db:
        db.add(
            EvidenceDetection(
                incident_id=incident,
                record_id=explorer.record_id,
                rule_id="44444444-4444-4444-8444-444444444444",
                rule_title="Read by the file",
                level=3,
                records=[],
                created_at="2026-11-25T00:00:00Z",
            )
        )
        db.get(EvidenceRecord, explorer.record_id).level = 3
        db.commit()
    chains.sync_levels(incident, [HOST])
    levels = {row.image.rsplit("\\", 1)[-1]: row.level for row in rows()}
    assert levels == {"explorer.exe": 3, "winword.exe": None, "cmd.exe": 4, "whoami.exe": 5}


def test_a_run_replaces_the_chain_detections_of_its_hosts_and_leaves_what_other_rules_found(
    incident, chain_rules, admin: TestClient, monkeypatch
):
    source_id = a_chain(incident, monkeypatch)
    cmd = by_image("C:\\Windows\\System32\\cmd.exe")["C:\\Windows\\System32\\cmd.exe"]
    # A rule of the file's own kind matched the same record, at a higher level.
    with SessionLocal() as db:
        db.add(
            EvidenceDetection(
                incident_id=incident,
                record_id=cmd.record_id,
                rule_id="other-rule",
                rule_title="Other",
                rule_author="x",
                level=5,
                tags=[],
                records=[],
                created_at="2026-11-25T00:00:00Z",
            )
        )
        record = db.get(EvidenceRecord, cmd.record_id)
        record.level = 5
        db.commit()
    # Switch the rule off and run the host again: its detection is gone, the other rule's stays, the level is remade.
    assert admin.patch(f"/api/sigma/rules/{WORD_CMD}", json={"enabled": False}).status_code == 200
    chains.run(incident, [HOST])
    with SessionLocal() as db:
        assert {d.rule_id for d in db.scalars(select(EvidenceDetection))} == {"other-rule", DEEP}
        assert db.get(EvidenceRecord, cmd.record_id).level == 5
    assert by_image("C:\\Windows\\System32\\cmd.exe")["C:\\Windows\\System32\\cmd.exe"].level is None
    # Both rules off: nothing is run, and the chain detections go.
    assert admin.patch(f"/api/sigma/rules/{DEEP}", json={"enabled": False}).status_code == 200
    asked = len(chain_rules.of("/sigma/try"))
    chains.run(incident, [HOST])
    assert len(chain_rules.of("/sigma/try")) == asked
    with SessionLocal() as db:
        assert [d.rule_id for d in db.scalars(select(EvidenceDetection))] == ["other-rule"]
    assert all(row.level is None for row in rows()) and source_id


def test_only_the_hosts_a_run_covers_are_replaced(incident, chain_rules, monkeypatch):
    read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(1, "C:\\Office\\winword.exe", 200, 4),
            record(2),
            proc(2, "C:\\Windows\\System32\\cmd.exe", 300, 200),
            record(3),
            proc(3, "C:\\Office\\winword.exe", 200, 4, host="SRV-1"),
            record(4),
            proc(4, "C:\\Windows\\System32\\cmd.exe", 300, 200, host="SRV-1"),
            end(4, 4),
        ],
    )
    assert [row.level for row in rows() if row.image.endswith("cmd.exe")] == [4, 4]
    chain_rules.calls.clear()
    chains.run(incident, ["SRV-1"])
    (call,) = chain_rules.of("/sigma/try")
    assert {item["host"] for item in call["records"]} == {"SRV-1"}
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EvidenceDetection)) == 2


def test_with_no_worker_or_no_chain_rule_nothing_happens_and_the_file_is_read_all_the_same(
    incident, admin: TestClient, monkeypatch
):
    source_id = a_chain(incident, monkeypatch)  # no rules, and the worker is a name that answers nothing
    assert source_of(source_id).read == "complete" and all(row.level is None for row in rows())
    fake = FakeSigma(monkeypatch)
    assert chains.run(incident, [HOST]) == {"hosts": 0, "matched": 0} and fake.of("/sigma/try") == []
    from app.core.config import settings

    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    assert chains.run(incident, [HOST]) == {"hosts": 0, "matched": 0}


def test_the_chain_rules_are_not_given_to_the_worker_with_a_file(incident, chain_rules, monkeypatch):
    from app.sigma import ruleset

    with SessionLocal() as db:
        assert ruleset.current(db) is None  # they are the only rules there are, and they run over processes
        lines, meta, every = ruleset.chains(db)
    assert {line["id"] for line in lines} == {WORD_CMD, DEEP} == every and meta[DEEP]["level"] == 5


def test_the_chain_pack_that_nik_ships_has_sixteen_rules_each_with_what_a_rule_needs(admin: TestClient, monkeypatch):
    fake = FakeSigma(monkeypatch)
    with SessionLocal() as db:
        seed.seed(db)
        db.commit()
    shipped = {
        rule_id: text for rule_id, (pack, text) in seed.shipped_by_pack().items() if pack == "nik-process-chains"
    }
    assert len(shipped) == 16 and fake
    for text in shipped.values():
        doc = yaml.safe_load(text)
        assert doc["author"] == "Nik" and doc["logsource"] == {"product": "nik", "service": "process-chain"}
        assert doc["level"] in ("medium", "high", "critical") and doc["falsepositives"] and doc["description"]
        assert any(tag.startswith("attack.t") for tag in doc["tags"]) and len(doc["id"]) == 36


def test_the_pack_finds_a_macro_that_starts_powershell_with_the_double(admin: TestClient, incident, monkeypatch):
    fake = FakeSigma(monkeypatch)
    with SessionLocal() as db:
        seed.seed(db)
        db.commit()
    read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            proc(1, "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", 200, 4),
            record(2),
            proc(
                2,
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                300,
                200,
                command_line="powershell -enc AAAA",
            ),
            record(3),
            proc(3, "/usr/sbin/apache2", 10, 1, host="WEB-1"),
            record(4),
            proc(4, "/bin/bash", 11, 10, host="WEB-1", command_line="bash -c id"),
            end(4, 4),
        ],
    )
    assert fake
    titles = {row.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]: row.level for row in rows() if row.level is not None}
    assert titles == {"powershell.exe": 4, "bash": 4}
    with SessionLocal() as db:
        names = {d.rule_title for d in db.scalars(select(EvidenceDetection))}
    assert names == {"Office Application Starts a Script Host or a Shell", "Web Server Starts a Shell (Linux)"}


def test_the_platform_comes_from_the_path_of_the_image():
    assert (
        chains.platform_of("C:\\Windows\\cmd.exe") == "windows" and chains.platform_of("\\Device\\x.exe") == "windows"
    )
    assert chains.platform_of("/usr/bin/bash") == "linux" and chains.platform_of("/System/Library/x") == "macos"
    assert chains.platform_of("/Applications/Safari.app/Contents/MacOS/Safari") == "macos"


def test_the_ancestors_stop_at_eight(incident, chain_rules, monkeypatch):
    events: list[dict] = [SOURCE]
    for number in range(1, 13):
        events += [
            record(number),
            proc(number, f"C:\\d\\p{number}.exe", 100 + number, 99 + number if number > 1 else 4),
        ]
    read(incident, monkeypatch, [*events, end(12, 12)])
    (call,) = chain_rules.of("/sigma/try")
    last = next(item for item in call["records"] if item["data"]["Image"].endswith("p12.exe"))
    assert last["data"]["Depth"] == 8 and last["data"]["Ancestors"][0].endswith("p11.exe")
    assert last["data"]["Ancestors"][-1].endswith("p4.exe")


def test_the_worker_refusing_a_batch_does_not_fail_the_reading(incident, chain_rules, monkeypatch):
    original = chain_rules.ask

    def refuse(route, body=None, **kwargs):
        if route == "/sigma/try":
            return 503, {"detail": "busy"}
        return original(route, body, **kwargs)

    from app.sigma import worker

    monkeypatch.setattr(worker, "ask", refuse)
    source_id = a_chain(incident, monkeypatch)
    assert source_of(source_id).read == "complete" and all(row.level is None for row in rows())


def test_processes_are_gone_with_the_incident(incident, admin: TestClient, monkeypatch):
    a_chain(incident, monkeypatch)
    assert admin.delete("/api/incidents/ev-parse").status_code in (200, 204)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(EvidenceProcess)) == 0
