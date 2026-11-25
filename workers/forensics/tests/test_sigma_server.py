"""Sigma over HTTP: the hand-over of a rule set, the detections in a parse, the check and the try.

Run in the worker's image: ``python -m pytest tests`` from /opt/nik-forensics. The events are those of the committed
evtx sample (see ``fixtures/README.md``) and of files made here: harmless text, never evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

from sigma_support import correlation, rid, rule
from test_forensics import call, events, worker  # noqa: F401 - the fixture

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "Application_no_crc32.evtx")


def ndjson(rules: list[dict]) -> tuple[bytes, str]:
    body = b"".join(json.dumps(line).encode() + b"\n" for line in rules)
    return body, hashlib.sha256(body).hexdigest()


def give(base: str, data: bytes) -> str:
    name = hashlib.sha256(data).hexdigest() + ".bin"
    assert call(base, "PUT", f"/files/{name}", raw=data)[0] == 200
    return name


def test_the_rule_set_is_asked_for_given_and_its_detections_follow_their_records(worker):  # noqa: F811
    _server, base = worker
    with open(SAMPLE, "rb") as handle:
        name = give(base, handle.read())
    spp = {"s": {"Provider_Name": "Microsoft-Windows-Security-SPP", "EventID": 1003}, "condition": "s"}
    rules = [
        rule("spp", spp, category=None, service="application"),
        rule(
            "winlogon",
            {"s": {"EventID": 6000, "provider": "microsoft-windows-winlogon"}, "condition": "s"},
            category=None,
            service="application",
        ),
        rule("refused", {"s": {"Data|re": "(?=a)b"}, "condition": "s"}, category=None, service="application"),
        rule("linux", {"s": {"a": "b"}, "condition": "s"}, product="linux", category=None, service="ftpd2"),
        rule("elsewhere", {"s": {"EventID": 1003}, "condition": "s"}, category=None, service="security"),
    ]
    body, digest = ndjson(rules)
    asked = {"name": name, "fileName": "Application.evtx", "rules": digest}

    status, answer = call(base, "POST", "/parse", asked)
    assert status == 409 and json.loads(answer)["missing"] == [] and json.loads(answer)["missingRules"] == digest
    assert call(base, "PUT", f"/rules/{digest}", raw=body, token="wrong")[0] == 401
    assert call(base, "PUT", f"/rules/{'0' * 64}", raw=body)[0] == 400, "a set that is not what its name says"
    status, answer = call(base, "PUT", f"/rules/{hashlib.sha256(b'x').hexdigest()}", raw=b"x")
    assert status == 400, "a set that is not NDJSON of rules"
    assert call(base, "POST", "/parse", {**asked, "rules": "nope"})[0] == 400
    status, answer = call(base, "PUT", f"/rules/{digest}", raw=body)
    assert status == 200 and json.loads(answer) == {"rules": 5}

    status, answer = call(base, "POST", "/parse", asked)
    found = events(answer)
    assert status == 200 and found[-1]["t"] == "end" and found[-1]["read"] == 17
    dets = [(index, event) for index, event in enumerate(found) if event["t"] == "det"]
    assert len(dets) == 2, [event for _i, event in dets]  # two records are 1003, only one is of that provider
    for index, det in dets:
        assert found[index - 1]["t"] in ("r", "det") and det["key"] in {e["key"] for e in found if e["t"] == "r"}
        previous = found[index - 1]
        assert previous["key"] == det["key"], "a detection follows the record it is about"
    assert sorted(det["rule"] for _i, det in dets) == sorted([rid("spp"), rid("winlogon")])
    (note,) = [event for event in found if event["t"] == "note" and event["reason"] == "rule not evaluated"]
    assert note["count"] == 2 and found.index(note) == len(found) - 2
    assert call(base, "GET", "/health")[0] == 200
    assert json.loads(call(base, "GET", "/health")[1])["sigma"] == "1"


def test_a_command_history_is_matched_by_the_rules_of_nik_and_a_lost_set_is_asked_for_again(worker, tmp_path):  # noqa: F811
    server, base = worker
    name = give(base, b"whoami\nmimikatz sekurlsa\n")
    rules = [
        rule(
            "m",
            {"s": {"command|contains": "mimikatz"}, "condition": "s"},
            product="nik",
            category=None,
            service="commands",
        )
    ]
    body, digest = ndjson(rules)
    assert call(base, "PUT", f"/rules/{digest}", raw=body)[0] == 200
    found = events(
        call(base, "POST", "/parse", {"name": name, "fileName": "ConsoleHost_history.txt", "rules": digest})[1]
    )
    assert [e["t"] for e in found] == ["source", "r", "r", "det", "note", "end"] or [e["t"] for e in found] == [
        "source",
        "r",
        "r",
        "det",
        "end",
    ]
    assert found[3]["rule"] == rid("m") and found[3]["key"] == found[2]["key"]
    # The file of the set is gone (a worker that was started again): the backend is asked to give it again.
    os.unlink(server.RULES.path(digest))
    status, answer = call(
        base, "POST", "/parse", {"name": name, "fileName": "ConsoleHost_history.txt", "rules": digest}
    )
    assert status == 409


def test_only_the_last_few_sets_are_kept(worker):  # noqa: F811
    server, base = worker
    digests = []
    for number in range(5):
        body, digest = ndjson([rule(f"r{number}", {"s": {"a": "b"}, "condition": "s"})])
        assert call(base, "PUT", f"/rules/{digest}", raw=body)[0] == 200
        digests.append(digest)
        os.utime(server.RULES.path(digest), (number, number))
    kept = sorted(name for name in os.listdir(server.RULES.folder) if name.endswith(".ndjson"))
    assert len(kept) == 3 and kept == sorted(f"{d}.ndjson" for d in digests[2:])


def test_the_off_hours_of_a_request_reach_the_rules(worker):  # noqa: F811
    _server, base = worker
    event = {
        "Id": 4624,
        "LogName": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "RecordId": 1,
        "MachineName": "WKS-1",
        "Level": 0,
        "TimeCreated": "2024-05-06T22:00:00.0000000Z",
        "Data": {"LogonType": "10", "TargetUserName": "alice"},
    }
    day = {**event, "RecordId": 2, "TimeCreated": "2024-05-06T09:00:00.0000000Z"}
    document = json.dumps({"format": "nik-eventlogs", "host": "WKS-1", "events": [event, day]}).encode()
    name = give(base, document)
    detection = {"s": {"EventID": 4624, "LogonType": "10", "NikOffHours": "true"}, "condition": "s"}
    body, digest = ndjson([rule("rdp", detection, category=None, service="security")])
    assert call(base, "PUT", f"/rules/{digest}", raw=body)[0] == 200
    hours = {"tz": "Europe/Rome", "days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"}
    asked = {"name": name, "fileName": "nik-eventlogs.json", "rules": digest, "params": {"hours": hours}}
    found = events(call(base, "POST", "/parse", asked)[1])
    dets = [event for event in found if event["t"] == "det"]
    records = {event["key"]: event for event in found if event["t"] == "r"}
    assert len(dets) == 1 and records[dets[0]["key"]]["ts"] == 1_715_032_800_000  # 22:00 UTC = midnight in Rome


def test_the_check_and_the_try_over_http(worker):  # noqa: F811
    _server, base = worker
    good = (
        "title: Mimikatz word\nid: 77777777-7777-4777-8777-777777777777\nlevel: high\nstatus: test\n"
        "logsource:\n  product: nik\n  service: commands\n"
        "detection:\n  k:\n    command|contains: mimikatz\n  condition: k\n"
    )
    status, answer = call(
        base, "POST", "/sigma/check", {"documents": [{"source": good}, {"source": "title: nothing\n"}]}
    )
    said = json.loads(answer)
    assert status == 200 and said["engine"] == "1"
    first, second = said["documents"]
    assert first["errors"] == [] and first["rules"][0]["supported"] is True and first["rules"][0]["line"] == 1
    assert second["rules"] == [] and second["errors"][0]["line"] >= 1
    assert call(base, "POST", "/sigma/check", {"documents": "no"})[0] == 400
    assert call(base, "POST", "/sigma/check", {"documents": []}, token="wrong")[0] == 401
    assert call(base, "POST", "/sigma/check", raw=b"{not json")[0] == 400

    rules = [
        json.loads(
            json.dumps(
                rule(
                    "m",
                    {"s": {"command|contains": "mimikatz"}, "condition": "s"},
                    product="nik",
                    category=None,
                    service="commands",
                )
            )
        ),
        rule("bad", {"s": {"x|re": "(?=a)b"}, "condition": "s"}, product="nik", category=None, service="commands"),
        correlation(
            "twice",
            {"type": "event_count", "rules": ["m"], "timespan": "1h", "generate": True, "condition": {"gte": 2}},
        ),
    ]
    command = {
        "kind": "commands",
        "channel": "",
        "event_id": None,
        "host": "H",
        "username": "u",
        "summary": "",
        "type": "command",
    }
    records = [
        {**command, "key": "c1", "ts": 1_700_000_000_000, "data": {"command": "Mimikatz"}},
        {**command, "key": "c2", "ts": 1_700_000_010_000, "data": {"command": "dir"}},
        {**command, "key": "c3", "ts": 1_700_000_020_000, "data": {"command": "mimikatz again"}},
    ]
    status, answer = call(base, "POST", "/sigma/try", {"rules": rules, "records": records})
    said = json.loads(answer)
    assert status == 200
    assert [(m["rule"], m["key"]) for m in said["matches"]] == [
        (rid("m"), "c1"),
        (rid("m"), "c3"),
        (rid("twice"), "c3"),
    ]
    assert said["matches"][2]["records"] == ["c1", "c3"] and said["matches"][2]["count"] == 2
    assert [item["rule"] for item in said["notEvaluated"]] == [rid("bad")] and "RE2" in said["notEvaluated"][0][
        "reason"
    ]
    assert call(base, "POST", "/sigma/try", {"rules": rules, "records": "no"})[0] == 400
    assert call(base, "POST", "/sigma/try", {"rules": [], "records": [{}] * 20001})[0] == 400


def test_a_hostile_rule_text_does_not_take_the_worker_down(worker):  # noqa: F811
    _server, base = worker
    bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
    previous = "a"
    for letter in "bcdefghijklmnop":
        bomb += f"{letter}: &{letter} [" + ", ".join([f"*{previous}"] * 10) + "]\n"
        previous = letter
    status, answer = call(base, "POST", "/sigma/check", {"documents": [{"source": bomb}, {"source": "[" * 5000}]})
    assert status == 200
    assert all(document["rules"] == [] and document["errors"] for document in json.loads(answer)["documents"])
    assert call(base, "GET", "/health")[0] == 200
