"""The Sigma engine: correlations, working hours, what the context writes, the text check.

Every rule and record is made here: harmless text, never evidence.
"""

from __future__ import annotations

import io
import json
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from nik_forensics.context import MAX_VALUE, Context
from nik_forensics.sigma import check
from nik_forensics.sigma.engine import Engine
from nik_forensics.sigma.hours import BadHours, Hours
from sigma_support import correlation, names, record, rid, rule

SEC = {"channel": "Security"}


def at(seconds: int) -> int:
    return 1_700_000_000_000 + seconds * 1000


def logon(user: str, when: int, ok: bool = False, ip: str = "10.0.0.1", key: str | None = None) -> tuple:
    """A failed (4625) or successful (4624) logon of ``user`` ``when`` seconds in."""
    name = "SubjectUserName" if ok else "TargetUserName"
    return record(
        {name: user, "IpAddress": ip},
        channel="Security",
        event_id=4624 if ok else 4625,
        key=key or f"{'ok' if ok else 'fail'}:{user}:{when}",
        ts=at(when),
    )


def base_rules() -> list[dict]:
    return [
        rule("fail", {"s": {"EventID": 4625}, "condition": "s"}, category=None, service="security"),
        rule("ok", {"s": {"EventID": 4624}, "condition": "s"}, category=None, service="security"),
    ]


def run(engine: Engine, records: list[tuple]) -> tuple[list[str], list[dict], list]:
    seen: list[str] = []
    for one in records:
        seen.extend(engine.see(*one))
    dets, notes = engine.finish()
    return seen, dets, notes


# --------------------------------------------------------------------------- #
# Correlations                                                                #
# --------------------------------------------------------------------------- #
def test_event_count_fires_once_per_episode_and_the_group_starts_again():
    corr = correlation(
        "brute",
        {
            "type": "event_count",
            "rules": ["fail"],
            "group-by": ["TargetUserName"],
            "timespan": "5m",
            "condition": {"gte": 3},
        },
    )
    engine = Engine([*base_rules(), corr])
    records = [logon("alice", n * 60) for n in range(6)] + [logon("bob", 10), logon("bob", 20)]
    seen, dets, _notes = run(engine, sorted(records, key=lambda r: r[3]))
    assert seen == [], "a base rule that feeds a correlation (generate false) writes no detection of its own"
    assert [(d["rule"], d["key"], d["count"]) for d in dets] == [
        (rid("brute"), "fail:alice:120", 3),
        (rid("brute"), "fail:alice:300", 3),
    ]
    assert dets[0]["records"] == ["fail:alice:0", "fail:alice:60", "fail:alice:120"] and dets[0]["t"] == "det"


def test_event_count_forgets_what_is_older_than_the_timespan():
    corr = correlation("brute", {"type": "event_count", "rules": ["fail"], "timespan": "5m", "condition": {"gte": 3}})
    _seen, dets, _notes = run(Engine([*base_rules(), corr]), [logon("a", 0), logon("a", 200), logon("a", 400)])
    assert dets == []
    _seen, dets, _notes = run(Engine([*base_rules(), corr]), [logon("a", 0), logon("b", 100), logon("a", 200)])
    assert len(dets) == 1, "without group-by the records of every user count together"


def test_generate_true_keeps_the_detections_of_the_base_rule_too():
    corr = correlation(
        "c", {"type": "event_count", "rules": ["fail"], "timespan": "5m", "generate": True, "condition": {"gte": 2}}
    )
    seen, dets, _notes = run(Engine([*base_rules(), corr]), [logon("a", 0), logon("a", 10)])
    assert seen == [rid("fail")] * 2 and len(dets) == 1


def test_value_count_counts_distinct_values():
    corr = correlation(
        "spray",
        {
            "type": "value_count",
            "rules": ["fail"],
            "group-by": ["TargetUserName"],
            "timespan": "10m",
            "condition": {"gte": 3, "field": "IpAddress"},
        },
    )
    same = [logon("alice", n * 10, ip="10.0.0.1") for n in range(5)]
    assert run(Engine([*base_rules(), corr]), same)[1] == []
    many = [logon("alice", n * 10, ip=f"10.0.0.{n % 3}", key=f"f{n}") for n in range(6)]
    _seen, dets, _notes = run(Engine([*base_rules(), corr]), many)
    assert [(d["key"], d["count"]) for d in dets] == [("f2", 3), ("f5", 3)]


def test_temporal_needs_every_base_rule_inside_the_timespan():
    corr = correlation(
        "fail-then-ok",
        {
            "type": "temporal",
            "rules": ["fail", "ok"],
            "group-by": ["user"],
            "timespan": "5m",
            "aliases": {"user": {"fail": "TargetUserName", "ok": "SubjectUserName"}},
            "condition": {"gte": 2},
        },
    )
    records = [logon("alice", 0), logon("bob", 10), logon("alice", 60, ok=True), logon("bob", 900, ok=True)]
    _seen, dets, _notes = run(Engine([*base_rules(), corr]), records)
    assert [(d["key"], d["records"]) for d in dets] == [("ok:alice:60", ["fail:alice:0", "ok:alice:60"])]


def test_temporal_ordered_wants_the_order_the_rules_are_named_in():
    corr = correlation(
        "ordered",
        {
            "type": "temporal_ordered",
            "rules": ["fail", "ok"],
            "group-by": ["user"],
            "timespan": "5m",
            "aliases": {"user": {"fail": "TargetUserName", "ok": "SubjectUserName"}},
            "condition": {"gte": 2},
        },
    )
    wrong = [logon("alice", 0, ok=True), logon("alice", 60)]
    assert run(Engine([*base_rules(), corr]), wrong)[1] == []
    right = [
        logon("alice", 0, ok=True),
        logon("alice", 60),
        logon("alice", 120, ok=True),
        logon("alice", 1000, ok=True),
    ]
    _seen, dets, _notes = run(Engine([*base_rules(), corr]), right)
    assert [(d["key"], d["records"]) for d in dets] == [("ok:alice:120", ["fail:alice:60", "ok:alice:120"])]
    slow = [logon("alice", 0), logon("alice", 400, ok=True)]
    assert run(Engine([*base_rules(), corr]), slow)[1] == []


def test_a_record_without_the_group_by_field_or_a_time_is_left_out_and_said():
    corr = correlation(
        "c",
        {
            "type": "event_count",
            "rules": ["fail"],
            "group-by": ["TargetUserName"],
            "timespan": "5m",
            "condition": {"gte": 1},
        },
    )
    engine = Engine([*base_rules(), corr])
    nobody = record({"IpAddress": "1.1.1.1"}, channel="Security", event_id=4625, key="x", ts=at(0))
    untimed = record({"TargetUserName": "a"}, channel="Security", event_id=4625, key="y", ts=None)
    _seen, dets, notes = run(engine, [nobody, untimed])
    assert dets == [] and ("records without a time left out of correlations", 1, "") in notes


def test_what_a_correlation_cannot_run_is_listed_with_the_reason():
    value_sum = correlation(
        "sum", {"type": "value_sum", "rules": ["fail"], "timespan": "5m", "condition": {"gte": 3, "field": "Bytes"}}
    )
    lonely = correlation(
        "lonely", {"type": "event_count", "rules": ["not-here"], "timespan": "5m", "condition": {"gte": 2}}
    )
    engine = Engine([*base_rules(), value_sum, lonely])
    engine.compile_all()
    reasons = dict(engine.not_evaluated())
    assert "value_sum" in reasons[rid("sum")] and "not-here" in reasons[rid("lonely")]
    _seen, _dets, notes = run(engine, [logon("a", 0)])
    assert [n for n in notes if n[0] == "rule not evaluated"][0][1] == 2


def test_a_base_rule_that_is_not_evaluated_stops_its_correlation_and_says_so():
    bad = rule("fail", {"s": {"CommandLine|re": "(?=x)y"}, "condition": "s"}, category=None, service="security")
    corr = correlation("c", {"type": "event_count", "rules": ["fail"], "timespan": "5m", "condition": {"gte": 1}})
    _seen, dets, notes = run(Engine([bad, corr]), [logon("a", 0)])
    assert dets == [] and [n for n in notes if n[0] == "rule not evaluated"][0][1] == 2


# --------------------------------------------------------------------------- #
# Working hours                                                               #
# --------------------------------------------------------------------------- #
def utc(text: str) -> int:
    return int(datetime.fromisoformat(text).replace(tzinfo=ZoneInfo("UTC")).timestamp() * 1000)


def test_off_hours_follow_the_time_zone_and_the_working_days():
    hours = Hours({"tz": "Europe/Rome", "days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"})
    assert not hours.off(utc("2024-05-06T07:30:00"))  # Monday 09:30 in Rome (UTC+2)
    assert hours.off(utc("2024-05-06T05:30:00"))  # Monday 07:30 in Rome
    assert hours.off(utc("2024-05-06T16:00:00"))  # Monday 18:00 in Rome: the end is not working time
    assert hours.off(utc("2024-05-04T10:00:00"))  # Saturday
    assert not hours.off(utc("2024-01-15T07:30:00"))  # Monday 08:30 in winter (UTC+1)
    utc_hours = Hours({"tz": "UTC", "days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"})
    assert utc_hours.off(utc("2024-05-06T07:30:00")), "the same instant is off hours when read in another zone"


def test_a_night_that_crosses_midnight_belongs_to_the_day_it_began_on():
    night = Hours({"tz": "UTC", "days": [1, 2, 3, 4, 5], "start": "22:00", "end": "06:00"})
    assert not night.off(utc("2024-05-06T23:00:00"))  # Monday evening
    assert not night.off(utc("2024-05-07T03:00:00"))  # Tuesday morning: Monday's night
    assert not night.off(utc("2024-05-11T03:00:00"))  # Saturday morning: Friday's night
    assert night.off(utc("2024-05-12T03:00:00"))  # Sunday morning: Saturday's night, not a working day
    assert night.off(utc("2024-05-11T23:00:00"))  # Saturday evening
    assert night.off(utc("2024-05-06T12:00:00"))  # Monday noon
    assert night.off(utc("2024-05-06T03:00:00")), "Monday morning is Sunday's night"


def test_bad_hours_are_said():
    for spec in ({"tz": "Nowhere/Land", "days": [1]}, {"days": [8]}, {"days": [1], "start": "late"}, "x"):
        with pytest.raises(BadHours):
            Hours(spec)  # type: ignore[arg-type]
    _seen, _dets, notes = run(Engine([], {"tz": "Nowhere/Land", "days": [1]}), [])
    assert notes[0][0] == "working hours not understood"


def test_a_rule_reads_the_off_hours_field():
    detection = {"s": {"EventID": 4624, "LogonType": "10", "NikOffHours": "true"}, "condition": "s"}
    rdp = rule("rdp-off-hours", detection, category=None, service="security")
    hours = {"tz": "Europe/Rome", "days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"}
    engine = Engine([rdp], hours)
    data = {"LogonType": "10"}
    night = record(data, channel="Security", event_id=4624, ts=utc("2024-05-06T22:00:00"))
    day = record(data, channel="Security", event_id=4624, ts=utc("2024-05-06T09:00:00"))
    untimed = record(data, channel="Security", event_id=4624, ts=None)
    assert engine.see(*night) == [rid("rdp-off-hours")]
    assert engine.see(*day) == [] and engine.see(*untimed) == []
    assert Engine([rdp]).see(*night) == [], "without hours the field does not exist"


# --------------------------------------------------------------------------- #
# What the context writes                                                     #
# --------------------------------------------------------------------------- #
def lines(out: io.BytesIO) -> list[dict]:
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def test_the_detection_comes_after_its_record_and_sees_the_whole_value():
    out = io.BytesIO()
    ctx = Context(out)
    ctx.detector = Engine(
        [rule("tail", {"s": {"ScriptBlockText|contains": "tail-marker"}, "condition": "s"}, category="ps_script")]
    )
    ctx.source("evtx", "1", "eventlog", "evtx", host="WKS")
    text = "A" * (MAX_VALUE + 1000) + "tail-marker"
    ctx.record(
        key="evtx:WKS:ps:1",
        type="event",
        ts=at(0),
        event_id=4104,
        channel="Microsoft-Windows-PowerShell/Operational",
        data={"ScriptBlockText": text},
    )
    ctx.record(
        key="evtx:WKS:ps:2",
        type="event",
        ts=at(1),
        event_id=4104,
        channel="Microsoft-Windows-PowerShell/Operational",
        data={"ScriptBlockText": "short"},
    )
    ctx.end()
    found = lines(out)
    assert [event["t"] for event in found] == ["source", "r", "det", "r", "end"]
    assert found[1]["trunc"] is True and "tail-marker" not in found[1]["data"]["ScriptBlockText"]
    assert found[2] == {"t": "det", "key": "evtx:WKS:ps:1", "rule": rid("tail")}


def test_correlations_and_the_note_about_rules_come_before_the_end():
    out = io.BytesIO()
    ctx = Context(out)
    corr = correlation("c", {"type": "event_count", "rules": ["fail"], "timespan": "5m", "condition": {"gte": 2}})
    broken = rule("broken", {"s": {"CommandLine|re": "(?=x)y"}, "condition": "s"}, category=None, service="security")
    ctx.detector = Engine([*base_rules(), corr, broken])
    ctx.source("evtx", "1", "eventlog", "evtx")
    for when in (0, 30):
        ctx.record(
            key=f"k{when}", type="event", ts=at(when), event_id=4625, channel="Security", data={"TargetUserName": "a"}
        )
    ctx.end()
    found = lines(out)
    assert [event["t"] for event in found] == ["source", "r", "r", "det", "note", "end"]
    assert found[3] == {"t": "det", "key": "k30", "rule": rid("c"), "records": ["k0", "k30"], "count": 2}
    assert found[4]["reason"] == "rule not evaluated" and found[4]["count"] == 1 and rid("broken") in found[4]["detail"]


# --------------------------------------------------------------------------- #
# The check of a text                                                         #
# --------------------------------------------------------------------------- #
GOOD = """title: Whoami run
id: 11111111-1111-4111-8111-111111111111
name: whoami
status: stable
level: high
author: A. Analyst
tags: [attack.discovery, attack.t1033]
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\whoami.exe'
  condition: selection
"""


def test_a_text_with_several_documents_is_split_and_each_rule_has_its_line():
    second = GOOD.replace("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222").replace(
        "Whoami run", "Net user"
    )
    answer = check.check([{"source": f"# a comment\n{GOOD}---\n\n{second}"}])
    assert answer["engine"] == "1"
    (document,) = answer["documents"]
    assert document["errors"] == []
    first, other = document["rules"]
    assert (first["line"], other["line"]) == (1, 18)
    assert first["source"] == "# a comment\n" + GOOD and other["source"].startswith("title: Net user")
    assert first["kind"] == "rule" and first["level"] == 4 and first["status"] == "stable" and first["name"] == "whoami"
    assert first["tags"] == ["attack.discovery", "attack.t1033"] and first["author"] == "A. Analyst"
    assert (first["product"], first["category"], first["service"]) == ("windows", "process_creation", "")
    assert first["supported"] is True and first["reason"] == ""


def test_errors_are_placed_on_the_line_of_their_key_in_the_whole_text():
    broken = GOOD.replace("Image|endswith", "Image|startswtih").replace("111111111111", "333333333333")
    bad_condition = GOOD.replace("condition: selection", "condition: selection and and").replace(
        "111111111111", "444444444444"
    )
    first = GOOD.replace("11111111-1111-4111-8111-111111111111", "55555555-5555-4555-8555-555555555555")
    text = f"{first}---\n{broken}---\n{bad_condition}"
    (document,) = check.check([{"source": text}])["documents"]
    assert len(document["rules"]) == 1
    by_line = {error["line"]: error["message"] for error in document["errors"]}
    rows = text.splitlines()
    modifier = rows.index("    Image|startswtih: '\\whoami.exe'") + 1
    assert "Unknown modifier 'startswtih'" in by_line[modifier]
    condition = rows.index("  condition: selection and and") + 1
    assert condition in by_line and "and" in by_line[condition]
    assert all(error["column"] >= 1 for error in document["errors"])


def test_a_rule_without_an_id_is_an_error_and_a_yaml_syntax_error_has_its_line():
    no_id = "\n".join(line for line in GOOD.splitlines() if not line.startswith("id:")) + "\n"
    (document,) = check.check([{"source": no_id}])["documents"]
    assert document["rules"] == [] and [e["message"] for e in document["errors"]] == ["a rule needs an id (a UUID)"]
    (document,) = check.check([{"source": "title: x\n---\nkey: [unclosed\n"}])["documents"]
    assert document["rules"] == [] and any(error["line"] >= 3 for error in document["errors"])
    (document,) = check.check([{"source": "   \n# nothing\n"}])["documents"]
    assert document["errors"][0]["message"] == "the text holds no rule"
    (document,) = check.check([{"source": GOOD + "---\n" + GOOD}])["documents"]
    assert len(document["rules"]) == 1 and "already used" in document["errors"][0]["message"]
    duplicate = GOOD.replace("level: high\n", "level: high\nlevel: low\n")
    assert "written twice" in check.check([{"source": duplicate}])["documents"][0]["errors"][0]["message"]


def test_a_rule_nik_cannot_run_is_listed_with_its_reason_not_as_an_error():
    def only(extra: str, replace: tuple[str, str] | None = None) -> dict:
        text = GOOD if replace is None else GOOD.replace(*replace)
        (document,) = check.check([{"source": text + extra}])["documents"]
        assert document["errors"] == [], document["errors"]
        return document["rules"][0]

    linux = only(
        "", ("category: process_creation\n  product: windows", "product: linux\n  category: network_connection")
    )
    assert linux["supported"] is False
    assert linux["reason"] == "Nik reads no records of this log source: linux/network_connection"
    regex = GOOD.replace("Image|endswith: '\\whoami.exe'", "Image|re: '(?=a)b'")
    (document,) = check.check([{"source": regex}])["documents"]
    assert (
        document["errors"] == []
        and document["rules"][0]["supported"] is False
        and "RE2" in document["rules"][0]["reason"]
    )
    hour = GOOD.replace("Image|endswith: '\\whoami.exe'", "Time|hour: 3")
    (document,) = check.check([{"source": hour}])["documents"]
    assert document["rules"][0]["supported"] is False and "timestamp" in document["rules"][0]["reason"]


def test_a_correlation_is_checked_too():
    text = (
        "title: Many\nid: 66666666-6666-4666-8666-666666666666\ncorrelation:\n  type: value_sum\n  rules: [x]\n"
        "  timespan: 5m\n  condition:\n    gte: 3\n    field: Bytes\n"
    )
    (document,) = check.check([{"source": text}])["documents"]
    (info,) = document["rules"]
    assert info["kind"] == "correlation" and info["supported"] is False and "value_sum" in info["reason"]
    ok = text.replace("value_sum", "event_count")
    assert check.check([{"source": ok}])["documents"][0]["rules"][0]["supported"] is True


def test_collection_actions_are_errors_not_silently_skipped():
    (document,) = check.check([{"source": "action: global\ntitle: shared\n---\n" + GOOD}])["documents"]
    assert "global" in document["errors"][0]["message"] and document["errors"][0]["line"] == 1


def test_an_alias_bomb_is_refused_not_expanded():
    bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
    previous = "a"
    for letter in "bcdefghij":
        bomb += f"{letter}: &{letter} [" + ", ".join([f"*{previous}"] * 10) + "]\n"
        previous = letter
    (document,) = check.check([{"source": bomb}])["documents"]
    assert document["rules"] == [] and "too large" in document["errors"][0]["message"]


def test_names_helper_is_used():
    assert names(Engine([]), {}) == set()


# --------------------------------------------------------------------------- #
# A correlation built on correlations (one level)                             #
# --------------------------------------------------------------------------- #
def success(user: str, when: int, key: str) -> tuple:
    """A successful logon as the Security log says it: the account is the TargetUserName."""
    return record({"TargetUserName": user}, channel="Security", event_id=4624, key=key, ts=at(when))


def inner_corr(generate: bool = False, group_by: list[str] | None = None) -> dict:
    body = {"type": "event_count", "rules": ["fail"], "timespan": "30m", "generate": generate, "condition": {"gte": 3}}
    if group_by is not None:
        body["group-by"] = group_by
    return correlation("many-fails", body)


def outer_corr(group_by: list[str] | None = ("TargetUserName",), generate: bool = False, **more) -> dict:
    body = {
        "type": "temporal_ordered",
        "rules": ["many-fails", "ok"],
        "timespan": "30m",
        "generate": generate,
        "condition": {"gte": 2},
        **more,
    }
    if group_by:
        body["group-by"] = list(group_by)
    return correlation("fails-then-ok", body)


def test_a_correlation_may_be_built_on_another_and_the_group_is_mapped_by_name():
    engine = Engine([*base_rules(), inner_corr(group_by=["TargetUserName"]), outer_corr()])
    ok_alice = record({"TargetUserName": "alice"}, channel="Security", event_id=4624, key="ok-alice", ts=at(400))
    ok_bob = record({"TargetUserName": "bob"}, channel="Security", event_id=4624, key="ok-bob", ts=at(500))
    fails = [logon("alice", n * 60) for n in range(3)] + [logon("bob", 30)]
    seen, dets, _notes = run(engine, sorted([*fails, ok_alice, ok_bob], key=lambda r: r[3]))
    assert seen == [], "neither the base rules nor the inner correlation write anything while the outer one works"
    assert [(d["rule"], d["key"]) for d in dets] == [(rid("fails-then-ok"), "ok-alice")]
    assert dets[0]["records"] == ["fail:alice:0", "fail:alice:60", "fail:alice:120", "ok-alice"]


def test_the_inner_correlation_writes_its_own_detections_when_it_says_generate_or_stands_alone():
    fails = [logon("alice", n * 60) for n in range(3)]
    _seen, dets, _notes = run(Engine([*base_rules(), inner_corr(group_by=["TargetUserName"]), outer_corr()]), fails)
    assert dets == [], "the generate of the outer correlation decides whether the alerts of the inner one are written"
    _seen, dets, _notes = run(Engine([*base_rules(), inner_corr(group_by=["TargetUserName"])]), fails)
    assert [d["rule"] for d in dets] == [rid("many-fails")]
    ok = record({"TargetUserName": "alice"}, channel="Security", event_id=4624, key="ok", ts=at(300))
    _seen, dets, _notes = run(
        Engine([*base_rules(), inner_corr(group_by=["TargetUserName"]), outer_corr(generate=True)]), [*fails, ok]
    )
    assert sorted(d["rule"] for d in dets) == sorted([rid("many-fails"), rid("fails-then-ok")])


def test_an_alias_maps_the_outer_group_onto_a_field_the_inner_one_groups_by():
    outer = outer_corr(group_by=["user"], aliases={"user": {"many-fails": "TargetUserName", "ok": "SubjectUserName"}})
    engine = Engine([*base_rules(), inner_corr(group_by=["TargetUserName"]), outer])
    ok = logon("alice", 300, ok=True, key="ok-alice")
    _seen, dets, _notes = run(engine, [*[logon("alice", n * 60) for n in range(3)], ok])
    assert [d["key"] for d in dets] == ["ok-alice"]


def test_the_records_of_a_correlation_on_correlations_are_capped_at_fifty():
    body = {
        "type": "event_count",
        "rules": ["fail"],
        "timespan": "30m",
        "condition": {"gte": 40},
        "group-by": ["TargetUserName"],
    }
    engine = Engine([*base_rules(), correlation("many-fails", body), outer_corr()])
    fails = [logon("alice", n, key=f"f{n}") for n in range(40)]
    _seen, dets, _notes = run(engine, [*fails, success("alice", 100, "ok-alice")])
    assert len(dets) == 1 and len(dets[0]["records"]) == 41 and dets[0]["records"][-1] == "ok-alice"
    engine = Engine([*base_rules(), correlation("many-fails", {**body, "condition": {"gte": 60}}), outer_corr()])
    fails = [logon("alice", n, key=f"f{n}") for n in range(60)]
    _seen, dets, _notes = run(engine, [*fails, success("alice", 100, "ok-alice")])
    assert len(dets[0]["records"]) == 50 and dets[0]["records"][-1] == "ok-alice"


def test_what_a_nested_correlation_cannot_run_is_listed_with_the_reason():
    def why(rules: list[dict]) -> dict:
        engine = Engine(rules)
        engine.compile_all()
        return dict(engine.not_evaluated())

    # a group-by field of the outer one the inner one does not group by (and an inner one without a group-by)
    reasons = why([*base_rules(), inner_corr(group_by=["IpAddress"]), outer_corr()])
    assert "targetusername" in reasons[rid("fails-then-ok")]
    assert "not one of the group-by fields" in reasons[rid("fails-then-ok")]
    assert rid("fails-then-ok") in why([*base_rules(), inner_corr(), outer_corr()])
    assert why([*base_rules(), inner_corr(), outer_corr(group_by=None)]) == {}
    # two levels of correlations
    top = correlation(
        "top", {"type": "event_count", "rules": ["fails-then-ok"], "timespan": "1h", "condition": {"gte": 2}}
    )
    reasons = why([*base_rules(), inner_corr(group_by=["TargetUserName"]), outer_corr(), top])
    assert "one level" in reasons[rid("top")] and rid("fails-then-ok") not in reasons
    # an inner correlation that cannot run
    broken = correlation(
        "many-fails", {"type": "value_sum", "rules": ["fail"], "timespan": "5m", "condition": {"gte": 3, "field": "x"}}
    )
    reasons = why([*base_rules(), broken, outer_corr()])
    assert "not evaluated" in reasons[rid("fails-then-ok")] or "value_sum" in reasons[rid("fails-then-ok")]


def test_a_text_that_names_a_correlation_as_base_is_supported_by_check():
    text = (
        "title: Outer\nid: 88888888-8888-4888-8888-888888888888\ncorrelation:\n"
        "  type: event_count\n  rules: [inner-one]\n"
        "  timespan: 5m\n  condition:\n    gte: 2\n"
    )
    (info,) = check.check([{"source": text}])["documents"][0]["rules"]
    assert info["kind"] == "correlation" and info["supported"] is True


def test_a_linux_rule_is_supported_and_a_macos_process_rule_says_why_not():
    def info(logsource: str) -> dict:
        text = GOOD.replace(
            "logsource:\n  category: process_creation\n  product: windows", f"logsource:\n  {logsource}"
        )
        (document,) = check.check([{"source": text}])["documents"]
        assert document["errors"] == [], document["errors"]
        return document["rules"][0]

    assert info("product: linux\n  service: auditd")["supported"] is True
    assert info("product: linux\n  category: process_creation")["supported"] is True
    assert info("product: macos")["supported"] is True
    mac = info("product: macos\n  category: process_creation")
    assert (
        mac["supported"] is False and mac["reason"] == "Nik reads no records of this log source: macos/process_creation"
    )


# --------------------------------------------------------------------------- #
# The process-chain log source                                                #
# --------------------------------------------------------------------------- #
def chain(name: str, detection: dict, **more) -> dict:
    return rule(name, detection, product="nik", category=None, service="process-chain", **more)


def process(**fields) -> tuple:
    """One record of the process-chain log source, as the API makes it: the fields of the process by their names."""
    data = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami", "Host": "WKS-1", "User": "alice"}
    data.update(fields)
    return record(data, channel="", event_id=None, kind="process-chain", rtype="process", source="", host="WKS-1")


def test_a_process_chain_rule_reads_the_fields_of_the_process():
    engine = Engine(
        [
            chain(
                "office-shell",
                {
                    "child": {"Image|endswith": "\\cmd.exe"},
                    "parent": {"ParentImage|endswith": "\\winword.exe"},
                    "condition": "child and parent",
                },
            ),
            chain("deep", {"s": {"Depth|gte": 3}, "condition": "s"}),
            chain("system", {"s": {"IntegrityLevel": "System", "Platform": "windows"}, "condition": "s"}),
        ]
    )
    by_id = {slot.rid: slot.line["title"] for slot in engine.slots}

    def hits(**fields):
        return {by_id[found] for found in engine.see(*process(**fields))}

    assert hits() == set()
    assert hits(ParentImage="C:\\Program Files\\winword.exe", Depth=3) == {"office-shell", "deep"}
    assert hits(IntegrityLevel="system", Platform="windows") == {"system"}
    # the fields that are not given are not a match for a rule that needs them
    assert hits(Image="C:\\x.exe") == set()


def test_ancestors_is_a_list_and_contains_matches_any_element():
    engine = Engine(
        [
            chain("anc", {"s": {"Ancestors|contains": "winword"}, "condition": "s"}),
            chain("none", {"s": {"Ancestors|contains": "excel"}, "condition": "s"}),
            chain("grand", {"s": {"GrandParentImage|endswith": "\\explorer.exe"}, "condition": "s"}),
        ]
    )
    by_id = {slot.rid: slot.line["title"] for slot in engine.slots}
    found = engine.see(
        *process(
            Ancestors=[
                "C:\\x\\EXCELish.txt".replace("EXCELish.txt", "powershell.exe"),
                "C:\\Office\\WINWORD.EXE",
                "C:\\Windows\\explorer.exe",
            ],
            GrandParentImage="C:\\Windows\\explorer.exe",
        )
    )
    assert {by_id[rule_id] for rule_id in found} == {"anc", "grand"}
    assert engine.see(*process(Ancestors=[])) == []


def test_the_host_and_the_user_of_a_process_record_are_the_fields_it_was_given():
    engine = Engine([chain("who", {"s": {"Host": "wks-1", "User": "alice", "Summary": ""}, "condition": "s"})])
    assert engine.see(*process()) == [engine.slots[0].rid]
    other = record(
        {"Image": "x"}, channel="", event_id=None, kind="process-chain", rtype="process", host="OTHER", username="bob"
    )
    assert engine.see(*other) == []
    # the arguments fill in what the fields lack
    engine = Engine([chain("arg", {"s": {"Host": "other", "User": "bob"}, "condition": "s"})])
    assert engine.see(*other) == [engine.slots[0].rid]
