"""The Sigma compiler: every modifier, the condition forms, the log source dispatch, the fields of a record.

Every rule and record is made here: harmless text, never evidence.
"""

from __future__ import annotations

import base64

import pytest
from sigma_support import SYSMON, names, one, record, rule

from nik_forensics.sigma import logsource
from nik_forensics.sigma.engine import Engine

# --------------------------------------------------------------------------- #
# Modifiers                                                                   #
# --------------------------------------------------------------------------- #
CASES = [
    # (detection, data, matches)
    (
        {"s": {"CommandLine|contains": "invoke-expression"}, "condition": "s"},
        {"CommandLine": "x Invoke-Expression y"},
        True,
    ),
    ({"s": {"CommandLine|contains": "invoke-expression"}, "condition": "s"}, {"CommandLine": "nothing"}, False),
    ({"s": {"Image|startswith": "c:\\windows"}, "condition": "s"}, {"Image": "C:\\Windows\\cmd.exe"}, True),
    ({"s": {"Image|startswith": "c:\\windows"}, "condition": "s"}, {"Image": "D:\\C:\\Windows"}, False),
    ({"s": {"Image|endswith": "\\cmd.exe"}, "condition": "s"}, {"Image": "C:\\Windows\\CMD.EXE"}, True),
    ({"s": {"Image|endswith": "\\cmd.exe"}, "condition": "s"}, {"Image": "C:\\cmd.exe.txt"}, False),
    (
        {"s": {"CommandLine|contains|all": ["-enc", "hidden"]}, "condition": "s"},
        {"CommandLine": "ps -Enc x -hidden"},
        True,
    ),
    ({"s": {"CommandLine|contains|all": ["-enc", "hidden"]}, "condition": "s"}, {"CommandLine": "ps -Enc x"}, False),
    ({"s": {"CommandLine|contains": ["-enc", "hidden"]}, "condition": "s"}, {"CommandLine": "ps -hidden"}, True),
    ({"s": {"CommandLine|re": "a[0-9]+b"}, "condition": "s"}, {"CommandLine": "xa123by"}, True),
    ({"s": {"CommandLine|re": "a[0-9]+b"}, "condition": "s"}, {"CommandLine": "xab"}, False),
    ({"s": {"CommandLine|re": "^A[0-9]+B$"}, "condition": "s"}, {"CommandLine": "a1b"}, False),  # case-sensitive
    ({"s": {"CommandLine|re|i": "^A[0-9]+B$"}, "condition": "s"}, {"CommandLine": "a1b"}, True),
    # the expression is read as written: backslashes, an escaped star, a dot, a wildcard-looking character
    ({"s": {"CommandLine|re": r"\d+\.\d+\\x"}, "condition": "s"}, {"CommandLine": r"v12.3\x"}, True),
    ({"s": {"CommandLine|re": r"\d+\.\d+\\x"}, "condition": "s"}, {"CommandLine": r"v12x3\x"}, False),
    ({"s": {"CommandLine|re": r"a\*b"}, "condition": "s"}, {"CommandLine": "a*b"}, True),
    ({"s": {"CommandLine|re": r"a\*b"}, "condition": "s"}, {"CommandLine": "aab"}, False),
    ({"s": {"CommandLine|re": r"a.*b?c"}, "condition": "s"}, {"CommandLine": "a---c"}, True),
    ({"s": {"CommandLine|re|m": "^b$"}, "condition": "s"}, {"CommandLine": "a\nb\nc"}, True),
    ({"s": {"CommandLine|re": "a.b"}, "condition": "s"}, {"CommandLine": "a\nb"}, False),
    ({"s": {"CommandLine|re|s": "a.b"}, "condition": "s"}, {"CommandLine": "a\nb"}, True),
    ({"s": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "s"}, {"DestinationIp": "10.1.2.3"}, True),
    ({"s": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "s"}, {"DestinationIp": "11.1.2.3"}, False),
    ({"s": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "s"}, {"DestinationIp": "not an address"}, False),
    (
        {"s": {"CommandLine|base64|contains": "hello"}, "condition": "s"},
        {"CommandLine": "x" + base64.b64encode(b"hello").decode()},
        True,
    ),
    (
        {"s": {"CommandLine|base64offset|contains": "hello"}, "condition": "s"},
        {"CommandLine": "q" + base64.b64encode(b"?hello").decode()},
        True,
    ),
    (
        {"s": {"CommandLine|base64offset|contains": "hello"}, "condition": "s"},
        {"CommandLine": "nothing like it"},
        False,
    ),
    ({"s": {"CommandLine|windash|contains": "-enc"}, "condition": "s"}, {"CommandLine": "powershell /enc abc"}, True),
    (
        {"s": {"CommandLine|windash|contains": "-enc"}, "condition": "s"},
        {"CommandLine": "powershell \u2013enc abc"},
        True,
    ),
    ({"s": {"CommandLine|windash|contains": "-enc"}, "condition": "s"}, {"CommandLine": "powershell enc abc"}, False),
    ({"s": {"CommandLine|cased|contains": "Invoke"}, "condition": "s"}, {"CommandLine": "x Invoke y"}, True),
    ({"s": {"CommandLine|cased|contains": "Invoke"}, "condition": "s"}, {"CommandLine": "x invoke y"}, False),
    ({"s": {"Foo|exists": True}, "condition": "s"}, {"Foo": "x"}, True),
    ({"s": {"Foo|exists": True}, "condition": "s"}, {"Bar": "x"}, False),
    ({"s": {"Foo|exists": False}, "condition": "s"}, {"Bar": "x"}, True),
    ({"s": {"Foo|exists": False}, "condition": "s"}, {"Foo": "x"}, False),
    ({"s": {"Image|fieldref": "ParentImage"}, "condition": "s"}, {"Image": "A.EXE", "ParentImage": "a.exe"}, True),
    ({"s": {"Image|fieldref": "ParentImage"}, "condition": "s"}, {"Image": "A.EXE", "ParentImage": "b.exe"}, False),
    ({"s": {"Image|fieldref": "ParentImage"}, "condition": "s"}, {"Image": "A.EXE"}, False),
    ({"s": {"Port|lt": 1024}, "condition": "s"}, {"Port": "80"}, True),
    ({"s": {"Port|lt": 1024}, "condition": "s"}, {"Port": 1024}, False),
    ({"s": {"Port|lte": 1024}, "condition": "s"}, {"Port": 1024}, True),
    ({"s": {"Port|gt": 1024}, "condition": "s"}, {"Port": "1025"}, True),
    ({"s": {"Port|gt": 1024}, "condition": "s"}, {"Port": "text"}, False),
    ({"s": {"Port|gte": 1024}, "condition": "s"}, {"Port": 1024}, True),
    ({"s": {"Port": 443}, "condition": "s"}, {"Port": "443"}, True),
    ({"s": {"Image|endswith": ["\\a.exe", "\\b.exe", "\\c.exe"]}, "condition": "s"}, {"Image": "C:\\x\\B.exe"}, True),
    ({"s": {"Image": ["c:\\a.exe", "c:\\b.exe"]}, "condition": "s"}, {"Image": "C:\\B.EXE"}, True),
    ({"s": {"Image": ["c:\\a.exe", "c:\\b.exe"]}, "condition": "s"}, {"Image": "C:\\c.exe"}, False),
    # in Sigma a backslash before a wildcard escapes it: a path separator before one is written twice
    ({"s": {"Image": "c:\\\\*\\\\cmd.exe"}, "condition": "s"}, {"Image": "C:\\Windows\\System32\\cmd.exe"}, True),
    ({"s": {"Image": "c:\\\\?.exe"}, "condition": "s"}, {"Image": "c:\\a.exe"}, True),
    ({"s": {"Image": "c:\\\\?.exe"}, "condition": "s"}, {"Image": "c:\\ab.exe"}, False),
    ({"s": {"Image": "c:\\\\\\*.exe"}, "condition": "s"}, {"Image": "c:\\*.exe"}, True),
    ({"s": {"Image": "c:\\\\\\*.exe"}, "condition": "s"}, {"Image": "c:\\a.exe"}, False),
    ({"s": {"Image": "*"}, "condition": "s"}, {"Other": "x"}, False),  # a missing field never matches *
    ({"s": {"Image": "*"}, "condition": "s"}, {"Image": ""}, True),
    ({"s": {"Foo": None}, "condition": "s"}, {"Bar": "x"}, True),  # null: missing…
    ({"s": {"Foo": None}, "condition": "s"}, {"Foo": ""}, True),  # …or empty
    ({"s": {"Foo": None}, "condition": "s"}, {"Foo": "x"}, False),
    ({"s": {"Flag": True}, "condition": "s"}, {"Flag": True}, True),
    ({"s": {"Flag": True}, "condition": "s"}, {"Flag": "false"}, False),
    (
        {"s": {"Image|endswith": "\\x.exe", "User": "alice"}, "condition": "s"},
        {"Image": "c:\\X.EXE", "User": "ALICE"},
        True,
    ),
    (
        {"s": {"Image|endswith": "\\x.exe", "User": "alice"}, "condition": "s"},
        {"Image": "c:\\X.EXE", "User": "bob"},
        False,
    ),
]


@pytest.mark.parametrize(("detection", "data", "expected"), CASES, ids=[f"{n}" for n in range(len(CASES))])
def test_a_modifier_matches_what_sigma_says(detection, data, expected):
    assert one(detection, data) is expected


def test_the_conditions_with_selectors_not_and_wildcards():
    detection = {
        "selection_a": {"Image|endswith": "\\a.exe"},
        "selection_b": {"CommandLine|contains": "boom"},
        "filter": {"User": "system"},
        "condition": "1 of selection_* and not filter",
    }
    assert one(detection, {"Image": "x\\a.exe", "User": "alice"})
    assert one(detection, {"CommandLine": "BOOM", "User": "alice"})
    assert not one(detection, {"Image": "x\\a.exe", "User": "SYSTEM"})
    assert not one(detection, {"User": "alice"})
    detection["condition"] = "all of selection_*"
    assert one(detection, {"Image": "x\\a.exe", "CommandLine": "a boom"})
    assert not one(detection, {"Image": "x\\a.exe"})
    detection["condition"] = "selection_a and not selection_b or filter"
    assert one(detection, {"Image": "x\\a.exe"}) and one(detection, {"User": "system"})
    assert not one(detection, {"Image": "x\\a.exe", "CommandLine": "boom"})
    detection["condition"] = "1 of them"
    assert one(detection, {"User": "system"})


def test_keywords_are_searched_in_all_the_values_of_the_record():
    detection = {"keywords": ["mimikatz", "sekurlsa::*"], "condition": "keywords"}
    assert one(detection, {"CommandLine": "run MimiKatz now"})
    assert one(detection, {"Other": "x", "Script": "privilege::debug sekurlsa::logonpasswords"})
    assert not one(detection, {"CommandLine": "notepad"})
    # a field missing from the record cannot hold the keyword
    assert not one({"keywords": ["mimikatz"], "condition": "keywords"}, {})


def test_a_rule_with_two_conditions_matches_on_either():
    detection = {"a": {"Image|endswith": "\\a.exe"}, "b": {"Image|endswith": "\\b.exe"}, "condition": ["a", "b"]}
    assert one(detection, {"Image": "c:\\b.exe"}) and one(detection, {"Image": "c:\\a.exe"})
    assert not one(detection, {"Image": "c:\\c.exe"})


def test_the_value_may_be_a_list_in_the_record():
    detection = {"s": {"Groups|contains": "admin"}, "condition": "s"}
    assert one(detection, {"Groups": ["users", "Domain Admins"]})
    assert not one(detection, {"Groups": ["users"]})


@pytest.mark.parametrize(
    ("detection", "reason"),
    [
        ({"s": {"CommandLine|re": "(?=x)y"}, "condition": "s"}, "RE2"),
        ({"s": {"CommandLine|re": "(a)\\1"}, "condition": "s"}, "RE2"),
        ({"s": {"Time|hour": 3}, "condition": "s"}, "timestamp"),
    ],
)
def test_what_nik_cannot_run_is_unsupported_with_the_reason(detection, reason):
    engine = Engine([rule("r", detection)])
    engine.compile_all()
    ((rid, why),) = engine.not_evaluated()
    assert rid and reason in why


def test_a_rule_that_does_not_compile_does_not_stop_the_others():
    engine = Engine(
        [
            rule("bad", {"s": {"CommandLine|re": "(?=x)y"}, "condition": "s"}),
            rule("good", {"s": {"A": "b"}, "condition": "s"}),
        ]
    )
    assert names(engine, {"A": "b"}) == {"good"}
    (_notes,) = [notes for notes in [engine.finish()[1]]]
    assert any(reason == "rule not evaluated" and count == 1 for reason, count, _detail in _notes)


def test_a_condition_pysigma_cannot_read_is_a_reason_not_a_crash():
    broken = rule("broken", {"s": {"A": "b"}, "condition": "s and and"})
    engine = Engine([broken])
    engine.compile_all()
    assert engine.not_evaluated()


# --------------------------------------------------------------------------- #
# Log sources                                                                 #
# --------------------------------------------------------------------------- #
def test_process_creation_is_the_sysmon_event_and_the_security_one():
    engine = Engine([rule("p", {"s": {"Image|endswith": "\\cmd.exe"}, "condition": "s"})])
    assert names(engine, {"Image": "c:\\cmd.exe"}) == {"p"}
    security = {"NewProcessName": "C:\\Windows\\cmd.exe", "ParentProcessName": "C:\\x.exe", "SubjectUserName": "alice"}
    assert names(engine, security, channel="Security", event_id=4688) == {"p"}
    assert names(engine, {"Image": "c:\\cmd.exe"}, event_id=3) == set()  # network connection
    assert names(engine, {"Image": "c:\\cmd.exe"}, kind="commands", channel="", event_id=None) == set()


def test_the_security_4688_and_4657_get_the_sysmon_field_names():
    engine = Engine(
        [
            rule(
                "who", {"s": {"ParentImage|endswith": "\\x.exe", "User": "alice", "LogonId": "0x3e7"}, "condition": "s"}
            ),
            rule(
                "reg",
                {
                    "s": {"TargetObject|contains": "\\Run\\", "Details": "evil.exe", "Image|endswith": "\\reg.exe"},
                    "condition": "s",
                },
                category="registry_event",
            ),
        ]
    )
    process = {
        "NewProcessName": "C:\\a.exe",
        "ParentProcessName": "C:\\y\\X.EXE",
        "SubjectUserName": "Alice",
        "SubjectLogonId": "0x3E7",
    }
    assert names(engine, process, channel="Security", event_id=4688) == {"who"}
    registry = {"ObjectName": "\\REGISTRY\\Run\\a", "NewValue": "evil.exe", "ProcessName": "C:\\reg.exe"}
    assert names(engine, registry, channel="security", event_id=4657) == {"reg"}


def test_registry_add_and_set_tell_the_sysmon_event_type_apart():
    engine = Engine(
        [
            rule("added", {"s": {"TargetObject|contains": "Run"}, "condition": "s"}, category="registry_add"),
            rule("set", {"s": {"TargetObject|contains": "Run"}, "condition": "s"}, category="registry_set"),
        ]
    )
    assert names(engine, {"TargetObject": "HKLM\\Run", "EventType": "CreateKey"}, event_id=12) == {"added"}
    assert names(engine, {"TargetObject": "HKLM\\Run", "EventType": "DeleteKey"}, event_id=12) == set()
    assert names(engine, {"TargetObject": "HKLM\\Run", "EventType": "SetValue"}, event_id=13) == {"set"}


def test_a_service_is_the_channel_in_any_case_with_any_event_id():
    engine = Engine([rule("sec", {"s": {"LogonType": "10"}, "condition": "s"}, category=None, service="security")])
    assert names(engine, {"LogonType": "10"}, channel="Security", event_id=4624) == {"sec"}
    assert names(engine, {"LogonType": "10"}, channel="SECURITY", event_id=4625) == {"sec"}
    assert names(engine, {"LogonType": "10"}, channel="System", event_id=4624) == set()


def test_product_windows_alone_reads_every_event_log_record():
    engine = Engine([rule("any", {"s": {"EventID": 4624}, "condition": "s"}, category=None)])
    assert names(engine, {}, channel="Security", event_id=4624) == {"any"}
    assert names(engine, {}, channel="Security", event_id=4625) == set()


def test_the_nik_product_reads_the_sections_of_its_own_records():
    commands = rule(
        "cmd",
        {"s": {"command|contains": "mimikatz", "Type": "command", "Source": "powershell"}, "condition": "s"},
        product="nik",
        category=None,
        service="commands",
    )
    browser = rule(
        "web", {"s": {"Summary|contains": "phish"}, "condition": "s"}, product="nik", category=None, service="browser"
    )
    engine = Engine([commands, browser])
    hit = record(
        {"command": "Invoke-Mimikatz"}, channel="", event_id=None, kind="commands", rtype="command", source="powershell"
    )
    assert {slot.line["title"] for slot in engine.slots if slot.rid in engine.see(*hit)} == {"cmd"}
    page = record(
        {"url": "http://x"},
        channel="",
        event_id=None,
        kind="browser",
        rtype="visit",
        summary="A Phish page",
        source="chrome",
    )
    assert {slot.line["title"] for slot in engine.slots if slot.rid in engine.see(*page)} == {"web"}
    other = record(
        {"command": "mimikatz"}, channel="", event_id=None, kind="endpoint", rtype="command", source="powershell"
    )
    assert engine.see(*other) == []


def test_a_log_source_nik_has_no_records_for_is_unsupported_with_the_sentence():
    with pytest.raises(
        logsource.NoRecords, match="^Nik reads no records of this log source: linux/network_connection$"
    ):
        logsource.places("linux", "network_connection", None)
    with pytest.raises(logsource.NoRecords, match="^Nik reads no records of this log source: macos/process_creation$"):
        logsource.places("macos", "process_creation", None)
    with pytest.raises(logsource.NoRecords, match="windows/unheard_of"):
        logsource.places("windows", "unheard_of", None)
    with pytest.raises(logsource.NoRecords, match="nik"):
        logsource.places("nik", None, "mail")
    engine = Engine([rule("l", {"s": {"a": "b"}, "condition": "s"}, product="linux", category=None, service="ftpd2")])
    assert engine.not_evaluated() == [(engine.slots[0].rid, "Nik reads no records of this log source: linux/ftpd2")]


def test_a_data_name_that_collided_is_also_seen_without_the_prefix():
    engine = Engine([rule("c", {"s": {"task": "gone"}, "condition": "s"}, category=None)])
    assert names(engine, {"Data.task": "gone", "task": 12}) == set()  # the name of the system field wins
    assert names(engine, {"Data.opcode": "x"}) == set()
    engine = Engine([rule("c", {"s": {"opcode": "gone"}, "condition": "s"}, category=None)])
    assert names(engine, {"Data.opcode": "gone"}) == {"c"}


def test_the_fixed_fields_of_an_event_are_there_for_the_rules():
    engine = Engine(
        [
            rule(
                "f",
                {
                    "s": {
                        "EventID": 4624,
                        "Channel": "Security",
                        "Computer": "wks-1",
                        "Provider_Name": "microsoft-windows-security-auditing",
                        "User": "bob",
                    },
                    "condition": "s",
                },
                category=None,
            )
        ]
    )
    data = {"provider": "Microsoft-Windows-Security-Auditing"}
    assert names(engine, data, channel="Security", event_id=4624, username="bob") == {"f"}
    assert names(engine, data, channel="Security", event_id=4625, username="bob") == set()


def test_a_value_the_rule_reads_is_the_whole_of_it_not_the_cut_one():
    engine = Engine(
        [rule("tail", {"s": {"ScriptBlockText|contains": "tail-marker"}, "condition": "s"}, category="ps_script")]
    )
    long = "A" * 9000 + "tail-marker"
    assert names(
        engine, {"ScriptBlockText": long}, channel="Microsoft-Windows-PowerShell/Operational", event_id=4104
    ) == {"tail"}
    assert SYSMON  # (the helper's name is used elsewhere)


def test_the_linux_and_macos_log_sources_are_placed_in_the_syslog_section():
    kind, found = logsource.places("linux", None, "auditd")
    assert kind == "syslog" and found == (("audit", None, None),)
    assert {place[0] for place in logsource.places("linux", None, None)[1]} == {"auth", "journal", "audit"}
    assert {place[0] for place in logsource.places("linux", None, "sshd")[1]} == {"auth", "journal"}
    assert logsource.places("linux", None, "sshd")[1][0][2] == {"program": ["sshd", "sshd-session", "sshd-auth"]}
    assert [place[0] for place in logsource.places("linux", "process_creation", None)[1]] == ["audit"]
    assert [place[0] for place in logsource.places("linux", "process_creation", "auditd")[1]] == ["audit"]
    assert logsource.places("macos", None, None) == ("syslog", (("unifiedlog", None, None),))
    for product, category, service in (
        ("linux", "file_event", None),
        ("linux", None, "guacamole"),
        ("linux", "file_event", "auditd"),
        ("macos", "process_creation", None),
        ("macos", None, "sshd"),
    ):
        with pytest.raises(logsource.NoRecords, match="Nik reads no records of this log source"):
            logsource.places(product, category, service)


def test_the_process_chain_log_source_is_the_section_of_the_records_the_api_makes():
    assert logsource.places("nik", None, "process-chain") == ("process-chain", ((None, None, None),))
    with pytest.raises(logsource.NoRecords, match="nik/process_creation/process-chain"):
        logsource.places("nik", "process_creation", "process-chain")
    with pytest.raises(logsource.NoRecords, match="must say its service: commands, endpoint, browser or process-chain"):
        logsource.places("nik", None, None)
    # a rule of the log source is indexed and compiled like any other, and is not listed as one Nik cannot run
    engine = Engine(
        [
            rule(
                "chain",
                {"s": {"Image|endswith": "\\cmd.exe"}, "condition": "s"},
                product="nik",
                category=None,
                service="process-chain",
            )
        ]
    )
    assert engine.not_evaluated() == []
