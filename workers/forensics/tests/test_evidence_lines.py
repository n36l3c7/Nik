"""The ``proc``, ``proc_end`` and ``logon`` lines: what each log says of a process or a logon, from the events of an
event log (the mapping all three readers share), the JSON export end to end, the audit and auth logs, and Plaso.

Every event and file is made here at test time: harmless content, never evidence.
"""

# ruff: noqa: E501 - a log line is one line

from __future__ import annotations

import io
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from nik_forensics import context  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import eventlog_json, evtx, plaso, syslog  # noqa: E402

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
HOST = "WKS-042.corp.example"


def lines_of(event_id: int, channel: str, data: dict, provider: str = "", host: str = HOST) -> list[tuple[str, dict]]:
    """The lines the shared mapping gives for an event whose fields are ``data``."""
    return evtx.evidence(channel, event_id, provider, host, data)


def only(event_id: int, channel: str, data: dict, **more) -> tuple[str, dict]:
    (found,) = lines_of(event_id, channel, data, **more)
    return found


# --------------------------------------------------------------------------- #
# Processes                                                                   #
# --------------------------------------------------------------------------- #
def test_4688_has_hex_ids_the_integrity_of_its_label_and_the_parent_the_log_names():
    kind, line = only(
        4688,
        SECURITY,
        {
            "NewProcessId": "0x1a2c",
            "ProcessId": "0x0f40",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x00000000000a1b2c",
            "TokenElevationType": "%%1938",
            "MandatoryLabel": "S-1-16-12288",
        },
    )
    assert kind == "proc"
    assert line == {
        "pid": 0x1A2C,
        "ppid": 0xF40,
        "image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "user": "alice",
        "logon_id": "0xa1b2c",
        "integrity": "high",  # the label wins over the elevation hint
        "parent_image": "C:\\Windows\\explorer.exe",
    }


@pytest.mark.parametrize(
    ("label", "name"),
    [
        ("S-1-16-4096", "low"),
        ("S-1-16-8192", "medium"),
        ("S-1-16-8448", "medium plus"),
        ("S-1-16-12288", "high"),
        ("S-1-16-16384", "system"),
        ("S-1-16-20480", "protected"),
        ("S-1-16-99999", "S-1-16-99999"),
    ],
)
def test_the_mandatory_label_sid_is_the_integrity(label, name):
    assert only(4688, SECURITY, {"NewProcessId": "0x4", "MandatoryLabel": label})[1]["integrity"] == name


@pytest.mark.parametrize(("hint", "name"), [("%%1936", "full"), ("%%1937", "elevated"), ("%%1938", "limited")])
def test_without_a_label_the_token_elevation_type_is_a_hint(hint, name):
    assert only(4688, SECURITY, {"NewProcessId": "0x4", "TokenElevationType": hint})[1]["integrity"] == name


def test_a_4688_without_what_it_lacks_has_no_member_for_it():
    # Windows 7 / 2008 R2: no parent name, no command line; "-" is no value
    _, line = only(
        4688, SECURITY, {"NewProcessId": "0x10", "ProcessId": "0x4", "NewProcessName": "C:\\a.exe", "CommandLine": "-"}
    )
    assert line == {"pid": 16, "ppid": 4, "image": "C:\\a.exe"}


def test_4689_ends_a_process_and_sysmon_5_names_the_guid():
    assert only(4689, SECURITY, {"ProcessId": "0x1a2c", "ProcessName": "C:\\x.exe", "Status": "0x0"}) == (
        "proc_end",
        {"pid": 0x1A2C},
    )
    assert only(5, SYSMON, {"ProcessId": "7040", "ProcessGuid": "{aaaa-bbbb}", "Image": "C:\\x.exe"}) == (
        "proc_end",
        {"pid": 7040, "guid": "{aaaa-bbbb}"},
    )


def test_sysmon_1_has_the_guids_the_hashes_and_the_parents_command_line():
    digest = "ab" * 32
    kind, line = only(
        1,
        SYSMON,
        {
            "ProcessGuid": "{5e1c0c7d-0001-6620-0000-0010a1b20000}",
            "ProcessId": "6700",
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell -enc AAAA",
            "User": "CORP\\alice",
            "LogonId": "0x3e7",
            "IntegrityLevel": "High",
            "Hashes": f"SHA256={digest},MD5={'cd' * 16},IMPHASH={'ef' * 16},BAD=12",
            "ParentProcessGuid": "{5e1c0c7d-0001-6620-0000-0010ffff0000}",
            "ParentProcessId": "3904",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
        },
        provider="Microsoft-Windows-Sysmon",
    )
    assert kind == "proc"
    assert line["guid"] == "{5e1c0c7d-0001-6620-0000-0010a1b20000}" and line["parent_guid"].endswith("ffff0000}")
    assert (line["pid"], line["ppid"], line["user"], line["logon_id"], line["integrity"]) == (
        6700,
        3904,
        "CORP\\alice",
        "0x3e7",
        "high",
    )
    assert line["hashes"] == {"sha256": digest, "md5": "cd" * 16, "imphash": "ef" * 16}
    assert (
        line["parent_image"] == "C:\\Windows\\explorer.exe"
        and line["parent_command_line"] == "C:\\Windows\\Explorer.EXE"
    )


def test_other_events_give_no_process_or_logon_line():
    assert lines_of(4104, "Microsoft-Windows-PowerShell/Operational", {"ScriptBlockText": "x"}) == []
    assert lines_of(4624, "Application", {"TargetUserName": "alice"}) == []
    assert lines_of(3, SYSMON, {"Image": "C:\\x.exe", "DestinationIp": "10.0.0.9"}) == []
    assert lines_of(4720, SECURITY, {"TargetUserName": "newuser"}) == []
    assert evtx.evidence(SECURITY, None, "", HOST, {}) == []


# --------------------------------------------------------------------------- #
# Logons                                                                      #
# --------------------------------------------------------------------------- #
LOGON = {
    "TargetUserName": "alice",
    "TargetDomainName": "CORP",
    "TargetLogonId": "0x7a3b1",
    "LogonType": "3",
    "IpAddress": "10.1.2.3",
    "WorkstationName": "LAPTOP-7",
    "AuthenticationPackageName": "NTLM",
    "LmPackageName": "NTLM V2",
}


def test_4624_is_a_success_with_its_type_source_and_method():
    kind, line = only(4624, SECURITY, LOGON)
    assert kind == "logon"
    assert line == {
        "outcome": "success",
        "user": "alice",
        "domain": "CORP",
        "logon_id": "0x7a3b1",
        "logon_type": 3,
        "source_ip": "10.1.2.3",
        "source_host": "LAPTOP-7",
        "method": "NTLM V2",
    }


def test_the_method_is_the_authentication_package_when_there_is_no_lm_package():
    assert (
        only(4624, SECURITY, {**LOGON, "LmPackageName": "-", "AuthenticationPackageName": "Kerberos"})[1]["method"]
        == "Kerberos"
    )


@pytest.mark.parametrize("address", ["-", "::1", "127.0.0.1", "::ffff:127.0.0.1", ""])
def test_a_type_3_logon_of_the_host_to_itself_has_no_source(address):
    _, line = only(
        4624,
        SECURITY,
        {
            **LOGON,
            "IpAddress": address,
            "WorkstationName": "wks-042",
        },  # the host's own name, in any case, short or long
    )
    assert line["outcome"] == "success" and line["logon_type"] == 3
    assert "source_ip" not in line and "source_host" not in line


def test_the_machine_accounts_and_the_noise_accounts_are_kept():
    for user in ("WKS-042$", "SYSTEM", "ANONYMOUS LOGON"):
        assert only(4624, SECURITY, {**LOGON, "TargetUserName": user})[1]["user"] == user


@pytest.mark.parametrize(
    ("status", "sub", "text"),
    [
        ("0xc000006d", "0xc000006a", "wrong password"),
        ("0xC000006D", "0xC0000064", "unknown user"),
        ("0xc0000234", "0x0", "account locked"),
        ("0xc000006d", "0xc0000072", "account disabled"),
        ("0xc000006d", "0xc0000071", "password expired"),
        ("0xc000006d", "0xc0000193", "account expired"),
        ("0xc000006d", "0xc000006f", "outside allowed hours"),
        ("0xc000006d", "0xc0000070", "0xc0000070"),  # a code with no short text stays as the hex
        ("0xc000006d", "0x0", "0xc000006d"),
        ("0xc000006d", "", "0xc000006d"),
    ],
)
def test_4625_says_why_it_failed_as_short_text_or_the_hex(status, sub, text):
    fields = {**LOGON, "Status": status}
    if sub:
        fields["SubStatus"] = sub
    kind, line = only(4625, SECURITY, fields)
    assert kind == "logon" and line["outcome"] == "failure" and line["status"] == text


def test_4624_has_no_status():
    assert "status" not in only(4624, SECURITY, {**LOGON, "Status": "0x0"})[1]


def test_logoffs_explicit_credentials_and_privileges():
    assert only(
        4634,
        SECURITY,
        {"TargetUserName": "alice", "TargetDomainName": "CORP", "TargetLogonId": "0x7a3b1", "LogonType": "3"},
    )[1] == {
        "outcome": "logoff",
        "user": "alice",
        "domain": "CORP",
        "logon_id": "0x7a3b1",
        "logon_type": 3,
    }
    assert only(4647, SECURITY, {"TargetUserName": "alice", "TargetDomainName": "CORP", "TargetLogonId": "0x7a3b1"})[
        1
    ] == {
        "outcome": "logoff",
        "user": "alice",
        "domain": "CORP",
        "logon_id": "0x7a3b1",
    }
    explicit = only(
        4648,
        SECURITY,
        {
            "SubjectUserName": "bob",
            "SubjectLogonId": "0x1111",
            "TargetUserName": "admin",
            "TargetDomainName": "CORP",
            "TargetServerName": "srv-1",
            "IpAddress": "10.9.9.9",
        },
    )[1]
    assert explicit == {
        "outcome": "explicit",
        "user": "admin",
        "domain": "CORP",
        "logon_id": "0x1111",
        "source_ip": "10.9.9.9",
        "target_host": "srv-1",
    }
    assert only(
        4672,
        SECURITY,
        {
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x7a3b1",
            "PrivilegeList": "SeDebugPrivilege",
        },
    )[1] == {
        "outcome": "privileged",
        "user": "alice",
        "domain": "CORP",
        "logon_id": "0x7a3b1",
    }


def test_rdp_session_events_of_the_security_log():
    fields = {
        "AccountName": "alice",
        "AccountDomain": "CORP",
        "LogonID": "0x7a3b1",
        "SessionName": "RDP-Tcp#3",
        "ClientName": "LAPTOP-7",
        "ClientAddress": "10.1.2.3",
    }
    assert only(4778, SECURITY, fields)[1] == {
        "outcome": "success",
        "user": "alice",
        "domain": "CORP",
        "logon_id": "0x7a3b1",
        "logon_type": 10,
        "source_ip": "10.1.2.3",
        "source_host": "LAPTOP-7",
    }
    assert only(4779, SECURITY, fields)[1]["outcome"] == "logoff"
    console = only(
        4778, SECURITY, {**fields, "SessionName": "Console", "ClientAddress": "LOCAL", "ClientName": "WKS-042"}
    )[1]
    assert "logon_type" not in console and "source_ip" not in console and "source_host" not in console


def test_terminal_services_events_split_the_account_and_take_the_address():
    assert only(21, LSM, {"User": "CORP\\alice", "SessionID": "3", "Address": "10.1.2.3"})[1] == {
        "outcome": "success",
        "user": "alice",
        "domain": "CORP",
        "logon_type": 10,
        "source_ip": "10.1.2.3",
    }
    assert only(24, LSM, {"User": "CORP\\alice", "SessionID": "3", "Address": "10.1.2.3"})[1]["outcome"] == "logoff"
    assert only(25, LSM, {"User": "alice", "SessionID": "3", "Address": "10.1.2.3"})[1]["outcome"] == "success"
    local = only(21, LSM, {"User": "CORP\\alice", "SessionID": "1", "Address": "LOCAL"})[1]
    assert "source_ip" not in local and "logon_type" not in local
    assert lines_of(22, LSM, {"User": "CORP\\alice"}) == []


def test_remote_connection_manager_1149_is_an_rdp_authentication_from_an_address():
    assert only(1149, RCM, {"Param1": "alice", "Param2": "CORP", "Param3": "10.1.2.3"})[1] == {
        "outcome": "success",
        "user": "alice",
        "domain": "CORP",
        "logon_type": 10,
        "source_ip": "10.1.2.3",
    }
    assert only(1149, RCM, {"Param1": "alice", "Param2": "CORP", "Param3": "LAPTOP-7"})[1]["source_host"] == "LAPTOP-7"


# --------------------------------------------------------------------------- #
# The native event and the stream                                             #
# --------------------------------------------------------------------------- #
def native(event_id: int, channel: str, provider: str, data: dict) -> dict:
    body = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": provider}},
                "EventID": event_id,
                "TimeCreated": {"#attributes": {"SystemTime": "2024-03-05T10:20:30.123456Z"}},
                "EventRecordID": 77,
                "Channel": channel,
                "Computer": HOST,
            },
            "EventData": data,
        }
    }
    return {"event_record_id": 77, "timestamp": "", "data": json.dumps(body), "recovered": False}


def test_normalise_carries_the_lines_and_the_other_events_carry_none():
    norm = evtx.normalise(
        native(
            4688,
            SECURITY,
            "Microsoft-Windows-Security-Auditing",
            {"NewProcessId": "0x10", "NewProcessName": "C:\\a.exe"},
        )
    )
    assert norm["lines"] == [("proc", {"pid": 16, "image": "C:\\a.exe"})]
    assert evtx.normalise(native(4104, "Application", "x", {"Data": "y"}))["lines"] == []


def stream(found: list[dict]) -> None:
    """Every line about a process or a logon follows the line of its record (or a line about the same record)."""
    last = None
    for line in found:
        if line["t"] == "r":
            last = line["key"]
        elif line["t"] in ("proc", "proc_end", "logon"):
            assert last is not None and line["key"] == last, line
        elif line["t"] == "end":
            break


def said(path: str, params: dict | None = None) -> list[dict]:
    out = io.BytesIO()
    eventlog_json.parse(str(path), Context(out, params or {}), "nik-eventlogs.json")
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def export(tmp_path, events: list[dict]) -> str:
    path = tmp_path / "nik-eventlogs.json"
    path.write_text(json.dumps({"format": "nik-eventlogs", "host": "WKS-042", "events": events}), encoding="utf-8")
    return str(path)


def make(event_id: int, log: str, provider: str, data: dict, number: int) -> dict:
    return {
        "TimeCreated": f"2024-05-01T10:00:{number % 60:02d}.1234567Z",
        "Id": event_id,
        "LogName": log,
        "ProviderName": provider,
        "RecordId": number,
        "MachineName": HOST,
        "Data": data,
    }


def test_the_json_export_writes_the_lines_after_their_records_tied_by_key(tmp_path):
    events = [
        make(
            4688,
            SECURITY,
            "Microsoft-Windows-Security-Auditing",
            {
                "NewProcessId": "0x1a2c",
                "ProcessId": "0x0f40",
                "NewProcessName": "C:\\Windows\\cmd.exe",
                "CommandLine": "cmd /c dir",
                "SubjectUserName": "alice",
                "TokenElevationType": "%%1937",
            },
            1,
        ),
        make(4689, SECURITY, "Microsoft-Windows-Security-Auditing", {"ProcessId": "0x1a2c"}, 2),
        make(
            1,
            SYSMON,
            "Microsoft-Windows-Sysmon",
            {
                "ProcessGuid": "{g1}",
                "ProcessId": 6700,
                "Image": "C:\\a.exe",
                "ParentProcessGuid": "{g0}",
                "Hashes": "MD5=" + "ab" * 16,
            },
            3,
        ),
        make(5, SYSMON, "Microsoft-Windows-Sysmon", {"ProcessGuid": "{g1}", "ProcessId": 6700}, 4),
        make(4624, SECURITY, "Microsoft-Windows-Security-Auditing", LOGON, 5),
        make(
            4625,
            SECURITY,
            "Microsoft-Windows-Security-Auditing",
            {**LOGON, "Status": "0xc000006d", "SubStatus": "0xc000006a"},
            6,
        ),
        make(
            4104,
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell",
            {"ScriptBlockText": "x"},
            7,
        ),
        make(
            1149,
            RCM,
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
            {"Param1": "alice", "Param2": "CORP", "Param3": "10.1.2.3"},
            8,
        ),
    ]
    found = said(export(tmp_path, events))
    stream(found)
    kinds = [
        (line["t"], line.get("key", "").rsplit(":", 1)[-1])
        for line in found
        if line["t"] in ("r", "proc", "proc_end", "logon")
    ]
    assert kinds == [
        ("r", "1"), ("proc", "1"),
        ("r", "2"), ("proc_end", "2"),
        ("r", "3"), ("proc", "3"),
        ("r", "4"), ("proc_end", "4"),
        ("r", "5"), ("logon", "5"),
        ("r", "6"), ("logon", "6"),
        ("r", "7"),
        ("r", "8"), ("logon", "8"),
    ]  # fmt: skip
    by_key = {line["key"]: line for line in found if line["t"] in ("proc", "proc_end", "logon")}
    proc = by_key[f"evtx:{HOST}:Security:1"]
    assert (proc["host"], proc["pid"], proc["ppid"], proc["integrity"], proc["user"]) == (
        HOST,
        0x1A2C,
        0xF40,
        "elevated",
        "alice",
    )
    assert proc["ts"] == 1714557601123
    assert by_key[f"evtx:{HOST}:Security:2"]["pid"] == 0x1A2C
    sysmon = by_key[f"evtx:{HOST}:{SYSMON}:3"]
    assert (
        sysmon["pid"] == 6700
        and sysmon["guid"] == "{g1}"
        and sysmon["parent_guid"] == "{g0}"
        and sysmon["hashes"] == {"md5": "ab" * 16}
    )
    assert by_key[f"evtx:{HOST}:{SYSMON}:4"]["guid"] == "{g1}"
    assert by_key[f"evtx:{HOST}:Security:5"]["outcome"] == "success"
    failed = by_key[f"evtx:{HOST}:Security:6"]
    assert failed["outcome"] == "failure" and failed["status"] == "wrong password"
    assert found[-1]["t"] == "end" and found[-1]["read"] == 8 and found[-1]["in_file"] == 8


def test_a_property_list_with_decimal_numbers_gives_the_same_lines(tmp_path):
    # Get-WinEvent hands the numbers over as numbers: 6700 for 0x1a2c, 999 for the logon ID 0x3e7
    event = make(
        4688,
        SECURITY,
        "Microsoft-Windows-Security-Auditing",
        {"NewProcessId": 6700, "ProcessId": 3904, "NewProcessName": "C:\\a.exe", "SubjectLogonId": 999},
        1,
    )
    (proc,) = [line for line in said(export(tmp_path, [event])) if line["t"] == "proc"]
    assert (proc["pid"], proc["ppid"], proc["logon_id"]) == (6700, 3904, "0x3e7")


def test_the_parsers_that_write_the_lines_have_a_new_version():
    assert evtx.VERSION != "1" and eventlog_json.VERSION != "1" and syslog.VERSION != "1" and plaso.VERSION != "1"


def test_the_real_log_reads_with_the_same_records_and_no_line_about_a_process(tmp_path):
    sample = os.path.join(HERE, "tests", "fixtures", "Application_no_crc32.evtx")
    out = io.BytesIO()
    evtx.parse(sample, Context(out, {}), "evtx")
    found = [json.loads(line) for line in out.getvalue().splitlines() if line]
    assert sum(1 for line in found if line["t"] == "r") == 17
    assert not [line for line in found if line["t"] in ("proc", "proc_end", "logon")]
    assert found[-1]["t"] == "end" and found[-1]["read"] == 17


# --------------------------------------------------------------------------- #
# The context                                                                 #
# --------------------------------------------------------------------------- #
def ctx_lines(run) -> list[dict]:
    out = io.BytesIO()
    ctx = Context(out)
    run(ctx)
    ctx.end()
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def test_the_command_line_goes_whole_and_the_other_texts_are_cut_like_a_value():
    long = "x" * (context.MAX_VALUE * 3)

    def run(ctx):
        ctx.record(key="k", type="event")
        assert ctx.process(
            "k",
            ts=5,
            host="H",
            pid=1,
            ppid=0,
            image=long,
            command_line=long,
            parent_command_line=long,
            hashes={"md5": "a"},
            user="",
        )

    found = ctx_lines(run)
    (proc,) = [line for line in found if line["t"] == "proc"]
    assert len(proc["command_line"]) == len(long)
    assert len(proc["image"]) == context.MAX_VALUE and len(proc["parent_command_line"]) == context.MAX_VALUE
    assert "user" not in proc and "guid" not in proc and proc["ppid"] == 0 and proc["hashes"] == {"md5": "a"}
    assert not [line for line in found if line["t"] == "note"]


def test_a_line_over_the_limit_is_cut_and_a_note_counts_it(monkeypatch):
    monkeypatch.setattr(context, "MAX_LINE", 20_000)
    big = "y" * 30_000

    def run(ctx):
        ctx.record(key="k", type="event")
        assert ctx.process("k", pid=1, command_line=big)

    found = ctx_lines(run)
    (proc,) = [line for line in found if line["t"] == "proc"]
    assert 0 < len(proc["command_line"]) < 20_000
    assert [line["count"] for line in found if line["t"] == "note" and line["reason"] == "process line cut"] == [1]


def test_a_line_whose_record_was_not_written_is_not_written_and_is_counted():
    def run(ctx):
        ctx.record(key="k", type="event")
        assert not ctx.logon("another", outcome="success")
        assert not ctx.process_end("another", pid=1)

    found = ctx_lines(run)
    assert not [line for line in found if line["t"] in ("logon", "proc_end")]
    assert [line["count"] for line in found if line["t"] == "note"] == [2]


# --------------------------------------------------------------------------- #
# syslog                                                                      #
# --------------------------------------------------------------------------- #
def hexed(text: str) -> str:
    return text.encode().hex().upper()


def syslog_said(tmp_path, name: str, text: str, source: str) -> list[dict]:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    out = io.BytesIO()
    syslog.parse(str(path), Context(out, {"host": "IR-1", "year": 2025}), source)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


AUDIT = """\
type=SYSCALL msg=audit(1764065101.100:500): arch=c000003e syscall=59 success=yes exit=0 a0=55d0 items=1 ppid=812 pid=900 auid=1000 uid=0 gid=0 euid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="susp"
type=EXECVE msg=audit(1764065101.100:500): argc=3 a0="curl" a1="-o" a2="/tmp/x y"
type=EOE msg=audit(1764065101.100:500):
type=SYSCALL msg=audit(1764065101.200:501): arch=c000003e syscall=59 success=yes exit=0 ppid=1 auid=4294967295 uid=1001 comm="sh" exe="/bin/sh"
type=EXECVE msg=audit(1764065101.200:501): argc=1 a0="sh"
type=EOE msg=audit(1764065101.200:501):
type=USER_LOGIN msg=audit(1764065101.300:502): pid=812 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="root" exe="/usr/sbin/sshd" hostname=? addr=198.51.100.9 terminal=ssh res=failed'
type=EOE msg=audit(1764065101.300:502):
type=USER_LOGIN msg=audit(1764065102.000:503): pid=812 uid=0 auid=1000 ses=5 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=laptop addr=203.0.113.7 terminal=/dev/pts/1 res=success'
type=EOE msg=audit(1764065102.000:503):
"""


def test_an_audit_execve_is_a_process_and_a_login_is_a_logon(tmp_path):
    found = syslog_said(tmp_path, "audit.log", AUDIT, "linux.audit")
    stream(found)
    (proc,) = [line for line in found if line["t"] == "proc"]
    assert proc["key"] == "audit:IR-1:1764065101.100:500" and proc["ts"] == 1764065101100
    assert (proc["host"], proc["pid"], proc["ppid"], proc["image"], proc["user"]) == (
        "IR-1",
        900,
        812,
        "/usr/bin/curl",
        "root",
    )
    assert proc["command_line"] == "curl -o /tmp/x y" and "guid" not in proc and "cwd" not in proc
    failed, success = [line for line in found if line["t"] == "logon"]
    assert (failed["outcome"], failed["user"], failed["source_ip"]) == ("failure", "root", "198.51.100.9")
    assert "logon_type" not in failed
    assert (success["outcome"], success["user"], success["source_ip"]) == ("success", "1000", "203.0.113.7")
    notes = {line["reason"]: line["count"] for line in found if line["t"] == "note"}
    assert (
        notes["process record without a pid"] == 1
    )  # the second execve has no pid: its record is kept, said in a note
    assert sum(1 for line in found if line["t"] == "r") == 4


AUTH = """\
Nov 25 10:00:01 web01 sshd[1201]: Accepted publickey for alice from 203.0.113.7 port 51822 ssh2: ED25519 SHA256:abc
Nov 25 10:00:05 web01 sshd[1202]: Failed password for invalid user admin from 198.51.100.9 port 4242 ssh2
Nov 25 10:00:06 web01 sshd[1203]: Failed password for root from 198.51.100.9 port 4243 ssh2
Nov 25 10:00:09 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls
"""


def test_the_auth_log_logons_have_the_method_the_source_and_why_they_failed(tmp_path):
    found = syslog_said(tmp_path, "auth.log", AUTH, "linux.auth")
    stream(found)
    ok, invalid, bad = [line for line in found if line["t"] == "logon"]
    assert (ok["outcome"], ok["user"], ok["source_ip"], ok["method"]) == (
        "success",
        "alice",
        "203.0.113.7",
        "publickey",
    )
    assert (invalid["outcome"], invalid["user"], invalid["method"], invalid["status"]) == (
        "failure",
        "admin",
        "password",
        "unknown user",
    )
    assert (bad["outcome"], bad["user"], bad["source_ip"]) == (
        "failure",
        "root",
        "198.51.100.9",
    ) and "status" not in bad
    assert ok["host"] == "web01" and "logon_type" not in ok


def test_the_journal_and_the_unified_log_say_their_logons_too(tmp_path):
    journal = json.dumps(
        {
            "__REALTIME_TIMESTAMP": "1764065101000000",
            "__CURSOR": "s=1",
            "_HOSTNAME": "web02",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Accepted password for bob from 192.0.2.5 port 22 ssh2",
        }
    )
    found = syslog_said(tmp_path, "journal.json", journal + "\n", "linux.journal")
    stream(found)
    (logon,) = [line for line in found if line["t"] == "logon"]
    assert (logon["host"], logon["user"], logon["source_ip"], logon["method"], logon["outcome"]) == (
        "web02",
        "bob",
        "192.0.2.5",
        "password",
        "success",
    )
    unified = json.dumps(
        {
            "timestamp": "2025-11-25 10:00:01.000000+0000",
            "processImagePath": "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            "eventMessage": "Login Window Application Started",
            "traceID": 1,
        }
    )
    found = syslog_said(tmp_path, "unified.ndjson", unified + "\n", "macos.unifiedlog")
    stream(found)
    assert sum(1 for line in found if line["t"] == "r") == 1


# --------------------------------------------------------------------------- #
# Plaso                                                                       #
# --------------------------------------------------------------------------- #
def test_a_plaso_event_of_an_evtx_gives_the_same_lines(tmp_path):
    xml = (
        "<Event><System><Channel>Security</Channel><Computer>WKS-042</Computer></System><EventData>"
        '<Data Name="NewProcessId">0x1a2c</Data><Data Name="ProcessId">0x10</Data><Data Name="NewProcessName">C:\\a.exe</Data>'
        '<Data Name="CommandLine">a.exe -x</Data><Data Name="SubjectUserName">alice</Data><Data Name="MandatoryLabel">S-1-16-8192</Data>'
        '<Data Name="TokenElevationType">-</Data></EventData></Event>'
    )
    logon = (
        "<Event><System><Channel>Security</Channel><Computer>WKS-042</Computer></System><EventData>"
        '<Data Name="TargetUserName">alice</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">10.1.2.3</Data>'
        '<Data Name="WorkstationName">-</Data><Data Name="AuthenticationPackageName">Negotiate</Data></EventData></Event>'
    )
    base = {
        "__container_type__": "event",
        "__type__": "AttributeContainer",
        "data_type": "windows:evtx:record",
        "display_name": "OS:/C/Security.evtx",
        "parser": "winevtx",
        "timestamp": 1_700_000_000_000_000,
        "timestamp_desc": "Creation Time",
        "computer_name": "WKS-042",
        "source_name": "Microsoft-Windows-Security-Auditing",
    }
    events = [
        {**base, "event_identifier": 4688, "record_number": 1, "xml_string": xml},
        {**base, "event_identifier": 4624 | (1 << 16), "record_number": 2, "xml_string": logon},
        {**base, "data_type": "fs:stat", "message": "a file"},
    ]
    path = tmp_path / "timeline.jsonl"
    path.write_bytes(b"\n".join(json.dumps(item).encode() for item in events) + b"\n")
    out = io.BytesIO()
    plaso.parse(str(path), Context(out, {}), "plaso.jsonl")
    found = [json.loads(line) for line in out.getvalue().splitlines() if line]
    stream(found)
    proc, logon_line = [line for line in found if line["t"] in ("proc", "logon")]
    assert proc["t"] == "proc" and proc["key"] == "evtx:WKS-042:Security:1" and proc["host"] == "WKS-042"
    assert (proc["pid"], proc["ppid"], proc["image"], proc["command_line"], proc["user"], proc["integrity"]) == (
        0x1A2C,
        16,
        "C:\\a.exe",
        "a.exe -x",
        "alice",
        "medium",
    )
    assert logon_line["key"] == "evtx:WKS-042:Security:2"
    assert (logon_line["outcome"], logon_line["logon_type"], logon_line["source_ip"], logon_line["method"]) == (
        "success",
        10,
        "10.1.2.3",
        "Negotiate",
    )
    assert sum(1 for line in found if line["t"] == "r") == 3


AUTH_SESSIONS = """Nov 25 10:01:01 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)
Nov 25 10:01:30 web01 sudo: pam_unix(sudo:session): session closed for user root
Nov 25 10:03:00 web01 su[3001]: Successful su for root by alice
Nov 25 10:03:10 web01 su[3002]: pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)
Nov 25 10:04:30 web01 CRON[5001]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Nov 25 10:04:31 web01 CRON[5001]: pam_unix(cron:session): session closed for user root
Nov 25 10:05:00 web01 sshd[1301]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)
Nov 25 10:05:01 web01 sshd[1301]: Accepted publickey for alice from 203.0.113.7 port 51822 ssh2
"""

AUDIT_SESSIONS = """type=USER_START msg=audit(1764065101.100:600): pid=1 uid=0 auid=0 ses=1 msg='op=PAM:session_open acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
type=USER_START msg=audit(1764065101.200:601): pid=2 uid=0 auid=1000 ses=2 msg='op=PAM:session_open acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=USER_ACCT msg=audit(1764065101.300:602): pid=3 uid=0 auid=1000 ses=2 msg='op=PAM:accounting acct="root" exe="/usr/bin/su" hostname=? addr=? terminal=pts/0 res=success'
type=CRED_ACQ msg=audit(1764065101.400:603): pid=4 uid=0 auid=1000 ses=2 msg='op=PAM:setcred acct="alice" exe="/usr/sbin/sshd" hostname=laptop addr=203.0.113.7 terminal=ssh res=success'
"""


def test_only_the_logon_records_give_logon_lines_never_a_session_of_cron_sudo_or_su(tmp_path):
    found = syslog_said(tmp_path, "auth.log", AUTH_SESSIONS, "linux.auth")
    stream(found)
    types = {line["key"]: line["type"] for line in found if line["t"] == "r"}
    logons = [line for line in found if line["t"] == "logon"]
    # "Successful su" and sshd's "Accepted" are logons; the four PAM sessions (sudo, su, cron, sshd) are not.
    assert [types[line["key"]] for line in logons] == ["logon", "logon"]
    assert sorted((line["user"], line.get("source_ip", "")) for line in logons) == [
        ("alice", "203.0.113.7"),
        ("root", ""),
    ]
    assert sum(1 for kind in types.values() if kind == "session") >= 5
    found = syslog_said(tmp_path, "audit.log", AUDIT_SESSIONS, "linux.audit")
    stream(found)
    types = {line["key"]: line["type"] for line in found if line["t"] == "r"}
    assert all(types[line["key"]] in ("logon", "logon_failed") for line in found if line["t"] == "logon")
    assert not [line for line in found if line["t"] == "logon"]


@pytest.mark.parametrize(
    ("target", "kept"),
    [
        ("srv-1", "srv-1"),
        ("srv-1.corp.example", "srv-1.corp.example"),
        ("localhost", ""),
        ("LOCALHOST", ""),
        ("-", ""),
        ("", ""),
        ("WKS-042", ""),
        ("wks-042.corp.example", ""),
    ],
)
def test_an_explicit_logon_names_the_server_it_went_to_unless_it_is_the_host_itself(target, kept):
    data = {"SubjectUserName": "bob", "SubjectLogonId": "0x1", "TargetUserName": "admin", "TargetServerName": target}
    line = only(4648, SECURITY, data)[1]
    assert line.get("target_host", "") == kept
    other = only(4624, SECURITY, {"TargetUserName": "bob", "LogonType": "3", "TargetServerName": target})[1]
    assert "target_host" not in other


def test_the_logon_line_carries_the_target_host_through_the_context():
    out = io.BytesIO()
    ctx = Context(out, {})
    ctx.record(key="k", type="event", ts=1, host="WKS", username="", channel="Security", summary="", data={})
    assert ctx.logon("k", ts=1, host="WKS", user="a", outcome="explicit", target_host="srv-1")
    last = json.loads(out.getvalue().splitlines()[-1])
    assert last["t"] == "logon" and last["target_host"] == "srv-1"
