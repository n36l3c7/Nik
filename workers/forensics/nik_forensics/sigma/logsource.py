"""Which records a Sigma ``logsource`` applies to.

The table is our own (the category and service names of Sigma, the channels and event ids Windows writes; the
service names follow the ones pySigma's Windows pipelines know). A record is placed by ``(kind, channel,
event_id)``: ``kind`` is the section of the evidence the parser says it fills (``eventlog``, ``commands``,
``endpoint``, ``browser``), ``channel`` is compared in lower case.

    ``product: windows``  event log records. A category names the Sysmon event (and the Security event that
                          is its equivalent, whose fields are given the Sysmon names when the record is read:
                          ``engine.py``); a service names the channels.
    ``product: nik``      the records Nik makes itself: ``service: commands | endpoint | browser`` is the section.
    ``product: linux``    the ``syslog`` section (``parsers/syslog.py``): channels ``auth`` (auth.log, secure, any
                          syslog file), ``journal`` (``journalctl -o json``) and ``audit`` (audit.log, an event
                          per record). ``service: auth | sshd | sudo | syslog | cron | vsftpd | clamav`` name the
                          text logs and, for the programs, the ``program`` that wrote the message; ``service:
                          auditd`` the audit log; ``category: process_creation`` the audit events that are an
                          execve (a journal entry says a process logged a line, not that it started). A rule with
                          no service and no category reads every channel.
    ``product: macos``    the ``syslog`` section, channel ``unifiedlog``, for a rule with no category and no
                          service (keywords). ``category: process_creation`` is NOT supported: a unified log record
                          says which process wrote it, not that one was started, and it has no command line.

Anything else (cloud, a Linux category the records cannot satisfy…) has no records in Nik: ``places`` raises
``NoRecords`` with the sentence that is shown to the analyst.
"""

from __future__ import annotations

SYSMON = "microsoft-windows-sysmon/operational"
SECURITY = "security"
PS_OP = "microsoft-windows-powershell/operational"
PS_CLASSIC = "windows powershell"

# A place: (channel or None for any, event ids or None for any, extra condition on the record or None). The extra
# condition maps a lower-case field name to the lower-case values it may have.
Place = tuple[str | None, tuple[int, ...] | None, dict | None]

CATEGORY: dict[str, list[tuple[str, tuple[int, ...], dict | None]]] = {
    "process_creation": [(SYSMON, (1,), None), (SECURITY, (4688,), None)],
    "file_change": [(SYSMON, (2,), None)],
    "network_connection": [(SYSMON, (3,), None)],
    "process_termination": [(SYSMON, (5,), None)],
    "driver_load": [(SYSMON, (6,), None)],
    "image_load": [(SYSMON, (7,), None)],
    "create_remote_thread": [(SYSMON, (8,), None)],
    "raw_access_thread": [(SYSMON, (9,), None)],
    "process_access": [(SYSMON, (10,), None)],
    "file_event": [(SYSMON, (11,), None)],
    "registry_add": [
        (SYSMON, (12,), {"eventtype": ["createkey"]}),
        (SECURITY, (4657,), {"operationtype": ["new registry value created", "%%1904"]}),
    ],
    "registry_delete": [(SYSMON, (12,), {"eventtype": ["deletekey", "deletevalue"]})],
    "registry_set": [
        (SYSMON, (13,), None),
        (SECURITY, (4657,), {"operationtype": ["existing registry value modified", "%%1905"]}),
    ],
    "registry_rename": [(SYSMON, (14,), None)],
    "registry_event": [(SYSMON, (12, 13, 14), None), (SECURITY, (4657,), None)],
    "create_stream_hash": [(SYSMON, (15,), None)],
    "pipe_created": [(SYSMON, (17, 18), None)],
    "wmi_event": [(SYSMON, (19, 20, 21), None)],
    "dns_query": [(SYSMON, (22,), None)],
    "file_delete": [(SYSMON, (23, 26), None)],
    "clipboard_capture": [(SYSMON, (24,), None)],
    "process_tampering": [(SYSMON, (25,), None)],
    "file_block_executable": [(SYSMON, (27,), None)],
    "file_block_shredding": [(SYSMON, (28,), None)],
    "file_executable_detected": [(SYSMON, (29,), None)],
    "sysmon_error": [(SYSMON, (255,), None)],
    "sysmon_status": [(SYSMON, (4, 16), None)],
    "ps_module": [(PS_OP, (4103,), None)],
    "ps_script": [(PS_OP, (4104,), None)],
    "ps_classic_start": [(PS_CLASSIC, (400,), None)],
    "ps_classic_provider_start": [(PS_CLASSIC, (600,), None)],
    "ps_classic_script": [(PS_CLASSIC, (800,), None)],
}

# service -> the channels (any event id)
SERVICE: dict[str, tuple[str, ...]] = {
    "adfs": ("ad fs/admin",),
    "application": ("application",),
    "application-experience": (
        "microsoft-windows-application-experience/program-telemetry",
        "microsoft-windows-application-experience/program-compatibility-assistant",
    ),
    "applocker": (
        "microsoft-windows-applocker/msi and script",
        "microsoft-windows-applocker/exe and dll",
        "microsoft-windows-applocker/packaged app-deployment",
        "microsoft-windows-applocker/packaged app-execution",
    ),
    "appmodel-runtime": ("microsoft-windows-appmodel-runtime/admin",),
    "appxdeployment-server": ("microsoft-windows-appxdeploymentserver/operational",),
    "appxpackaging-om": ("microsoft-windows-appxpackaging/operational",),
    "bitlocker": ("microsoft-windows-bitlocker/bitlocker management",),
    "bits-client": ("microsoft-windows-bits-client/operational",),
    "capi2": ("microsoft-windows-capi2/operational",),
    "certificateservicesclient-lifecycle-system": (
        "microsoft-windows-certificateservicesclient-lifecycle-system/operational",
    ),
    "codeintegrity-operational": ("microsoft-windows-codeintegrity/operational",),
    "dhcp": ("microsoft-windows-dhcp-server/operational",),
    "diagnosis-scripted": ("microsoft-windows-diagnosis-scripted/operational",),
    "dns-client": ("microsoft-windows-dns client events/operational",),
    "dns-server": ("dns server",),
    "dns-server-analytic": ("microsoft-windows-dns-server/analytical",),
    "dns-server-audit": ("microsoft-windows-dns-server/audit",),
    "driver-framework": ("microsoft-windows-driverframeworks-usermode/operational",),
    "firewall-as": ("microsoft-windows-windows firewall with advanced security/firewall",),
    "hyper-v-worker": ("microsoft-windows-hyper-v-worker",),
    "iis-configuration": ("microsoft-iis-configuration/operational",),
    "kernel-event-tracing": ("microsoft-windows-kernel-eventtracing",),
    "kernel-shimengine": (
        "microsoft-windows-kernel-shimengine/operational",
        "microsoft-windows-kernel-shimengine/diagnostic",
    ),
    "ldap": ("microsoft-windows-ldap-client/debug",),
    "ldap_debug": ("microsoft-windows-ldap-client/debug",),
    "lsa-server": ("microsoft-windows-lsa/operational",),
    "microsoft-servicebus-client": ("microsoft-servicebus-client/operational", "microsoft-servicebus-client/admin"),
    "msexchange-management": ("msexchange management",),
    "ntfs": ("microsoft-windows-ntfs/operational",),
    "ntlm": ("microsoft-windows-ntlm/operational",),
    "openssh": ("openssh/operational",),
    "powershell": (PS_OP, "powershellcore/operational"),
    "powershell-classic": (PS_CLASSIC,),
    "printservice-admin": ("microsoft-windows-printservice/admin",),
    "printservice-operational": ("microsoft-windows-printservice/operational",),
    "security": (SECURITY,),
    "security-mitigations": (
        "microsoft-windows-security-mitigations/kernel mode",
        "microsoft-windows-security-mitigations/user mode",
    ),
    "sense": ("microsoft-windows-sense/operational",),
    "servicebus-client": ("microsoft-servicebus-client/operational", "microsoft-servicebus-client/admin"),
    "shell-core": ("microsoft-windows-shell-core/operational",),
    "smbclient-security": ("microsoft-windows-smbclient/security",),
    "sysmon": (SYSMON,),
    "system": ("system",),
    "taskscheduler": ("microsoft-windows-taskscheduler/operational",),
    "terminalservices-localsessionmanager": ("microsoft-windows-terminalservices-localsessionmanager/operational",),
    "vhdmp": ("microsoft-windows-vhdmp/operational",),
    "windefend": ("microsoft-windows-windows defender/operational",),
    "wmi": ("microsoft-windows-wmi-activity/operational",),
}

# The sections of the records Nik makes itself (``product: nik``).
NIK_SERVICES = ("commands", "endpoint", "browser")

# ``product: linux`` and ``product: macos``: the places of the ``syslog`` section. A place is a channel and an extra
# condition on lower-case fields of the record (``program`` is the program that wrote the message, ``facility`` the
# syslog facility of a journal entry, ``recordtype`` the type Nik gave the record).
SYSLOG = "syslog"
_AUTH_FACILITY = {"facility": ["auth", "authpriv"]}


def _programs(*names: str) -> tuple[Place, ...]:
    return (("auth", None, {"program": list(names)}), ("journal", None, {"program": list(names)}))


LINUX_SERVICE: dict[str, tuple[Place, ...]] = {
    "auth": (("auth", None, None), ("journal", None, _AUTH_FACILITY)),
    "syslog": (("auth", None, None), ("journal", None, None)),
    "sshd": _programs("sshd", "sshd-session", "sshd-auth"),
    "sudo": _programs("sudo"),
    "cron": _programs("cron", "crond", "crontab", "anacron"),
    "vsftpd": _programs("vsftpd"),
    "clamav": _programs("clamd", "freshclam", "clamav-daemon", "clamav-freshclam"),
    "auditd": (("audit", None, None),),
}
# ``process_creation`` of Linux: an execve of the audit log. A journal entry is NOT one: it says a process logged a
# line, not that it started.
LINUX_CATEGORY: dict[str, tuple[Place, ...]] = {
    "process_creation": (("audit", None, {"recordtype": ["process"]}),),
}
LINUX_ALL: tuple[Place, ...] = (("auth", None, None), ("journal", None, None), ("audit", None, None))
MACOS_ALL: tuple[Place, ...] = (("unifiedlog", None, None),)

# Fields added to a record of the ``syslog`` section, by channel: name -> the name it is read from (when the name is not
# there already). The audit log's own names (``exe``, ``ppid``, ``auid``…) stay too, as SigmaHQ's auditd rules write
# them.
SYSLOG_ALIASES: dict[str, dict[str, str]] = {
    "audit": {
        "image": "exe",
        "parentprocessid": "ppid",
        "processid": "pid",
        "logonid": "auid",
        "currentdirectory": "cwd",
    },
    "journal": {"image": "_exe", "commandline": "_cmdline", "processid": "_pid"},
    "unifiedlog": {"image": "processimagepath"},
}

# Fields added to a record of a given kind, so that rules written with the Sysmon names also run on the Security
# equivalents. The key is (lower-case channel, event id): name -> the name it is read from.
ALIASES: dict[tuple[str, int], dict[str, str]] = {
    (SECURITY, 4688): {
        "image": "newprocessname",
        "parentimage": "parentprocessname",
        "user": "subjectusername",
        "logonid": "subjectlogonid",
    },
    (SECURITY, 4657): {"image": "processname", "targetobject": "objectname", "details": "newvalue"},
}


class NoRecords(Exception):
    """Nik reads no records of this log source: the message is the sentence shown to the analyst."""


def _name(product: str | None, category: str | None, service: str | None) -> str:
    return "/".join(part for part in (product, category, service) if part) or "(nothing)"


def _linux_places(category: str | None, service: str | None, sorry: NoRecords) -> tuple[Place, ...]:
    if category:
        found = LINUX_CATEGORY.get(category)
        if found is None:
            raise sorry
        if service:
            wanted = LINUX_SERVICE.get(service)
            if wanted is None:
                raise sorry
            channels = {place[0] for place in wanted}
            found = tuple(place for place in found if place[0] in channels)
            if not found:
                raise sorry
        return found
    if service:
        found = LINUX_SERVICE.get(service)
        if found is None:
            raise sorry
        return found
    return LINUX_ALL


def syslog_fields(channel: str, rtype: str, orig: dict) -> None:
    """The fields of a ``syslog`` record that its parser does not write under the name the rules read: the Windows
    names of a process (``Image``, ``CommandLine``…), ``recordtype`` (the type Nik gave the record), and for the audit
    log ``type``, which is the list of the types of the lines of the event (SigmaHQ writes ``type: EXECVE``)."""
    orig["recordtype"] = rtype
    for name, read in SYSLOG_ALIASES.get(channel, {}).items():
        if name not in orig and orig.get(read) is not None:
            orig[name] = orig[read]
    if channel == "audit" and orig.get("types") is not None:
        orig["type"] = orig["types"]


def places(product: str | None, category: str | None, service: str | None) -> tuple[str, tuple[Place, ...]]:
    """The section a rule reads and the places of its records, or ``NoRecords``."""
    product = (product or "").lower() or None
    category = (category or "").lower() or None
    service = (service or "").lower() or None
    sorry = NoRecords(f"Nik reads no records of this log source: {_name(product, category, service)}")
    if product == "nik":
        if category or service not in (None, *NIK_SERVICES):
            raise sorry
        if service is None:
            raise NoRecords("a rule for product nik must say its service: commands, endpoint or browser")
        return service, ((None, None, None),)
    if product == "linux":
        return SYSLOG, _linux_places(category, service, sorry)
    if product == "macos":
        if category or service:
            raise sorry
        return SYSLOG, MACOS_ALL
    if product not in (None, "windows"):
        raise sorry
    if category:
        if category not in CATEGORY:
            raise sorry
        found: list[Place] = list(CATEGORY[category])
        if service:
            channels = SERVICE.get(service)
            if channels is None:
                raise sorry
            found = [place for place in found if place[0] in channels]
            if not found:
                raise sorry
        return "eventlog", tuple(found)
    if service:
        channels = SERVICE.get(service)
        if channels is None:
            raise sorry
        return "eventlog", tuple((channel, None, None) for channel in channels)
    if product is None:
        raise sorry
    return "eventlog", ((None, None, None),)
