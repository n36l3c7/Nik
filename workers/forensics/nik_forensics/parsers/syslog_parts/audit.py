"""The lines of ``audit.log`` and the events they make.

A line is ``type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 …`` (``node=<host> `` in front when
the log was relayed). The lines of one event share the time and the serial in ``audit(…)`` and may be mixed with the
lines of other events: ``Joiner`` holds the events that are not complete (at most ``MAX_OPEN`` of them, so memory is
bounded), and gives them back in the order they began, a complete one (its ``EOE`` line came) as soon as every event
before it is out, the others when the window is full or the file ends.

``decode_event`` turns the lines of an event into ``data``: for an ``execve`` event (a ``SYSCALL`` of execve, an
``EXECVE`` line) the executable, the process and parent ids, the user ids, the terminal, the key, the directory and
the command line (``CommandLine``, from the ``argc``/``aN`` arguments, hex-encoded ones decoded, long ones given in
pieces joined); for ``USER_LOGIN`` / ``USER_AUTH`` / ``USER_ACCT`` / ``CRED_ACQ`` the account, the address and the
result; for the other types the fields of the line.

Standard library only.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

MAX_OPEN = 512  # events held while their lines may still come
MAX_LINES = 400  # lines of one event that are joined; the others are counted, not kept
MAX_PATHS = 64
MAX_ARGS = 2048
MAX_ARG_FIELDS = 64  # arguments that are also given as the fields a0, a1… that Sigma rules read

_HEAD = re.compile(
    r"^(?:node=(?P<node>\S+) )?type=(?P<type>\S+) msg=audit\((?P<time>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s?(?P<body>.*)$"
)
_KV = re.compile(r"""([A-Za-z_][\w\-.\[\]]*)=("[^"]*"|'[^']*'|[^\s]*)""")
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_ARG = re.compile(r"^a(\d+)(?:\[(\d+)\]|_len)?$")
# Fields whose value is hex when it holds a space, a quote or a control character.
_ENCODED = frozenset({"proctitle", "comm", "exe", "cwd", "name", "acct", "cmd", "dir", "path", "key", "unit", "grp"})
_HEX_UPPER = re.compile(r"^(?:[0-9A-F]{2})+$")
_RES_OK = {"success", "yes", "1"}

# The syscalls Sigma rules and investigations name, by the architecture audit writes (``arch=`` in hex).
SYSCALLS: dict[str, dict[int, str]] = {
    "c000003e": {  # x86_64
        0: "read",
        1: "write",
        2: "open",
        3: "close",
        9: "mmap",
        10: "mprotect",
        16: "ioctl",
        41: "socket",
        42: "connect",
        43: "accept",
        44: "sendto",
        49: "bind",
        50: "listen",
        56: "clone",
        57: "fork",
        58: "vfork",
        59: "execve",
        62: "kill",
        82: "rename",
        86: "link",
        87: "unlink",
        88: "symlink",
        90: "chmod",
        92: "chown",
        99: "sysinfo",
        101: "ptrace",
        103: "syslog",
        105: "setuid",
        106: "setgid",
        113: "setreuid",
        117: "setresuid",
        133: "mknod",
        135: "personality",
        157: "prctl",
        161: "chroot",
        165: "mount",
        166: "umount2",
        175: "init_module",
        176: "delete_module",
        188: "setxattr",
        246: "kexec_load",
        257: "openat",
        259: "mknodat",
        263: "unlinkat",
        264: "renameat",
        272: "unshare",
        288: "accept4",
        308: "setns",
        313: "finit_module",
        319: "memfd_create",
        321: "bpf",
        322: "execveat",
    },
    "c00000b7": {  # aarch64
        33: "mknodat",
        35: "unlinkat",
        40: "mount",
        51: "chroot",
        56: "openat",
        92: "personality",
        97: "unshare",
        105: "init_module",
        106: "delete_module",
        116: "syslog",
        117: "ptrace",
        129: "kill",
        146: "setuid",
        179: "sysinfo",
        198: "socket",
        200: "bind",
        202: "accept",
        203: "connect",
        220: "clone",
        221: "execve",
        268: "setns",
        273: "finit_module",
        279: "memfd_create",
        280: "bpf",
        281: "execveat",
    },
    "40000003": {11: "execve", 358: "execveat"},  # i386
}


def decode_hex(text: str) -> str:
    """A hex-encoded value as text (NUL bytes, which separate the arguments of a process title, become spaces)."""
    return bytes.fromhex(text).decode("utf-8", "replace").replace("\x00", " ")


def _value(name: str, raw: str) -> str:
    """A value of a line: its quotes taken off, a hex-encoded one decoded."""
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    # Audit writes the hex of a value that holds a space, a quote or a control character in capitals; a value of
    # digits only is a number far more often than it is that.
    if name in _ENCODED and _HEX_UPPER.match(raw) and (name == "proctitle" or not raw.isdigit()):
        return decode_hex(raw)
    if raw == "(null)":
        return ""
    return raw


def _name(raw: str) -> str:
    """A field name: a name audit writes in capitals is the enriched form of the field (``UID="root"``)."""
    if raw.isupper() and raw not in ("EOE",):
        return f"{raw.lower()}_name"
    return raw


def pairs(body: str) -> dict[str, str]:
    """The ``name=value`` pairs of a line. ``msg='…'`` (the text of a user-space record) is read as pairs too."""
    found: dict[str, str] = {}
    for name, raw in _KV.findall(body):
        if name == "msg" and raw[:1] == "'":
            for inner, inner_raw in _KV.findall(raw[1:-1]):
                found.setdefault(_name(inner), _value(inner, inner_raw))
            continue
        found.setdefault(_name(name) if name != "msg" else name, _value(name, raw))
    return found


class Line:
    """One parsed line of the log."""

    __slots__ = ("node", "type", "time", "serial", "body", "fields", "number", "offset", "length")

    def __init__(self, node: str, kind: str, time: str, serial: str, body: str, number: int, offset: int, length: int):
        self.node, self.type, self.time, self.serial, self.body = node, kind, time, serial, body
        self.number, self.offset, self.length = number, offset, length
        self.fields: dict[str, str] | None = None

    def values(self) -> dict[str, str]:
        if self.fields is None:
            self.fields = pairs(self.body)
        return self.fields


def parse_line(text: str, number: int, offset: int, length: int) -> Line | None:
    """The line, or None when it is not a line of an audit log."""
    found = _HEAD.match(text.replace("\x1d", " ").rstrip("\r\n"))
    if not found:
        return None
    return Line(
        found.group("node") or "",
        found.group("type"),
        found.group("time"),
        found.group("serial"),
        found.group("body"),
        number,
        offset,
        length,
    )


def time_ms(text: str) -> int:
    """``1700000000.123`` → milliseconds."""
    whole, _dot, fraction = text.partition(".")
    return int(whole) * 1000 + int((fraction + "000")[:3])


class Event:
    """The lines of one event."""

    __slots__ = ("time", "serial", "node", "lines", "dropped", "complete")

    def __init__(self, time: str, serial: str, node: str) -> None:
        self.time, self.serial, self.node = time, serial, node
        self.lines: list[Line] = []
        self.dropped = 0
        self.complete = False


class Joiner:
    """Collects lines into events; ``add`` returns the events that are out (in the order they began)."""

    def __init__(self, window: int | None = None) -> None:
        self.window = MAX_OPEN if window is None else window
        self.open: OrderedDict[tuple[str, str, str], Event] = OrderedDict()
        self.overflowed = 0  # events given back before their ``EOE`` because the window was full
        self.dropped_lines = 0

    def add(self, line: Line) -> list[Event]:
        key = (line.time, line.serial, line.node)
        event = self.open.get(key)
        if event is None:
            event = self.open[key] = Event(line.time, line.serial, line.node)
        if line.type == "EOE":
            event.complete = True
        elif len(event.lines) < MAX_LINES:
            event.lines.append(line)
        else:
            event.dropped += 1
            self.dropped_lines += 1
        return self._out()

    def _out(self) -> list[Event]:
        out: list[Event] = []
        while self.open:
            first = next(iter(self.open.values()))
            if first.complete or len(self.open) > self.window:
                if not first.complete:
                    self.overflowed += 1
                out.append(self.open.popitem(last=False)[1])
            else:
                break
        return out

    def flush(self) -> list[Event]:
        out = list(self.open.values())
        self.open.clear()
        return out


# --------------------------------------------------------------------------- #
# What an event says                                                          #
# --------------------------------------------------------------------------- #
def _arguments(lines: list[Line]) -> tuple[list[str], int | None]:
    """The argv of the ``EXECVE`` lines of an event and the ``argc`` they say: arguments by number, a long one given
    as ``aN_len`` and ``aN[0]``, ``aN[1]``… in pieces."""
    whole: dict[int, str] = {}
    pieces: dict[int, dict[int, str]] = {}
    argc: int | None = None
    for line in lines:
        if line.type != "EXECVE":
            continue
        for name, raw in _KV.findall(line.body):
            if name == "argc":
                argc = int(raw) if raw.isdigit() else argc
                continue
            found = _ARG.match(name)
            if not found or name.endswith("_len") or int(found.group(1)) >= MAX_ARGS:
                continue
            value = _value("a", raw) if raw[:1] == '"' else (decode_hex(raw) if _HEX.match(raw) else raw)
            if found.group(2) is not None:
                pieces.setdefault(int(found.group(1)), {})[int(found.group(2))] = value
            else:
                whole[int(found.group(1))] = value
    for number, parts in pieces.items():
        whole[number] = "".join(parts[index] for index in sorted(parts))
    return [whole[number] for number in sorted(whole)], argc


def _saddr(text: str) -> dict[str, Any]:
    """The address of a ``SOCKADDR`` line (hex): family 2 (IPv4) and 10 (IPv6) give ``dest_ip`` and ``dest_port``."""
    if not _HEX.match(text) or len(text) < 8:
        return {}
    raw = bytes.fromhex(text)
    family = raw[0] | (raw[1] << 8)
    port = int.from_bytes(raw[2:4], "big")
    if family == 2 and len(raw) >= 8:
        return {"dest_ip": ".".join(str(part) for part in raw[4:8]), "dest_port": port}
    if family == 10 and len(raw) >= 24:
        import ipaddress

        return {"dest_ip": str(ipaddress.IPv6Address(raw[8:24])), "dest_port": port}
    return {}


def syscall_name(arch: str, number: str) -> str:
    if number.isdigit():
        return SYSCALLS.get(arch.lower(), {}).get(int(number), "")
    return ""


def decode_event(event: Event) -> dict[str, Any]:
    """The ``data`` of an event, with ``types`` (the types of its lines, in order) and ``kind``: ``process`` for an
    execve, ``user`` for an authentication event, else ``audit``."""
    data: dict[str, Any] = {"serial": int(event.serial) if event.serial.isdigit() else event.serial}
    types: list[str] = []
    paths: list[dict[str, str]] = []
    names: list[str] = []
    extra: dict[str, Any] = {}
    for line in event.lines:
        if line.type not in types:
            types.append(line.type)
        values = line.values()
        if line.type == "SYSCALL":
            for name, value in values.items():
                if name in ("a0", "a1", "a2", "a3"):
                    data.setdefault("syscall_args", []).append(value)  # hexadecimal arguments of the call, not argv
                elif name == "syscall":
                    data["syscall_number"] = value
                elif name == "syscall_name":
                    data["syscall_name"] = value
                else:
                    data.setdefault(name, value)
        elif line.type == "EXECVE":
            continue
        elif line.type == "CWD":
            if "cwd" in values:
                data["cwd"] = values["cwd"]
        elif line.type == "PATH":
            if len(paths) < MAX_PATHS:
                one = {k: values[k] for k in ("name", "nametype", "mode", "ouid", "ogid", "inode") if k in values}
                paths.append(one)
                if "name" in one:
                    names.append(one["name"])
        elif line.type == "PROCTITLE":
            if "proctitle" in values:
                data["proctitle"] = values["proctitle"]
        elif line.type == "SOCKADDR":
            extra.update(_saddr(_raw_of(line.body, "saddr")))
        else:
            for name, value in values.items():
                data.setdefault(name, value)
    argv, argc = _arguments(event.lines)
    if argv:
        data["argv"] = argv
        data["CommandLine"] = " ".join(argv)
        for number, value in enumerate(argv[:MAX_ARG_FIELDS]):
            data[f"a{number}"] = value
    elif data.get("proctitle"):
        data["CommandLine"] = data["proctitle"]
    if argc is not None:
        data["argc"] = argc
    arch = str(data.get("arch", ""))
    number = str(data.get("syscall_number", ""))
    name = data.pop("syscall_name", "") or syscall_name(arch, number)
    if number or name:
        data["syscall"] = name or number
    if paths:
        data["paths"] = paths
        data["name"] = names
    data.update(extra)
    data["types"] = types
    if event.dropped:
        data["lines_not_joined"] = event.dropped
    is_exec = "EXECVE" in types or data.get("syscall") in ("execve", "execveat")
    if is_exec:
        kind = "process"
    elif any(t in types for t in ("USER_LOGIN", "USER_AUTH", "USER_ACCT", "CRED_ACQ")):
        kind = "user"
    else:
        kind = "audit"
    data["kind"] = kind
    return data


def _raw_of(body: str, name: str) -> str:
    for found, raw in _KV.findall(body):
        if found == name:
            return raw
    return ""


def result_ok(data: dict[str, Any]) -> bool | None:
    """Did the event succeed (``res=success``/``success=yes``)? None when it does not say."""
    for name in ("res", "success"):
        value = str(data.get(name, "")).lower()
        if value:
            return value in _RES_OK
    return None
