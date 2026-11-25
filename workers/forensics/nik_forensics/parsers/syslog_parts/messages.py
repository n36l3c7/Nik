"""The messages that matter in a Linux or macOS authentication log, decoded into fields.

``decode(program, message)`` is given the program that wrote a message (``sshd``, ``sudo``…) and its text, and
answers ``(type, data, username)`` or None when the message is none of the ones it knows (the record is then a
plain ``log``). The same code reads the lines of ``auth.log`` / ``secure``, the ``MESSAGE`` of a journal entry and
the ``eventMessage`` of the macOS unified log: the programs are the same, so the texts are.

Record types:

    logon         sshd Accepted…, a session opened by login or a display manager, a macOS authorization
    logon_failed  sshd Failed… / Invalid user, PAM "authentication failure", FAILED su, FAILED LOGIN, a sudo that
                  gave up after wrong passwords
    sudo          a command run through sudo (user, tty, pwd, runas, command), or refused (``error``)
    account       useradd, usermod, userdel, groupadd, passwd…: ``action`` says what was done
    session       a session opened or closed that is not a logon (sshd's, systemd-logind's)

``data`` keys: ``source_ip`` (only when the text is an address), ``source_host`` (when it is a name),
``source_port``, ``method``, ``logon_type``, ``service``, ``tty``, ``pwd``, ``runas``, ``command``, ``action``…
The account the message is about is the third value (``username``), not a ``data`` key.

Standard library only.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

SSHD = frozenset({"sshd", "sshd-session", "sshd-auth"})
SU = frozenset({"su", "su-l"})
LOGIN = frozenset(
    {"login", "gdm-password", "gdm-autologin", "gdm-fingerprint", "gdm-smartcard", "lightdm", "sddm", "xdm"}
)
ACCOUNT = frozenset(
    {
        "useradd",
        "usermod",
        "userdel",
        "groupadd",
        "groupmod",
        "groupdel",
        "passwd",
        "chpasswd",
        "gpasswd",
        "chage",
        "newusers",
        "chfn",
        "chsh",
        "adduser",
        "deluser",
        "vipw",
    }
)
# The PAM service of a session that is a logon (the display managers, the shells that ask for a password).
_LOGON_SERVICES = {
    "sudo": "sudo",
    "sudo-i": "sudo",
    "su": "su",
    "su-l": "su",
    "login": "login",
    "gdm-password": "gdm",
    "gdm-autologin": "gdm",
    "gdm-fingerprint": "gdm",
    "gdm-smartcard": "gdm",
    "lightdm": "lightdm",
    "sddm": "sddm",
    "xdm": "xdm",
    "polkit-1": "polkit",
    "cockpit": "cockpit",
}
# A sudo or su session is a user taking another one's rights, not somebody logging on: its record is a ``session``.
_ELEVATIONS = frozenset({"sudo", "su"})
_NO_ADDRESS = {"", "-", "::1", "127.0.0.1", "::ffff:127.0.0.1", "0.0.0.0", "::"}

_SSH_ACCEPT = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: ssh\d)?(?::\s*(.*))?$")
_SSH_FAILED = re.compile(r"^Failed (\S+) for (invalid user )?(.+?) from (\S+) port (\d+)")
_SSH_INVALID = re.compile(r"^Invalid user (.*?) from (\S+)(?: port (\d+))?\s*$")
_SSH_PAM = re.compile(r"^(?:error: )?PAM: [Aa]uthentication failure for (?:illegal user )?(\S+) from (\S+)")
_SSH_REFUSED = re.compile(r"^User (\S+) from (\S+) not allowed because")
_PAM = re.compile(r"^pam_(\w+)\(([^:)]*):(\w+)\):\s*(.*)$")
_PAM_SESSION = re.compile(
    r"^session (opened|closed) for user (\S+?)(?:\(uid=(\d+)\))?"
    r"(?: by (?:\(uid=\d+\)|([^\s(]*)(?:\(uid=(\d+)\))?))?\s*$"
)
_PAM_FAILURE = re.compile(r"^authentication failure;(.*)$")
_PAM_PAIR = re.compile(r"(\w+)=(\S*)")
_PAM_PASSWORD = re.compile(r"^password changed for (\S+)")
_SUDO_HEAD = re.compile(r"^\s*(\S+)\s*:\s*(.*)$")
_SU_OK = re.compile(r"^Successful su for (\S+) by (\S+)")
_SU_FAILED = re.compile(r"^FAILED su for (\S+) by (\S+)")
_LOGIN_OK = re.compile(r"^(ROOT )?LOGIN ON (\S+)(?: BY (\S+))?(?: FROM (\S+))?")
_LOGIN_FAILED = re.compile(r"^FAILED LOGIN(?: \d+)? FROM (\S+) FOR (\S+?),?(?: |$)")
_NEW_USER = re.compile(r"^new user: name=([^,\s]+), UID=(\d+), GID=(\d+), home=([^,\s]*), shell=(\S*)")
_NEW_GROUP = re.compile(r"^new group: name=([^,\s]+), GID=(\d+)")
_GROUP_ADDED = re.compile(r"^group added to /etc/\w+: name=([^,\s]+)(?:, GID=(\d+))?")
_DELETE = re.compile(r"^delete (user|group) '([^']+)'")
_ADD_TO_GROUP = re.compile(r"^add '([^']+)' to (?:shadow )?group '([^']+)'")
_REMOVE_FROM_GROUP = re.compile(r"^delete '([^']+)' from (?:shadow )?group '([^']+)'")
_CHANGE_NAME = re.compile(r"^change user name '([^']+)' to '([^']+)'")
_LOCK = re.compile(r"^(lock|unlock) user '([^']+)'")
_CHANGE_SHELL = re.compile(r"^(?:change|changed) user '([^']+)' (shell|home directory|password expiry information)")
_LOGIND_NEW = re.compile(r"^New session (\S+) of user (\S+?)\.?$")
_LOGIND_END = re.compile(r"^Removed session (\S+?)\.?$")
_AUTHD_OK = re.compile(r"^Succeeded authorizing right '([^']+)' by client '([^']+)'")
_AUTHD_FAILED = re.compile(r"^Failed to authorize right '([^']+)' by client '([^']+)'(?: .*?\((-?\d+)\))?")
_LOGINWINDOW = re.compile(r"\b(?:user )?(?:authentication|login) (succeeded|failed)\b", re.IGNORECASE)


def base_name(program: str) -> str:
    """The program without its path or its brackets, in lower case: what the tables above are keyed by."""
    name = program.rsplit("/", 1)[-1].strip().lower()
    return name.split("[", 1)[0].rstrip("]")


def address(text: str) -> str:
    """The text as an IP address when it is one (a zone or brackets are taken off), else an empty text."""
    text = text.strip().strip("[]")
    if text.lower().startswith("::ffff:") and "." in text:
        text = text[7:]
    text = text.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def source_of(data: dict[str, Any], where: str) -> None:
    """Where a logon came from: an address (``source_ip``) or a name (``source_host``)."""
    where = where.strip().rstrip(",")
    if where in ("", "?", "-", "(none)"):
        return
    ip = address(where)
    if ip:
        data["source_ip"] = ip
    else:
        data["source_host"] = where


def indicators(data: dict[str, Any]) -> list[tuple[str, str]]:
    """The source address of a logon, which is an indicator; a loopback or unset one is not."""
    ip = data.get("source_ip")
    return [("ip", ip)] if isinstance(ip, str) and ip not in _NO_ADDRESS else []


def _port(text: str | None) -> int | None:
    try:
        return int(text) if text else None
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# sshd                                                                        #
# --------------------------------------------------------------------------- #
def _sshd(message: str) -> tuple[str, dict, str] | None:
    found = _SSH_ACCEPT.match(message)
    if found:
        method, user, where, port, key = found.groups()
        data: dict[str, Any] = {"method": method, "logon_type": "ssh", "source_port": _port(port)}
        source_of(data, where)
        if key:
            data["key"] = key
        return "logon", data, user
    found = _SSH_FAILED.match(message)
    if found:
        method, invalid, user, where, port = found.groups()
        data = {"method": method, "logon_type": "ssh", "source_port": _port(port), "invalid_user": bool(invalid)}
        source_of(data, where)
        return "logon_failed", data, user
    found = _SSH_INVALID.match(message)
    if found:
        user, where, port = found.groups()
        data = {"logon_type": "ssh", "source_port": _port(port), "invalid_user": True}
        source_of(data, where)
        return "logon_failed", data, user
    found = _SSH_PAM.match(message)
    if found:
        data = {"method": "pam", "logon_type": "ssh"}
        source_of(data, found.group(2))
        return "logon_failed", data, found.group(1)
    found = _SSH_REFUSED.match(message)
    if found:
        data = {"logon_type": "ssh", "error": "user not allowed by the sshd configuration"}
        source_of(data, found.group(2))
        return "logon_failed", data, found.group(1)
    return None


# --------------------------------------------------------------------------- #
# PAM                                                                         #
# --------------------------------------------------------------------------- #
def _pam(message: str, program: str) -> tuple[str, dict, str] | None:
    found = _PAM.match(message)
    if not found:
        return None
    _module, service, area, rest = found.groups()
    service_name = service.lower()
    if area == "session":
        session = _PAM_SESSION.match(rest)
        if not session:
            return None
        state, user, _uid, by, _by_uid = session.groups()
        data: dict[str, Any] = {"action": state, "service": service, "by": by or ""}
        kind = _LOGON_SERVICES.get(service_name)
        if kind:
            data["logon_type"] = kind
            if kind in _ELEVATIONS:
                data["runas"] = user
        if state == "opened" and kind and kind not in _ELEVATIONS:
            return "logon", data, user
        return "session", data, user
    if area == "auth":
        failure = _PAM_FAILURE.match(rest)
        if not failure:
            return None
        pairs = dict(_PAM_PAIR.findall(failure.group(1)))
        data = {"service": service, "method": "pam", "tty": pairs.get("tty", "")}
        kind = _LOGON_SERVICES.get(service_name) or ("ssh" if service_name.startswith("sshd") else "")
        if kind:
            data["logon_type"] = kind
        source_of(data, pairs.get("rhost", ""))
        user = pairs.get("user") or pairs.get("ruser") or pairs.get("logname") or ""
        return "logon_failed", data, user
    if area == "chauthtok":
        changed = _PAM_PASSWORD.match(rest)
        if changed:
            return "account", {"action": "password_changed", "service": service}, changed.group(1)
    return None


# --------------------------------------------------------------------------- #
# sudo, su, login                                                             #
# --------------------------------------------------------------------------- #
def _sudo(message: str) -> tuple[str, dict, str] | None:
    if "TTY=" not in message and "COMMAND=" not in message and "incorrect password" not in message:
        return None
    found = _SUDO_HEAD.match(message)
    if not found or found.group(1).startswith("pam_"):
        return None
    user, rest = found.groups()
    command = ""
    at = rest.find("COMMAND=")
    if at >= 0:
        command = rest[at + 8 :].strip()
        rest = rest[:at]
    data: dict[str, Any] = {}
    errors: list[str] = []
    for part in (piece.strip() for piece in rest.split(";")):
        name, equals, value = part.partition("=")
        if equals and name in ("TTY", "PWD", "USER", "ENV"):
            data[{"TTY": "tty", "PWD": "pwd", "USER": "runas", "ENV": "env"}[name]] = value.strip()
        elif part:
            errors.append(part)
    if command:
        data["command"] = command
    if errors:
        data["error"] = "; ".join(errors)
    if any("incorrect password" in error for error in errors):
        data["method"] = "password"
        data["logon_type"] = "sudo"
        return "logon_failed", data, user
    if not command and not errors:
        return None
    return "sudo", data, user


def _su(message: str) -> tuple[str, dict, str] | None:
    found = _SU_OK.match(message)
    if found:
        return "logon", {"logon_type": "su", "by": found.group(2)}, found.group(1)
    found = _SU_FAILED.match(message)
    if found:
        return "logon_failed", {"logon_type": "su", "by": found.group(2), "method": "password"}, found.group(1)
    return None


def _login(message: str) -> tuple[str, dict, str] | None:
    found = _LOGIN_FAILED.match(message)
    if found:
        data: dict[str, Any] = {"logon_type": "login", "method": "password", "tty": found.group(1)}
        return "logon_failed", data, found.group(2)
    found = _LOGIN_OK.match(message)
    if found:
        root, tty, user, where = found.groups()
        data = {"logon_type": "login", "tty": tty}
        source_of(data, where or "")
        return "logon", data, user or ("root" if root else "")
    return None


# --------------------------------------------------------------------------- #
# Accounts                                                                    #
# --------------------------------------------------------------------------- #
def _account(message: str) -> tuple[str, dict, str] | None:
    found = _NEW_USER.match(message)
    if found:
        name, uid, gid, home, shell = found.groups()
        return "account", {"action": "user_added", "uid": int(uid), "gid": int(gid), "home": home, "shell": shell}, name
    found = _NEW_GROUP.match(message)
    if found:
        return "account", {"action": "group_added", "gid": int(found.group(2)), "group": found.group(1)}, ""
    found = _GROUP_ADDED.match(message)
    if found:
        data: dict[str, Any] = {"action": "group_added", "group": found.group(1)}
        if found.group(2):
            data["gid"] = int(found.group(2))
        return "account", data, ""
    found = _DELETE.match(message)
    if found:
        what = found.group(1)
        return "account", {"action": f"{what}_deleted"}, found.group(2) if what == "user" else ""
    found = _ADD_TO_GROUP.match(message)
    if found:
        return "account", {"action": "added_to_group", "group": found.group(2)}, found.group(1)
    found = _REMOVE_FROM_GROUP.match(message)
    if found:
        return "account", {"action": "removed_from_group", "group": found.group(2)}, found.group(1)
    found = _CHANGE_NAME.match(message)
    if found:
        return "account", {"action": "user_renamed", "new_name": found.group(2)}, found.group(1)
    found = _LOCK.match(message)
    if found:
        return "account", {"action": f"user_{found.group(1)}ed"}, found.group(2)
    found = _CHANGE_SHELL.match(message)
    if found:
        return "account", {"action": "user_changed", "changed": found.group(2)}, found.group(1)
    return None


# --------------------------------------------------------------------------- #
# macOS                                                                       #
# --------------------------------------------------------------------------- #
def _authd(message: str) -> tuple[str, dict, str] | None:
    found = _AUTHD_FAILED.match(message)
    if found:
        data: dict[str, Any] = {"right": found.group(1), "client": found.group(2), "logon_type": "authorization"}
        if found.group(3):
            data["error"] = found.group(3)
        return "logon_failed", data, ""
    found = _AUTHD_OK.match(message)
    if found and found.group(1).startswith("system.login."):
        return "logon", {"right": found.group(1), "client": found.group(2), "logon_type": "console"}, ""
    if found:
        return "log", {"right": found.group(1), "client": found.group(2)}, ""
    return None


def _loginwindow(message: str) -> tuple[str, dict, str] | None:
    found = _LOGINWINDOW.search(message)
    if not found:
        return None
    kind = "logon" if found.group(1).lower() == "succeeded" else "logon_failed"
    return kind, {"logon_type": "console"}, ""


# --------------------------------------------------------------------------- #
# Dispatch                                                                    #
# --------------------------------------------------------------------------- #
def decode(program: str, message: str) -> tuple[str, dict, str] | None:
    """What a message of ``program`` says, as ``(type, data, username)``, or None when it is none that is known."""
    name = base_name(program)
    if message.startswith("pam_"):
        return _pam(message, name)
    if name in SSHD:
        return _sshd(message)
    if name == "sudo":
        return _sudo(message)
    if name in SU:
        return _su(message)
    if name in LOGIN:
        return _login(message)
    if name in ACCOUNT:
        return _account(message)
    if name == "systemd-logind":
        found = _LOGIND_NEW.match(message)
        if found:
            return (
                "session",
                {"action": "opened", "session": found.group(1), "service": "systemd-logind"},
                found.group(2),
            )
        found = _LOGIND_END.match(message)
        if found:
            return "session", {"action": "closed", "session": found.group(1), "service": "systemd-logind"}, ""
        return None
    if name == "authd":
        return _authd(message)
    if name == "loginwindow":
        return _loginwindow(message)
    return None
