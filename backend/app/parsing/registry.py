"""Parsing registry + upload dispatch/merge.

Mirrors the ids and shapes of the JS configs (``config/browsers.js``,
``shells.js``, ``artifacts.js``) so an uploaded file can be routed to the right
parser and merged into the incident document exactly like the frontend does.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import artifact as artifact_mod
from . import browser as browser_mod
from . import shell as shell_mod

# --- Browsers: id -> engine + per-source `produces` ------------------------ #
_CHROMIUM_SOURCES = {
    "history": ["history", "downloads"],
    "bookmarks": ["bookmarks"],
    "shortcuts": ["shortcuts"],
}
BROWSERS = {
    "chrome": {"engine": "chromium", "sources": _CHROMIUM_SOURCES},
    "edge": {"engine": "chromium", "sources": _CHROMIUM_SOURCES},
    "brave": {"engine": "chromium", "sources": _CHROMIUM_SOURCES},
    "opera": {"engine": "chromium", "sources": _CHROMIUM_SOURCES},
    "firefox": {"engine": "firefox", "sources": {"places": ["history", "bookmarks", "downloads"]}},
}

# --- Shells: id -> history format ------------------------------------------ #
SHELLS = {"bash": "bash", "zsh": "zsh", "fish": "fish", "powershell": "psreadline"}

# --- Endpoint artifact categories (mirror of config/artifacts.js) ---------- #
_EXEC_FIELDS = {
    "name": ["name", "program", "executable", "application", "filename", "process", "value"],
    "path": ["path", "fullpath", "full_path", "file_path", "image", "devicepath", "programpath"],
    "runCount": ["runcount", "run_count", "count", "executioncount", "timesexecuted"],
    "source": ["source", "artifact", "sourcetype", "type", "hive"],
}
_PERS_FIELDS = {
    "name": ["name", "entry", "task", "service", "key", "label", "value"],
    "kind": ["kind", "type", "mechanism", "category"],
    "command": ["command", "commandline", "command_line", "target", "path", "action", "exec", "data"],
    "location": ["location", "source", "hive", "file", "registrykey", "key_path"],
}
_FA_FIELDS = {
    "name": ["name", "item", "file", "filename", "document", "label", "value"],
    "target": ["target", "targetpath", "target_path", "path", "localpath", "href"],
    "kind": ["kind", "type", "artifact", "source"],
}
_USB_FIELDS = {
    "device": ["device", "friendlyname", "friendly_name", "devicename", "description", "model", "value"],
    "serial": ["serial", "serialnumber", "serial_number", "iserialnumber", "guid"],
    "vendor": ["vendor", "vendorproduct", "manufacturer", "product", "vid_pid", "vidpid"],
    "connection": ["connection", "event", "action", "kind", "type"],
}


def _src(key, name, parser=None, record_kind=None, record_name=None):
    return {"key": key, "name": name, "parser": parser, "recordKind": record_kind, "recordName": record_name}


ARTIFACT_CATEGORIES = {
    "execution": {
        "primaryField": "name",
        "fields": _EXEC_FIELDS,
        "timeAliases": ["lastrun", "last_run", "lastexecuted", "last_executed", "runtime", "executiontime", "timestamp", "time", "lastmodified", "date", "lastruntime"],
        "sources": {
            "bam": _src("bam", "BAM/DAM last execution"),
            "knowledgec": _src("knowledgec", "KnowledgeC app usage", parser="knowledgec"),
        },
    },
    "persistence": {
        "primaryField": "name",
        "fields": _PERS_FIELDS,
        "timeAliases": ["created", "modified", "lastmodified", "timestamp", "time", "date", "lastwrite"],
        "sources": {
            "runkeys": _src("runkeys", "Run / RunOnce keys"),
            "tasks": _src("tasks", "Scheduled Tasks"),
            "services": _src("services", "Services"),
            "startup": _src("startup", "Startup folder"),
            "wmi": _src("wmi", "WMI subscriptions"),
            "systemd": _src("systemd", "enabled systemd units"),
            "cron": _src("cron", "cron", parser="configlines", record_kind="cron", record_name="cron entry"),
            "sshkeys": _src("sshkeys", "SSH authorized_keys", parser="configlines", record_kind="authorized_keys", record_name="authorized_key"),
            "rc": _src("rc", "shell rc / profile", parser="configlines", record_kind="shell rc", record_name="rc line"),
            "launch": _src("launch", "LaunchAgent / LaunchDaemon", parser="plist"),
        },
    },
    "fileaccess": {
        "primaryField": "name",
        "fields": _FA_FIELDS,
        "timeAliases": ["accessed", "lastaccessed", "modified", "visited", "timestamp", "time", "date"],
        "sources": {"recent": _src("recent", "GTK recently-used", parser="xbel")},
    },
    "usb": {
        "primaryField": "device",
        "fields": _USB_FIELDS,
        "timeAliases": ["firstconnected", "first_connected", "lastconnected", "last_connected", "firstinstall", "timestamp", "time", "date", "installdate", "connected"],
        "sources": {
            "usbstor": _src("usbstor", "USBSTOR"),
            "setupapi": _src("setupapi", "setupapi log", parser="setupapi"),
            "journal": _src("journal", "kernel USB events"),
        },
    },
}

BROWSER_KEYS = ("history", "downloads", "bookmarks", "shortcuts")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bad(message: str) -> ValueError:
    return ValueError(message)


def apply_upload(doc: dict, tab: str, params: dict, data: bytes, file_name: str) -> dict:
    """Parse an uploaded file and merge it into ``doc['data']``.

    Returns a small summary ``{rows, format, target}``. Raises ValueError on an
    unknown target or unparseable file (the caller maps it to 400).
    """
    data_root = doc.setdefault("data", {})
    meta_base = {"fileName": file_name or "upload", "importedAt": _now()}

    if tab == "browser":
        browser_id = params.get("browser")
        source_key = params.get("source")
        spec = BROWSERS.get(browser_id)
        if spec is None or source_key not in spec["sources"]:
            raise _bad(f"Unknown browser/source '{browser_id}/{source_key}'.")
        produced, fmt = browser_mod.parse_browser_source(
            data, spec["engine"], source_key, spec["sources"][source_key]
        )
        browsers = data_root.setdefault("browser", {}).setdefault("browsers", {})
        slot = browsers.setdefault(browser_id, {})
        rows = 0
        for key in BROWSER_KEYS:
            if key in produced:
                slot[key] = produced[key]
                rows += len(produced[key])
        slot.setdefault("meta", {})[source_key] = {**meta_base, "format": fmt, "rows": rows}
        return {"rows": rows, "format": fmt, "target": f"browser/{browser_id}/{source_key}"}

    if tab == "commands":
        shell_id = params.get("shell")
        fmt_name = SHELLS.get(shell_id)
        if fmt_name is None:
            raise _bad(f"Unknown shell '{shell_id}'.")
        produced, fmt = shell_mod.parse_shell_history(data, fmt_name, file_name)
        shells = data_root.setdefault("commands", {}).setdefault("shells", {})
        slot = shells.setdefault(shell_id, {})
        slot["commands"] = produced["commands"]
        slot.setdefault("meta", {})["history"] = {**meta_base, "format": fmt, "rows": len(produced["commands"])}
        return {"rows": len(produced["commands"]), "format": fmt, "target": f"commands/{shell_id}"}

    if tab == "endpoint":
        category_id = params.get("category")
        source_key = params.get("source")
        category = ARTIFACT_CATEGORIES.get(category_id)
        if category is None or source_key not in category["sources"]:
            raise _bad(f"Unknown category/source '{category_id}/{source_key}'.")
        produced, fmt = artifact_mod.parse_artifact(data, category, category["sources"][source_key])
        cats = data_root.setdefault("endpoint", {}).setdefault("categories", {})
        slot = cats.setdefault(category_id, {}).setdefault("sources", {})
        slot[source_key] = {
            "records": produced["records"],
            "meta": {**meta_base, "format": fmt, "rows": len(produced["records"])},
        }
        return {"rows": len(produced["records"]), "format": fmt, "target": f"endpoint/{category_id}/{source_key}"}

    raise _bad(f"Unknown tab '{tab}' (expected browser|commands|endpoint).")
