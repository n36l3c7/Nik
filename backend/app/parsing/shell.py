"""Shell history parser — port of ``shellParsers.js``.

Produces ``{ commands: [{ id, command, time, lineNo }], format }`` where ``time``
is Unix ms or None.
"""

from __future__ import annotations

import json
import re

from .common import gen_id, normalize_row, parse_csv, pick
from .timeutil import any_to_ms

COMMAND_ALIASES = ["command", "cmd", "commandline", "command_line", "line", "input"]
TIME_ALIASES = ["time", "timestamp", "when", "date", "datetime", "executed_at", "start"]


def _epoch_seconds_to_ms(value):
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return round(n * 1000) if n > 0 else None


def _entry(command, time, line_no):
    return {"id": gen_id(), "command": command, "time": time, "lineNo": line_no}


def parse_bash(text):
    commands, pending, line_no = [], None, 0
    for raw in text.split("\n"):
        line_no += 1
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        ts = re.match(r"^#(\d{9,11})$", line)
        if ts:
            pending = _epoch_seconds_to_ms(ts.group(1))
            continue
        commands.append(_entry(line, pending, line_no))
        pending = None
    return commands


def parse_zsh(text):
    commands, current, line_no = [], None, 0
    for raw in text.split("\n"):
        line_no += 1
        line = raw.rstrip("\r")
        if current is not None:
            continued = line.endswith("\\")
            current["command"] += "\n" + (line[:-1] if continued else line)
            if not continued:
                commands.append(current)
                current = None
            continue
        if not line.strip():
            continue
        ext = re.match(r"^:\s*(\d{9,11}):(\d+);([\s\S]*)$", line)
        time = _epoch_seconds_to_ms(ext.group(1)) if ext else None
        body = ext.group(3) if ext else line
        if not body.strip() and not ext:
            continue
        entry = _entry(body[:-1] if body.endswith("\\") else body, time, line_no)
        if body.endswith("\\"):
            current = entry
        else:
            commands.append(entry)
    if current is not None:
        commands.append(current)
    return commands


def parse_fish(text):
    commands, current, line_no = [], None, 0
    for raw in text.split("\n"):
        line_no += 1
        line = raw.rstrip("\r")
        cmd = re.match(r"^-\s+cmd:\s?(.*)$", line)
        if cmd:
            if current is not None:
                commands.append(current)
            command = cmd.group(1).replace("\\n", "\n").replace("\\\\", "\\")
            current = _entry(command, None, line_no)
            continue
        when = re.match(r"^\s+when:\s?(\d{9,11})", line)
        if when and current is not None:
            current["time"] = _epoch_seconds_to_ms(when.group(1))
    if current is not None:
        commands.append(current)
    return commands


def parse_psreadline(text):
    commands, current, line_no = [], None, 0
    for raw in text.split("\n"):
        line_no += 1
        line = raw.rstrip("\r")
        if current is not None:
            continued = line.endswith("`")
            current["command"] += "\n" + (line[:-1] if continued else line)
            if not continued:
                commands.append(current)
                current = None
            continue
        if not line.strip():
            continue
        continued = line.endswith("`")
        entry = _entry(line[:-1] if continued else line, None, line_no)
        if continued:
            current = entry
        else:
            commands.append(entry)
    if current is not None:
        commands.append(current)
    return commands


TEXT_PARSERS = {
    "bash": parse_bash,
    "zsh": parse_zsh,
    "fish": parse_fish,
    "psreadline": parse_psreadline,
}


def _map_export_rows(rows):
    commands, line_no = [], 0
    for raw in rows:
        line_no += 1
        if not isinstance(raw, dict):
            continue
        row = normalize_row(raw)
        command = None
        for alias in COMMAND_ALIASES:
            value = row.get(alias.lower().replace("_", ""))
            if value not in (None, ""):
                command = str(value)
                break
        if not command:
            continue
        time = None
        for alias in TIME_ALIASES:
            value = row.get(alias.lower().replace("_", ""))
            if value not in (None, ""):
                time = any_to_ms(value)
                if time is not None:
                    break
        commands.append(_entry(command, time, line_no))
    return commands


def parse_shell_history(data: bytes, fmt: str, file_name: str = ""):
    """Parse an uploaded shell-history file → ({commands}, format)."""
    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        raise ValueError("The file is empty.")

    trimmed = text.lstrip()
    if trimmed.startswith("{") or trimmed.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        rows = (
            parsed
            if isinstance(parsed, list)
            else parsed.get("commands") if isinstance(parsed, dict) and isinstance(parsed.get("commands"), list)
            else parsed.get("history") if isinstance(parsed, dict) and isinstance(parsed.get("history"), list)
            else None
        )
        if rows:
            commands = _map_export_rows(rows)
            if commands:
                return {"commands": commands}, "json"

    if file_name.lower().endswith(".csv"):
        commands = _map_export_rows(parse_csv(text))
        if commands:
            return {"commands": commands}, "csv"
        raise ValueError('CSV not recognized: a "command" column is required.')

    parser = TEXT_PARSERS.get(fmt, parse_bash)
    commands = parser(text)
    if not commands:
        raise ValueError("No commands found in the history file.")
    return {"commands": commands}, "text"
