"""Run Mandiant capa on one sample and reduce its JSON report.

capa's report repeats the full match tree of every rule (megabytes on a large
binary). Nik keeps what the analyst reads: per capability its name,
namespace, scope, description, ATT&CK and MBC mappings and the addresses
where it matched. Rules capa marks as library or sub-scope helpers are
dropped, as capa's own text report does.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, Iterable, List

CAPA = os.environ.get("CAPA_BIN", "capa")
RULES = os.environ.get("CAPA_RULES", "/opt/capa/rules")
SIGNATURES = os.environ.get("CAPA_SIGNATURES", "/opt/capa/sigs")
MAX_ADDRESSES = 200
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class CapaError(Exception):
    """capa could not analyse the file."""


class CapaTimeout(CapaError):
    """capa did not finish in time and was stopped."""


def capa_version() -> str:
    return metadata.version("flare-capa")


def run_capa(path: str, timeout: float, extra_rules: Iterable[str] = ()) -> Dict[str, Any]:
    """capa's JSON report of ``path``; the process is killed after ``timeout`` seconds.

    ``extra_rules`` are rule files (admin rules) matched with the bundled set.
    """
    if not os.path.isfile(path):
        raise CapaError("The sample is not in the store.")
    command = [CAPA, "-r", RULES]
    for rule in extra_rules:
        command += ["-r", rule]
    command += ["-s", SIGNATURES, "-j", path]
    # A wide "terminal" keeps each of capa's log messages on one line.
    env = {**os.environ, "COLUMNS": "1000"}
    try:
        done = subprocess.run(command, capture_output=True, timeout=timeout, check=False, env=env)  # noqa: S603
    except subprocess.TimeoutExpired as exc:
        raise CapaTimeout(f"capa did not finish within {int(timeout)} seconds") from exc
    if done.returncode != 0:
        raise CapaError(_last_error(done.stderr.decode("utf-8", "replace")) or f"capa exited with {done.returncode}")
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError as exc:
        raise CapaError("capa did not return a JSON report") from exc


def _last_error(stderr: str) -> str:
    """The first meaningful ERROR message capa logged (decorations and source locations removed)."""
    lines = [_ANSI.sub("", line).strip() for line in stderr.splitlines()]
    for line in lines:
        if not line.startswith("ERROR"):
            continue
        text = re.sub(r"^ERROR\s+(capa:\s*)?", "", line)
        text = re.sub(r"\s*\S+\.py:\d+$", "", text).strip()
        if text.strip("-"):
            return text[:300]
    tail = [line for line in lines if line]
    return tail[-1][:300] if tail else ""


def _address(location: Dict[str, Any]) -> int | None:
    return location.get("value") if location.get("type") == "absolute" else None


def _attack(entry: Dict[str, Any]) -> Dict[str, str]:
    return {key: entry.get(key, "") for key in ("id", "tactic", "technique", "subtechnique")}


def _mbc(entry: Dict[str, Any]) -> Dict[str, str]:
    return {key: entry.get(key, "") for key in ("id", "objective", "behavior", "method")}


def compact(report: Dict[str, Any]) -> Dict[str, Any]:
    """The parts of capa's report Nik stores and shows."""
    analysis = report.get("meta", {}).get("analysis", {})
    capabilities: List[Dict[str, Any]] = []
    for name, rule in report.get("rules", {}).items():
        meta = rule.get("meta", {})
        if meta.get("lib") or meta.get("is_subscope_rule"):
            continue
        scopes = meta.get("scopes") or {}
        addresses = sorted({a for a in (_address(m[0]) for m in rule.get("matches", [])) if a is not None})
        capabilities.append(
            {
                "name": meta.get("name", name),
                "namespace": meta.get("namespace") or "",
                "scope": scopes.get("static") or meta.get("scope") or "",
                "description": meta.get("description") or "",
                "attack": [_attack(a) for a in meta.get("attack", [])],
                "mbc": [_mbc(m) for m in meta.get("mbc", [])],
                "addresses": addresses[:MAX_ADDRESSES],
                "truncated": len(addresses) > MAX_ADDRESSES,
            }
        )
    capabilities.sort(key=lambda c: (c["namespace"], c["name"]))
    base = _address(analysis.get("base_address") or {})
    return {
        "engine": {"name": "capa", "version": report.get("meta", {}).get("version", "")},
        "format": analysis.get("format", ""),
        "arch": analysis.get("arch", ""),
        "os": analysis.get("os", ""),
        "baseAddress": base,
        "libraryFunctions": len(analysis.get("library_functions") or []),
        "capabilities": capabilities,
    }


def analyze(path: str, timeout: float, extra_rules: Iterable[str] = ()) -> Dict[str, Any]:
    return compact(run_capa(path, timeout, extra_rules))


# ---------------------------------------------------------------------------
# Rule validation (admin rules)
# ---------------------------------------------------------------------------
_bundled_lock = threading.Lock()
_bundled: List[Any] = []


def _bundled_rules() -> List[Any]:
    """The bundled rules, parsed once (capa also caches them on disk)."""
    from capa.rules import get_rules

    with _bundled_lock:
        if not _bundled:
            _bundled.extend(get_rules([Path(RULES)]).rules.values())
        return list(_bundled)


def validate_rule(source: str, others: Iterable[str] = ()) -> Dict[str, Any]:
    """Parse one capa rule and check it against the bundled rules and the ``others`` (admin rules).

    Returns ``{ok, errors, name, namespace, scope}``: a duplicate name, a
    missing dependency (``match:`` of an unknown rule), an unknown feature or
    bad YAML is an error.
    """
    from capa.rules import Rule, RuleSet

    try:
        rule = Rule.from_yaml(source)
        extra = [Rule.from_yaml(other) for other in others]
        RuleSet(_bundled_rules() + extra + [rule])
    except Exception as exc:  # capa raises InvalidRule, yaml errors and others for bad input
        return {
            "ok": False,
            "errors": [" ".join(str(exc).split())[:500]],
            "name": None,
            "namespace": None,
            "scope": None,
        }
    scopes = getattr(rule, "scopes", None)
    static = getattr(scopes, "static", None)
    return {
        "ok": True,
        "errors": [],
        "name": rule.name,
        "namespace": rule.meta.get("namespace") or "",
        "scope": getattr(static, "value", str(static or "")),
    }
