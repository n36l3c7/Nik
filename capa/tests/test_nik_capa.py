"""The capa worker's reduction of capa's report and its error handling (capa itself is not run)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nik_capa  # noqa: E402
from nik_capa import CapaError, CapaTimeout, compact, run_capa  # noqa: E402

REPORT = json.loads((Path(__file__).parent / "fixtures" / "report.json").read_text(encoding="utf-8"))


def test_compact_keeps_capabilities_with_mappings_and_addresses():
    result = compact(REPORT)
    assert result["engine"] == {"name": "capa", "version": "10.0.0"}
    assert (result["format"], result["arch"], result["os"]) == ("pe", "amd64", "windows")
    assert result["baseAddress"] == 0x140000000 and result["libraryFunctions"] == 1
    # Library helper rules are dropped; the rest is sorted by namespace.
    assert [c["name"] for c in result["capabilities"]] == [
        "send data on socket",
        "compiled with rust",
        "link function at runtime on Windows",
    ]
    send = result["capabilities"][0]
    assert send["scope"] == "function" and send["addresses"] == [5371943088, 5371943200]
    assert send["mbc"] == [
        {"id": "C0001.007", "objective": "Communication", "behavior": "Socket Communication", "method": "Send Data"}
    ]
    link = result["capabilities"][2]
    assert link["attack"] == [{"id": "T1129", "tactic": "Execution", "technique": "Shared Modules", "subtechnique": ""}]
    assert result["capabilities"][1]["addresses"] == []  # file scope: no address


def test_compact_caps_the_addresses_per_capability():
    report = json.loads(json.dumps(REPORT))
    report["rules"]["send data on socket"]["matches"] = [
        [{"type": "absolute", "value": 0x1000 + i}, {}] for i in range(nik_capa.MAX_ADDRESSES + 5)
    ]
    send = compact(report)["capabilities"][0]
    assert len(send["addresses"]) == nik_capa.MAX_ADDRESSES and send["truncated"] is True


def _completed(returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_run_capa_reports_capa_errors_and_timeouts(tmp_path, monkeypatch):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")
    with pytest.raises(CapaError, match="not in the store"):
        run_capa(str(tmp_path / "missing.bin"), timeout=5)

    stderr = (  # as capa logs it: blank and ruler lines around the message, source locations on the right
        b"\x1b[31mERROR\x1b[0m    capa:                                   helpers.py:271\n"
        b"ERROR    capa:  ------------------------------------------------   helpers.py:271\n"
        b"ERROR    capa:  Input file does not appear to be a supported file.   helpers.py:272\n"
        b"ERROR    capa:  See all supported file formats via capa's help output (-h).   helpers.py:274\n"
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(14, stderr=stderr))
    with pytest.raises(CapaError, match=r"^Input file does not appear to be a supported file\.$"):
        run_capa(str(sample), timeout=5)

    def too_slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="capa", timeout=kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", too_slow)
    with pytest.raises(CapaTimeout, match="within 5 seconds"):
        run_capa(str(sample), timeout=5)

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(0, stdout=json.dumps(REPORT).encode()))
    assert run_capa(str(sample), timeout=5)["meta"]["version"] == "10.0.0"


def test_admin_rules_are_passed_after_the_bundled_ones(tmp_path, monkeypatch):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")
    seen = []

    def record(command, **kwargs):
        seen.append(command)
        return _completed(0, stdout=json.dumps(REPORT).encode())

    monkeypatch.setattr(subprocess, "run", record)
    run_capa(str(sample), timeout=5, extra_rules=["/samples/_capa_rules/a.yml", "/samples/_capa_rules/b.yml"])
    command = seen[0]
    rules = [command[i + 1] for i, arg in enumerate(command) if arg == "-r"]
    assert rules == [nik_capa.RULES, "/samples/_capa_rules/a.yml", "/samples/_capa_rules/b.yml"]
    assert command[-1] == str(sample)


RULE = """rule:
  meta:
    name: nik test mutex and process
    namespace: nik/test
    authors: [nik]
    scopes:
      static: function
      dynamic: process
  features:
    - and:
      - api: kernel32.CreateMutexA
      - match: create process on Windows
"""


@pytest.mark.skipif(not Path(nik_capa.RULES).is_dir(), reason="needs capa and its rules (the worker image)")
def test_validate_rule_against_the_bundled_rules():
    ok = nik_capa.validate_rule(RULE)
    assert ok["ok"] and ok["name"] == "nik test mutex and process" and ok["scope"] == "function"
    duplicate = nik_capa.validate_rule(RULE.replace("nik test mutex and process", "create process on Windows"))
    assert not duplicate["ok"] and "duplicate rule name" in duplicate["errors"][0]
    missing = nik_capa.validate_rule(RULE.replace("create process on Windows", "nik helper"))
    assert not missing["ok"] and "missing rule" in missing["errors"][0]
    helper = RULE.replace("nik test mutex and process", "nik helper").replace(
        "      - match: create process on Windows\n", ""
    )
    assert nik_capa.validate_rule(RULE.replace("create process on Windows", "nik helper"), [helper])["ok"]
    assert not nik_capa.validate_rule("rule: [\n")["ok"]
