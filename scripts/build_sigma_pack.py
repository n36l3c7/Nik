#!/usr/bin/env python3
"""Build Nik content packs from a checkout of SigmaHQ's rules.

    python scripts/build_sigma_pack.py /path/to/sigma --out ./packs-out

The checkout is the one you made yourself (``git clone https://github.com/SigmaHQ/sigma``): this tool reads
it and never downloads anything, and it never changes it. It writes two content packs, ready to be installed
from Settings, Content packs (the ``.nikpack`` files):

    sigmahq-windows       the rules of ``rules/windows``
    sigmahq-linux-macos   the rules of ``rules/linux`` and ``rules/macos``

Each pack holds one rule per file, ``sigma/<id of the rule>.yml``, exactly as SigmaHQ wrote it, and a
``pack.yml`` with the version (the tag of the checkout, else the date of its last commit), ``nik: ">=7.0"`` and
a notice: the rules are under the Detection Rule License 1.1, and each one keeps its author. Nik shows the
notice with the pack, and the author of a rule beside each match.

A file that is not a rule is skipped, and counted by why: ``info.yml`` and the other files of a folder that are
not rules, a rule with no ``id``, one whose ``id`` is not an id Nik takes, a file that holds more than one
document (a pack's file holds one rule), one that is not UTF-8 text, one too long, and a second file with an
id that was seen. Nik's own check of a rule (is it supported?) happens when the pack is installed.

Python 3 standard library only, and ``git`` when it is there (to read the tag and date of the checkout).
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_URL = "https://github.com/SigmaHQ/sigma"
LICENSE_URL = "https://github.com/SigmaHQ/Detection-Rule-License"
LICENSE_FILES = ("LICENSE.Detection.Rules.md", "LICENSE")  # SigmaHQ names it LICENSE
NIK_NEEDS = ">=7.0"
# What a pack of Nik takes of a rule (app/sigma/pack_items.py): one document, an id of these characters, a size.
TEXT_MAX = 100_000
ID_MAX = 64
NOTICE_MAX = 20_000
ID_LINE = re.compile(r"^id:[ \t]*['\"]?([^\s'\"#]+)", re.MULTILINE)
SEPARATOR = re.compile(r"^---[ \t]*$", re.MULTILINE)
ID_OK = re.compile(r"[A-Za-z0-9._:-]+")
FIXED_TIME = (2020, 1, 1, 0, 0, 0)  # the same checkout gives the same bytes


@dataclass(frozen=True)
class Spec:
    pack_id: str
    name: str
    folders: tuple[str, ...]  # under rules/
    tag: str
    summary: str


PACKS = (
    Spec(
        "sigmahq-windows",
        "SigmaHQ rules: Windows",
        ("windows",),
        "windows",
        "The Windows rules of SigmaHQ (rules/windows): process creation, event logs, registry, file, network, "
        "PowerShell, Sysmon and the rest of the Windows log sources.",
    ),
    Spec(
        "sigmahq-linux-macos",
        "SigmaHQ rules: Linux and macOS",
        ("linux", "macos"),
        "linux",
        "The Linux and macOS rules of SigmaHQ (rules/linux and rules/macos): auth, sshd, sudo, auditd, syslog, "
        "cron and the macOS unified log.",
    ),
)


@dataclass
class Built:
    spec: Spec
    rules: dict[str, str] = field(default_factory=dict)  # id -> text
    skipped: dict[str, int] = field(default_factory=dict)  # why -> how many
    examples: dict[str, list[str]] = field(default_factory=dict)

    def skip(self, why: str, path: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1
        held = self.examples.setdefault(why, [])
        if len(held) < 3:
            held.append(path)


def rule_id_of(text: str) -> tuple[str | None, str]:
    """The id of the rule a file holds, or ``(None, why it is not one Nik takes)``."""
    if len(text) > TEXT_MAX:
        return None, "longer than a pack's file may be"
    if sum(1 for part in SEPARATOR.split(text.lstrip("﻿")) if part.strip()) > 1:
        return None, "more than one document in the file"
    found = ID_LINE.search(text)
    if found is None:
        return None, "no id (not a rule, or a rule without one)"
    held = found.group(1)
    if len(held) > ID_MAX or not ID_OK.fullmatch(held):
        return None, "an id Nik does not take"
    return held, ""


def read_rules(root: Path, spec: Spec) -> Built:
    """Every ``.yml`` file under the folders of the pack, in a fixed order, as a rule or as a skip."""
    built = Built(spec)
    seen: set[str] = set()
    for folder in spec.folders:
        base = root / "rules" / folder
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.yml"), key=lambda item: item.as_posix()):
            if not path.is_file() or path.is_symlink():
                continue
            shown = path.relative_to(root).as_posix()
            if path.name.lower() in ("info.yml", "info.yaml"):
                built.skip("info.yml (a description of a folder, not a rule)", shown)
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                built.skip("not UTF-8 text", shown)
                continue
            found, why = rule_id_of(text)
            if found is None:
                built.skip(why, shown)
            elif found.lower() in seen:
                built.skip("an id that another file already has", shown)
            else:
                seen.add(found.lower())
                built.rules[found] = text
    return built


def version_of(root: Path, given: str | None) -> tuple[str, str]:
    """``(x.y.z, a sentence about where it comes from)``: the one given, else the tag of the checkout
    (``r2025-12-01`` is 2025.12.1), else the date of its last commit; the date of today when it is no repository."""
    if given:
        if not re.fullmatch(r"\d+\.\d+\.\d+", given):
            raise SystemExit(f'--version is three numbers: 1.0.0 (got "{given}")')
        return given, f"version {given}"

    def git(*arguments: str) -> str:
        try:
            done = subprocess.run(  # noqa: S603 - fixed arguments, the checkout is only read
                ["git", "-C", str(root), *arguments], capture_output=True, text=True, timeout=30, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return done.stdout.strip() if done.returncode == 0 else ""

    tag = git("describe", "--tags", "--exact-match", "HEAD")
    commit = git("rev-parse", "--short", "HEAD")
    day = git("log", "-1", "--format=%cs")
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", tag)
    if match:
        year, month, date = (int(part) for part in match.groups())
        return f"{year}.{month}.{date}", f"SigmaHQ tag {tag}" + (f" (commit {commit})" if commit else "")
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", day)
    if match:
        year, month, date = (int(part) for part in match.groups())
        return f"{year}.{month}.{date}", f"SigmaHQ commit {commit} of {day}"
    today = datetime.date.today()
    return f"{today.year}.{today.month}.{today.day}", f"a checkout read on {today.isoformat()}"


def notice(root: Path, origin: str) -> str:
    """The licence line and, when the checkout has it, the text of the Detection Rule License 1.1."""
    head = (
        "These rules are written by the SigmaHQ project and its contributors "
        f"({PROJECT_URL}) and are distributed under the Detection Rule License (DRL) 1.1 ({LICENSE_URL}). "
        "Each rule keeps its author: the name in the author field of the rule is who wrote it, and the DRL asks "
        "that it is shown wherever a rule's detection is. Nik shows it beside each match. "
        f"Built from {origin} with scripts/build_sigma_pack.py; the rules are as SigmaHQ wrote them."
    )
    for name in LICENSE_FILES:
        held = root / name
        if not held.is_file():
            continue
        try:
            text = held.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            continue
        full = f"{head}\n\n{text}"
        if "Detection Rule License" in text and len(full) <= NOTICE_MAX:
            return full
    return head


def yaml_text(value: str) -> str:
    """A string as one YAML scalar (JSON strings are YAML): no library needed to write the manifest."""
    return json.dumps(value, ensure_ascii=False)


def manifest_of(built: Built, version: str, origin: str, note: str) -> str:
    spec = built.spec
    count = len(built.rules)
    lines = [
        f"id: {spec.pack_id}",
        f"name: {yaml_text(spec.name)}",
        "vendor: SigmaHQ",
        "category: Detection",
        f"tags: [sigma, detection, {spec.tag}]",
        f"version: {version}",
        f"description: {yaml_text(f'{spec.summary} {count} rules, from {origin}.')}",
        "author: SigmaHQ and the authors of each rule",
        f"nik: {yaml_text(NIK_NEEDS)}",
        f"notice: {yaml_text(note)}",
    ]
    return "\n".join(lines) + "\n"


def write_zip(target: Path, built: Built, manifest: str) -> None:
    """A ``.nikpack``: ``pack.yml`` and ``sigma/<id>.yml``, in a fixed order with a fixed time."""
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as pack:
        for name, text in (
            ("pack.yml", manifest),
            *((f"sigma/{rid}.yml", body) for rid, body in sorted(built.rules.items())),
        ):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            pack.writestr(info, text.encode("utf-8"))


def write_folder(target: Path, built: Built, manifest: str) -> None:
    if target.exists():
        shutil.rmtree(target)
    (target / "sigma").mkdir(parents=True)
    (target / "pack.yml").write_text(manifest, encoding="utf-8", newline="\n")
    for rule_id, text in built.rules.items():
        (target / "sigma" / f"{rule_id}.yml").write_text(text, encoding="utf-8", newline="")


def build(checkout: Path, out: Path, version: str | None = None, folder: bool = False) -> list[Built]:
    """Write the packs; returns what each holds and what was left out."""
    if not (checkout / "rules").is_dir():
        raise SystemExit(f'"{checkout}" has no rules/ folder: it is not a checkout of {PROJECT_URL}')
    number, origin = version_of(checkout, version)
    note = notice(checkout, origin)
    out.mkdir(parents=True, exist_ok=True)
    made = []
    for spec in PACKS:
        built = read_rules(checkout, spec)
        if not built.rules:
            raise SystemExit(f"No rule was found for {spec.pack_id} under rules/{'/'.join(spec.folders)}")
        manifest = manifest_of(built, number, origin, note)
        write_zip(out / f"{spec.pack_id}-{number}.nikpack", built, manifest)
        if folder:
            write_folder(out / spec.pack_id, built, manifest)
        made.append(built)
    return made


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("checkout", type=Path, help="a checkout of https://github.com/SigmaHQ/sigma (never downloaded)")
    parser.add_argument("--out", type=Path, default=Path("sigma-packs"), help="where the packs are written")
    parser.add_argument(
        "--version", default=None, help="the version of the packs (three numbers); default: the checkout's"
    )
    parser.add_argument("--folder", action="store_true", help="also write each pack as a folder (pack.yml and sigma/)")
    args = parser.parse_args(argv)
    for built in build(args.checkout, args.out, args.version, args.folder):
        print(f"{built.spec.pack_id}: {len(built.rules)} rules")
        for why, count in sorted(built.skipped.items(), key=lambda item: -item[1]):
            print(f"  skipped {count}: {why} (for instance {', '.join(built.examples[why])})")
    print(f"Written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
