"""``scripts/build_sigma_pack.py``: a checkout of SigmaHQ becomes content packs that Nik reads."""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

from app import packs

TOOL = Path(__file__).resolve().parents[2] / "scripts" / "build_sigma_pack.py"
ID = "{}-0000-0000-0000-000000000001"

RULE = """title: {title}
id: {rule_id}
status: test
description: A test rule
author: Florian Roth
date: 2024-01-01
logsource:
    category: process_creation
    product: {product}
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: medium
"""


def rule(title: str, rule_id: str, product: str = "windows") -> str:
    return RULE.format(title=title, rule_id=rule_id, product=product)


@pytest.fixture(scope="module")
def tool():
    if not TOOL.is_file():
        pytest.skip("the scripts folder is not in this copy of the repository")
    spec = importlib.util.spec_from_file_location("build_sigma_pack", TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # a dataclass finds its module here
    spec.loader.exec_module(module)
    return module


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture()
def checkout(tmp_path: Path) -> Path:
    root = tmp_path / "sigma"
    first, second = ID.format("aaaaaaaa"), ID.format("aaaaaaab")
    write(root, "rules/windows/process_creation/a.yml", rule("A", first))
    write(root, "rules/windows/builtin/security/b.yml", rule("B", second))
    write(root, "rules/windows/info.yml", "title: Windows rules\n")
    write(
        root,
        "rules/windows/no_id.yml",
        "title: No id\nlogsource:\n    product: windows\ndetection:\n    condition: x\n",
    )
    write(root, "rules/windows/twice.yml", rule("Again", first.upper()))
    write(
        root,
        "rules/windows/two_documents.yml",
        rule("C", ID.format("aaaaaaac")) + "---\n" + rule("D", ID.format("aaaaaaad")),
    )
    write(root, "rules/windows/bad_id.yml", "title: Bad\nid: not/an/id\n")
    write(root, "rules/linux/auth/c.yml", rule("L", ID.format("bbbbbbbb"), "linux"))
    write(root, "rules/macos/m.yml", rule("M", ID.format("cccccccc"), "macos"))
    write(root, "rules/cloud/aws/x.yml", rule("Not here", ID.format("dddddddd"), "aws"))
    (root / "rules/windows/binary.yml").write_bytes(b"\xff\xfe not utf-8 \x80")
    write(root, "LICENSE.Detection.Rules.md", "Detection Rule License (DRL) 1.1\n\nThe text of the licence.\n")
    return root


def test_the_rules_of_each_folder_go_to_their_pack_and_what_is_not_a_rule_is_counted(tool, checkout, tmp_path):
    windows, other = tool.build(checkout, tmp_path / "out", version="2024.5.6")
    assert sorted(windows.rules) == [ID.format("aaaaaaaa"), ID.format("aaaaaaab")]
    assert sorted(other.rules) == [ID.format("bbbbbbbb"), ID.format("cccccccc")]
    assert sum(windows.skipped.values()) == 6 and sum(other.skipped.values()) == 0
    assert windows.skipped["info.yml (a description of a folder, not a rule)"] == 1
    assert windows.skipped["no id (not a rule, or a rule without one)"] == 1
    assert windows.skipped["more than one document in the file"] == 1
    assert windows.skipped["an id Nik does not take"] == 1
    assert windows.skipped["an id that another file already has"] == 1
    assert windows.skipped["not UTF-8 text"] == 1


def test_a_pack_is_read_by_nik_with_its_notice_and_each_rule_as_written(tool, checkout, tmp_path):
    tool.build(checkout, tmp_path / "out", version="2024.5.6", folder=True)
    written = sorted(path.name for path in (tmp_path / "out").iterdir())
    assert written == [
        "sigmahq-linux-macos",
        "sigmahq-linux-macos-2024.5.6.nikpack",
        "sigmahq-windows",
        "sigmahq-windows-2024.5.6.nikpack",
    ]
    pack = packs.read((tmp_path / "out" / "sigmahq-windows-2024.5.6.nikpack").read_bytes())
    manifest = pack.manifest
    assert (manifest["id"], manifest["version"], manifest["nik"]) == ("sigmahq-windows", "2024.5.6", ">=7.0")
    assert "Detection Rule License" in manifest["notice"] and "https://github.com/SigmaHQ/sigma" in manifest["notice"]
    assert "keeps its author" in manifest["notice"] and "The text of the licence." in manifest["notice"]
    assert {item.kind for item in pack.items} == {"sigma_rules"}
    assert sorted(item.name for item in pack.items) == [ID.format("aaaaaaaa"), ID.format("aaaaaaab")]
    original = (checkout / "rules/windows/process_creation/a.yml").read_text(encoding="utf-8")
    assert next(item.data for item in pack.items if item.name == ID.format("aaaaaaaa")) == original
    other = packs.read((tmp_path / "out" / "sigmahq-linux-macos-2024.5.6.nikpack").read_bytes())
    assert other.manifest["id"] == "sigmahq-linux-macos" and len(other.items) == 2
    # The folder holds the same: one file for each rule, named by its id.
    assert (tmp_path / "out" / "sigmahq-windows" / "sigma" / f"{ID.format('aaaaaaab')}.yml").is_file()
    assert (tmp_path / "out" / "sigmahq-windows" / "pack.yml").is_file()


def test_the_same_checkout_gives_the_same_bytes_and_it_is_left_as_it_was(tool, checkout, tmp_path):
    def files() -> list[tuple[str, bytes]]:
        return sorted(
            (path.relative_to(checkout).as_posix(), path.read_bytes()) for path in checkout.rglob("*") if path.is_file()
        )

    before = files()
    tool.build(checkout, tmp_path / "one", version="1.2.3")
    tool.build(checkout, tmp_path / "two", version="1.2.3")
    name = "sigmahq-windows-1.2.3.nikpack"
    assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()
    assert files() == before
    with zipfile.ZipFile(tmp_path / "one" / name) as archive:
        assert archive.namelist()[0] == "pack.yml" and all(item.startswith("sigma/") for item in archive.namelist()[1:])


def test_a_folder_that_is_not_a_checkout_and_a_bad_version_are_refused(tool, tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(SystemExit, match="not a checkout"):
        tool.build(tmp_path / "empty", tmp_path / "out")
    with pytest.raises(SystemExit, match="three numbers"):
        tool.version_of(tmp_path, "2024")


def test_the_version_falls_back_to_the_date_when_the_folder_is_no_repository(tool, tmp_path):
    number, origin = tool.version_of(tmp_path, None)
    assert number.count(".") == 2 and "checkout read on" in origin
