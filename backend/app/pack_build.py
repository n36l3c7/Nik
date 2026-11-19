"""Make a catalogue of content packs from a folder of packs.

    python -m app.pack_build <folder of packs> <folder to write>

Each folder with a ``pack.yml`` becomes ``<id>-<version>.nikpack``, read back
and checked like a file someone uploads; ``index.json`` lists them with their
size and SHA-256, and ``index.json.sig`` is its signature, made with the
Ed25519 private key in ``PACKS_SIGNING_KEY`` (base64 of its 32 bytes). Without
the key the index is written unsigned, which is enough to look at it: Nik
reads only a signed one.

This is what the workflow of Nik's repository runs to publish ``packs/``, and
what a company runs to keep a catalogue of its own: the address and the public
key are then set in Settings → Content packs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import packs
from .automation import connector_logo
from .automation.connectors import load as load_connector


class BuildError(Exception):
    pass


def contents(pack: packs.PackFile) -> dict[str, int]:
    """How many of each kind a pack holds, and how many commands its connectors have."""
    found: dict[str, int] = {}
    for item in pack.items:
        found[item.kind] = found.get(item.kind, 0) + 1
        if item.kind == "connectors":
            connector = load_connector(item.data)
            found["commands"] = found.get("commands", 0) + len(connector.commands)
            premium = sum(1 for command in connector.commands if getattr(command, "premium", False))
            if premium:
                found["premium"] = found.get("premium", 0) + premium
    return found


def entry(folder: Path) -> tuple[dict[str, Any], str, bytes]:
    """One pack of a folder: its line of the index, the name of its file, and the file."""
    try:
        data = packs.folder_bytes(folder)
        pack = packs.read(data)
    except packs.PackError as error:
        raise BuildError(f"{folder.name}: {error.message}") from None
    manifest = pack.manifest
    if manifest["id"] != folder.name:
        raise BuildError(
            f'{folder.name}: its pack.yml says the id is "{manifest["id"]}"; the folder has the name of the id'
        )
    file_name = f"{manifest['id']}-{manifest['version']}.nikpack"
    line: dict[str, Any] = {
        **manifest,
        "file": file_name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "contents": contents(pack),
    }
    # The logo of the pack, or the one of its first connector that has one.
    logo = pack.logo or next((item.extras["logo"] for item in pack.items if item.extras.get("logo")), None)
    if logo:
        cleaned, kind = connector_logo.clean(logo)
        line["logo"] = {"type": kind, "data": base64.b64encode(cleaned).decode("ascii")}
    return line, file_name, data


def build(source: Path) -> tuple[bytes, dict[str, bytes]]:
    """The index of the packs of a folder (its bytes) and their files, by name."""
    files: dict[str, bytes] = {}
    lines = []
    for folder in sorted(path.parent for path in source.glob("*/pack.yml")):
        line, name, data = entry(folder)
        lines.append(line)
        files[name] = data
    if not lines:
        raise BuildError(f"{source} holds no pack (a folder with a pack.yml)")
    known = {line["id"] for line in lines}
    for line in lines:
        for need in line.get("requires") or []:
            if need["pack"] not in known and need["pack"] != packs.BUILTIN_ID:
                raise BuildError(f'{line["id"]}: it requires the pack "{need["pack"]}", which is not in this folder')
    index = json.dumps({"v": 1, "packs": lines}, indent=1, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return index, files


def sign(data: bytes, private_key: str) -> bytes:
    """The signature of ``data`` (base64) under an Ed25519 private key given as the base64 of its 32 bytes."""
    try:
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key.strip(), validate=True))
    except ValueError:
        raise BuildError("PACKS_SIGNING_KEY is not the base64 of an Ed25519 private key (32 bytes)") from None
    return base64.b64encode(key.sign(data))


def public_of(private_key: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key.strip(), validate=True))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    source, target = Path(arguments[0]), Path(arguments[1])
    try:
        index, files = build(source)
        key = os.environ.get("PACKS_SIGNING_KEY", "").strip()
        signature = sign(index, key) if key else None
    except BuildError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    target.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (target / name).write_bytes(data)
    (target / "index.json").write_bytes(index)
    if signature is not None:
        (target / "index.json.sig").write_bytes(signature)
    print(f"{len(files)} packs written to {target}" + ("" if signature else " (not signed: no PACKS_SIGNING_KEY)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
