"""The packs of vendors' products, as the repository keeps them (``packs/<id>/``).

They are not inside Nik (they are published to the catalogue), but they are
tested like what is: each connector against its recorded exchanges, each
mapper and playbook against the Nik it is installed in.
"""

from __future__ import annotations

import json
from pathlib import Path

from app import mapping, packs
from app.automation import connector_actions as ca

REPO_PACKS = Path(__file__).resolve().parents[2] / "packs"


def folders() -> list[Path]:
    return sorted(path.parent for path in REPO_PACKS.glob("*/pack.yml"))


def connectors() -> list[tuple[str, ca.ConnectorFile]]:
    """Every connector there is to test: the ones Nik ships and the ones of the packs."""
    found = list(ca.shipped())
    for path in sorted(REPO_PACKS.glob("*/connectors/*/connector.yml")):
        text = path.read_text(encoding="utf-8")
        found.append((text, ca.load(text)))
    return found


def mappers() -> dict[str, dict]:
    """connector id → the mappers and the classifier it comes with."""
    found = dict(mapping.shipped())
    for path in sorted(REPO_PACKS.glob("*/mappers/*.json")):
        found[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    return found


def playbooks() -> dict[str, dict]:
    """file name → the playbook of a pack."""
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))["playbook"]
        for path in sorted(REPO_PACKS.glob("*/playbooks/*.json"))
    }


def install(db) -> int:
    """Install every pack of the repository, as a Nik with ``NIK_PACKS_DIR`` does at start."""
    return packs.install_folder(db, REPO_PACKS)
