"""Build step: download capa's rules and library signatures, verify, extract.

Used only while building the image (it needs the network then); the running
worker has no route outside its internal network.

    python fetch_rules.py <capa version> <rules sha256> <source sha256> <dest>
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

RULES_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/v{version}.tar.gz"
SOURCE_URL = "https://github.com/mandiant/capa/archive/refs/tags/v{version}.tar.gz"


def fetch(url: str, expected: str, target: Path) -> None:
    urllib.request.urlretrieve(url, target)  # noqa: S310 - fixed https URL
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    if digest != expected:
        raise SystemExit(f"{url}: sha256 {digest} does not match the pinned {expected}")


def extract(archive: Path, member: str, dest: Path) -> None:
    """Extract ``<top>/<member>`` of a GitHub source archive to ``dest``."""
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(archive) as tar:
        tar.extractall(tmp, filter="data")
        (top,) = Path(tmp).iterdir()
        shutil.copytree(top / member if member else top, dest)


def main() -> None:
    version, rules_sha256, source_sha256, dest = sys.argv[1:5]
    out = Path(dest)
    with tempfile.TemporaryDirectory() as tmp:
        rules, source = Path(tmp) / "rules.tgz", Path(tmp) / "source.tgz"
        fetch(RULES_URL.format(version=version), rules_sha256, rules)
        fetch(SOURCE_URL.format(version=version), source_sha256, source)
        extract(rules, "", out / "rules")
        extract(source, "sigs", out / "sigs")


if __name__ == "__main__":
    main()
