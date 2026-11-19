"""The catalogue of content packs: what there is to install, read from one address.

The packs of vendors' products are not inside Nik: they are files published
beside an **index** (``index.json``), and Nik reads the index to show what
there is. By default that is the release ``packs`` of Nik's repository; an
admin may set another address (a mirror inside the company, a fork).

Nothing of the catalogue is trusted for where it comes from:

- the index is **signed** (``index.json.sig``, Ed25519 over the bytes of the
  index) and is read only when the signature is of the key Nik holds (the
  one below, or the one set beside another address);
- a pack is taken only when its size and its SHA-256 are the ones the index
  gives;
- then it is a pack like one uploaded by hand: read, compared with what is
  here, and applied only after someone looked at what it would do.

What is read is kept (settings row 3), so that the page does not go out each
time it is opened: "Read again" does.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import packs
from .automation import connector_logo, egress, state
from .core.config import settings as app_settings
from .core.models import Pack, Setting
from .core.security import now_iso

SETTINGS_ID = 3
# The public half of the key the packs of Nik's repository are signed with (base64 of its 32 bytes).
# The private half is a secret of the repository, used by the workflow that publishes the packs.
NIK_KEY = "0s/izpmHr8vtRI2ipJJt0he4D1g1HWkZsQ0dx6jRMeU="
INDEX_MAX = 8 * 1024 * 1024
LOGO_MAX = 200_000
ENTRIES_MAX = 2000
# Where GitHub sends for the file of a release: the address of the catalogue is not the host that answers.
GITHUB_HOSTS = ("objects.githubusercontent.com", "release-assets.githubusercontent.com")
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,150}\.nikpack$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COUNTED = (*packs.KINDS, "commands")


class CatalogueError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- #
# What is kept                                                                #
# --------------------------------------------------------------------------- #
def _doc(db: OrmSession) -> dict[str, Any]:
    row = db.get(Setting, SETTINGS_ID)
    return dict((row.doc if row else None) or {})


def _keep(db: OrmSession, **changes: Any) -> dict[str, Any]:
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        row = Setting(id=SETTINGS_ID, doc={})
        db.add(row)
        db.flush()
    row.doc = {**(row.doc or {}), **changes}
    flag_modified(row, "doc")
    return row.doc


def clean_key(text: Any) -> str:
    """A public key as Nik keeps it (base64 of 32 bytes), or raises."""
    text = str(text or "").strip()
    try:
        raw = base64.b64decode(text, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (binascii.Error, ValueError):
        raise CatalogueError("The key of a catalogue is the base64 of an Ed25519 public key (32 bytes)", 400) from None
    return base64.b64encode(raw).decode("ascii")


def clean_address(text: Any) -> str:
    text = str(text or "").strip()
    parts = urlsplit(text)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or len(text) > 500:
        raise CatalogueError("The address of a catalogue is an https address of its index.json", 400)
    if parts.query or parts.fragment:
        raise CatalogueError("The address of a catalogue has no ? and no #", 400)
    return text


def where(db: OrmSession) -> dict[str, Any]:
    """Where the catalogue is read from: ``{address, key, custom}``."""
    held = _doc(db)
    address = held.get("address") or app_settings.PACKS_CATALOGUE
    return {
        "address": address,
        "key": held.get("key") or NIK_KEY,
        "custom": bool(held.get("address")),
        "ownKey": bool(held.get("key")),
    }


def set_where(db: OrmSession, address: Any, key: Any) -> dict[str, Any]:
    """Set the address and the key (the caller commits). Both empty: Nik's own again. What was read from
    the address before is forgotten: it is not this catalogue's."""
    address, key = str(address or "").strip(), str(key or "").strip()
    _keep(
        db,
        address=clean_address(address) if address else "",
        key=clean_key(key) if key else "",
        index=None,
        fetchedAt="",
        error="",
    )
    return where(db)


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def _policy(db: OrmSession, address: str) -> egress.Policy:
    """Setting the address is the permission to reach its host; GitHub answers a release from other hosts."""
    host = (urlsplit(address).hostname or "").lower()
    hosts = {host, *(state.read(db).get("hosts") or [])}
    if host == "github.com":
        hosts.update(GITHUB_HOSTS)
    return egress.Policy(mode="listed", hosts=frozenset(found.lower() for found in hosts if found))


def _get(db: OrmSession, url: str, limit: int) -> bytes:
    try:
        answer = egress.request(
            _policy(db, url),
            "GET",
            url,
            headers={"Accept": "application/octet-stream, application/json;q=0.9, */*;q=0.5", "User-Agent": "nik"},
            timeout=120,
            max_body=limit,
        )
    except egress.EgressError as error:
        raise CatalogueError(f"The catalogue could not be read: {error}") from None
    if answer.status == 404:
        raise CatalogueError("The catalogue has nothing at this address (404)")
    if answer.status != 200:
        raise CatalogueError(f"The catalogue answered {answer.status}")
    return answer.body


def verify(data: bytes, signature: bytes, key: str) -> None:
    """Raise unless ``signature`` (base64) is the one of ``data`` under the public ``key``."""
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True))
        public.verify(base64.b64decode(signature.strip(), validate=True), data)
    except (binascii.Error, ValueError, InvalidSignature):
        raise CatalogueError(
            "The catalogue is not signed with the key Nik holds for it: nothing of it was read"
        ) from None


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 100_000 else 0


def clean_entry(raw: Any) -> dict[str, Any] | None:
    """One pack of an index, as Nik keeps it; None for an entry that is not one."""
    if not isinstance(raw, dict):
        return None
    try:
        manifest = packs.clean_manifest(raw)
    except packs.PackError:
        return None
    file_name, sha = str(raw.get("file") or ""), str(raw.get("sha256") or "").lower()
    size = raw.get("size")
    if not FILE_RE.match(file_name) or not SHA_RE.match(sha) or not isinstance(size, int):
        return None
    if not 0 < size <= packs.MAX_BYTES:
        return None
    logo = None
    held = raw.get("logo")
    if isinstance(held, dict) and isinstance(held.get("data"), str) and len(held["data"]) <= LOGO_MAX * 2:
        try:
            cleaned, kind = connector_logo.clean(base64.b64decode(held["data"], validate=True))
            if len(cleaned) <= LOGO_MAX:
                logo = {"type": kind, "data": base64.b64encode(cleaned).decode("ascii")}
        except (binascii.Error, ValueError, connector_logo.LogoError):
            logo = None
    contents = raw.get("contents") if isinstance(raw.get("contents"), dict) else {}
    return {
        **manifest,
        "file": file_name,
        "sha256": sha,
        "size": size,
        "contents": {kind: _count(contents.get(kind)) for kind in COUNTED if _count(contents.get(kind))},
        "premium": _count(contents.get("premium")),
        "logo": logo,
    }


def clean_index(data: bytes) -> list[dict[str, Any]]:
    try:
        raw = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise CatalogueError("The index of the catalogue cannot be read") from None
    if not isinstance(raw, dict) or not isinstance(raw.get("packs"), list):
        raise CatalogueError("The index of the catalogue does not list packs")
    found: dict[str, dict[str, Any]] = {}
    for entry in raw["packs"][:ENTRIES_MAX]:
        cleaned = clean_entry(entry)
        if cleaned is not None and cleaned["id"] != packs.BUILTIN_ID:
            found[cleaned["id"]] = cleaned
    return sorted(found.values(), key=lambda entry: (entry["vendor"].lower(), entry["name"].lower()))


def refresh(db: OrmSession) -> dict[str, Any]:
    """Read the catalogue again and keep it (commits). A catalogue that cannot be read, or whose signature
    is not right, leaves what was read before and says why."""
    place = where(db)
    try:
        data = _get(db, place["address"], INDEX_MAX)
        signature = _get(db, place["address"] + ".sig", 4096)
        verify(data, signature, place["key"])
        entries = clean_index(data)
    except CatalogueError as error:
        _keep(db, error=error.message, triedAt=now_iso())
        db.commit()
        raise
    _keep(db, index=entries, fetchedAt=now_iso(), fetchedEpoch=time.time(), error="", triedAt=now_iso())
    db.commit()
    return shown(db)


def _state_of(entry: dict[str, Any], installed: Pack | None) -> dict[str, Any]:
    wanted = re.findall(r"\d+", entry.get("nik") or "")
    too_new = bool(wanted) and tuple(int(part) for part in (wanted + ["0"])[:3]) > packs.NIK_VERSION
    here = packs.version_of(installed.version) if installed is not None else None
    there = packs.version_of(entry["version"]) or (0, 0, 0)
    return {
        "installed": installed.version if installed is not None else None,
        "update": here is not None and there > here,
        "needsNik": entry["nik"][2:] if too_new else "",
    }


def shown(db: OrmSession) -> dict[str, Any]:
    """The catalogue as the page shows it: where it is read from, when, and each pack with what is true of
    it here (installed, a newer version there, for a later Nik)."""
    held, place = _doc(db), where(db)
    installed = {row.id: row for row in packs.installed(db)}
    entries = []
    for entry in held.get("index") or []:
        entries.append({**entry, **_state_of(entry, installed.get(entry["id"]))})
    return {
        "address": place["address"],
        "custom": place["custom"],
        "ownKey": place["ownKey"],
        "fetchedAt": held.get("fetchedAt") or "",
        "error": held.get("error") or "",
        "read": held.get("index") is not None,
        "packs": entries,
    }


def entry_of(db: OrmSession, pack_id: str) -> dict[str, Any]:
    for entry in _doc(db).get("index") or []:
        if entry["id"] == pack_id:
            return entry
    raise CatalogueError("The catalogue has no pack with this id: read it again", 404)


def download(db: OrmSession, pack_id: str) -> bytes:
    """The file of a pack of the catalogue, checked against what the signed index says of it."""
    entry, place = entry_of(db, pack_id), where(db)
    data = _get(db, urljoin(place["address"], entry["file"]), packs.MAX_BYTES + 1)
    if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise CatalogueError("The file of this pack is not the one the catalogue lists: it was not read")
    return data
