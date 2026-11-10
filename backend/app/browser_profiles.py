"""Browser profiles inside an incident document.

Since 2.0.0 each browser holds several profiles::

    data.browser.browsers[<browserId>] = {
        "activeProfile": "<profileId>",
        "profiles": {
            "<profileId>": {"id", "name", "createdAt", "history", "downloads",
                            "bookmarks", "shortcuts", "meta"},
        },
    }

Profiles are keyed by a stable id (renaming does not move data) and ordered by
``createdAt`` (JSONB does not keep key order). Before 2.0.0 a browser held the
artifact lists directly; :func:`normalize_browser_data` moves that legacy shape
into a profile named "Default" with the fixed id ``default``. The same rules
live in ``frontend/src/domain/browserProfiles.js`` for the frontend.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

DEFAULT_PROFILE_ID = "default"
DEFAULT_PROFILE_NAME = "Default"
ARTIFACT_KEYS = ("history", "downloads", "bookmarks", "shortcuts")
# Epoch timestamp for the migrated/implicit "Default" profile so it sorts first.
DEFAULT_PROFILE_CREATED_AT = "1970-01-01T00:00:00.000Z"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_profile(name: str, profile_id: str | None = None, created_at: str | None = None) -> dict:
    """An empty profile."""
    return {
        "id": profile_id or str(uuid.uuid4()),
        "name": name,
        "createdAt": created_at or _now(),
        **{key: [] for key in ARTIFACT_KEYS},
        "meta": {},
    }


def is_legacy_slot(slot) -> bool:
    """True for a pre-2.0.0 browser slot (artifact lists stored directly)."""
    return isinstance(slot, dict) and "profiles" not in slot


def migrate_slot(slot: dict) -> dict:
    """Move a legacy browser slot into a "Default" profile (pure function)."""
    profile = new_profile(DEFAULT_PROFILE_NAME, DEFAULT_PROFILE_ID, DEFAULT_PROFILE_CREATED_AT)
    for key in ARTIFACT_KEYS:
        if isinstance(slot.get(key), list):
            profile[key] = slot[key]
    if isinstance(slot.get("meta"), dict):
        profile["meta"] = slot["meta"]
    return {"activeProfile": DEFAULT_PROFILE_ID, "profiles": {DEFAULT_PROFILE_ID: profile}}


def normalize_browser_data(doc: dict) -> bool:
    """Migrate every legacy browser slot of an incident document in place.

    Returns True when the document changed.
    """
    browsers = ((doc.get("data") or {}).get("browser") or {}).get("browsers")
    if not isinstance(browsers, dict):
        return False
    changed = False
    for browser_id, slot in list(browsers.items()):
        if is_legacy_slot(slot):
            browsers[browser_id] = migrate_slot(slot)
            changed = True
    return changed


def profile_for_upload(browsers: dict, browser_id: str, name: str | None) -> dict:
    """Return the profile named ``name`` (case-insensitive) of a browser, creating
    the browser slot and/or the profile when missing. ``None`` means "Default"."""
    wanted = (name or DEFAULT_PROFILE_NAME).strip() or DEFAULT_PROFILE_NAME
    slot = browsers.get(browser_id)
    if not isinstance(slot, dict):
        slot = {"activeProfile": None, "profiles": {}}
    elif is_legacy_slot(slot):
        slot = migrate_slot(slot)
    browsers[browser_id] = slot
    profiles = slot.setdefault("profiles", {})
    for profile in profiles.values():
        if isinstance(profile, dict) and str(profile.get("name", "")).casefold() == wanted.casefold():
            return profile
    is_default = wanted.casefold() == DEFAULT_PROFILE_NAME.casefold() and DEFAULT_PROFILE_ID not in profiles
    profile = (
        new_profile(DEFAULT_PROFILE_NAME, DEFAULT_PROFILE_ID, DEFAULT_PROFILE_CREATED_AT)
        if is_default
        else new_profile(wanted)
    )
    profiles[profile["id"]] = profile
    if not slot.get("activeProfile") or slot["activeProfile"] not in profiles:
        slot["activeProfile"] = profile["id"]
    return profile
