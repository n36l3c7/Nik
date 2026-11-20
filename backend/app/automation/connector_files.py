"""The files a connector's command carries, on Nik's side.

A command of a connector may give a file (``answer: file``: a sample, a
capture, a screenshot, an archive) or send one Nik holds (``files``,
``body_file``: a sample submitted to a sandbox). The runtime moves the bytes;
what happens to them here is decided in this module, for one step of a run:

- **A file that comes in** becomes a file artifact, analysed as an uploaded
  file is, in the incident the run works on when there is one. It is stored
  as it came: an archive the vendor protects with a password stays an
  archive, nothing is unpacked. What is over the limit of an upload is not
  kept, and the step says so.
- **A file that goes out** is one of the store, named by its artifact id
  (``file-<sha256>``) or its SHA-256. Before it leaves, the data guard judges
  it as it judges an attachment of a message (``outbound.guarded_files``): by
  what it is, never by opening it. One that is not in the store, cannot be
  read or is over the limit is refused whatever the playbook opened.

The store holds live malware. A file is written under its SHA-256, read as
bytes, and never opened by the program it is meant for.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from .. import artifacts
from ..core import audit
from ..core.config import settings
from ..core.locking import lock_incident
from ..core.models import Artifact, Sample
from ..core.permissions import SYSTEM_USER
from ..malware.samples import is_sha256, read_sample
from . import outbound, triggers
from .actions import Call
from .connector_runtime import CommandError


class Store:
    """What the runtime of a connector asks of Nik's store, for one step of a run."""

    def __init__(self, call: Call, connector_name: str, command: str, decided: dict):
        self.call = call
        self.connector_name = connector_name
        self.command = command
        self.decided = decided  # what the guard said of the arguments: what it says of a file is added

    @property
    def limit_mb(self) -> int:
        return settings.SAMPLE_MAX_MB

    @property
    def limit(self) -> int:
        """The size above which nothing is kept nor sent: the one of an upload."""
        return settings.SAMPLE_MAX_MB * 1024 * 1024

    # ------------------------------------------------------------------ in --
    def keep(self, data: bytes, name: str, kind: str) -> dict[str, Any]:
        """Keep the bytes a command received as a file artifact, and say what it is: ``name``, ``type``,
        ``size``, ``sha256``, ``artifact`` and whether an incident references it (``linked``)."""
        from ..routers import samples as sample_routes

        call, db = self.call, self.call.db
        if len(data) > self.limit:
            raise CommandError(f"The file is larger than the {self.limit_mb} MB limit of a sample: it was not kept")
        incident_id = str(call.run.incident_id or "")
        incident = lock_incident(db, incident_id) if incident_id else None
        origin = f"{self.connector_name} ({self.command})"
        try:
            row, _ref = sample_routes.keep_sample(db, incident, data, name, SYSTEM_USER, origin)
        except HTTPException as error:
            raise CommandError(f"The file was not kept: {error.detail}") from None
        artifact = artifacts.artifact_id("file", row.sha256)
        playbook = (call.run.trigger or {}).get("playbook", "")
        who = f", approved by {call.approved_by}" if call.approved_by else ""
        audit.record(
            db,
            SYSTEM_USER,
            "connector.file.keep",
            f"Kept the file {name or row.sha256} ({row.sha256[:12]}…) that {origin} gave"
            f' (playbook "{playbook}", run {call.run.id}{who})',
            incident,
        )
        if incident is not None:
            triggers.incident_changed(db, incident, "incident.updated", ["data"])
        return {
            "name": name or row.sha256,
            "type": kind or row.type_label or "",
            "size": row.size,
            "sha256": row.sha256,
            "artifact": artifact,
            "linked": incident is not None,
        }

    # ----------------------------------------------------------------- out --
    def describe(self, wanted: Any) -> dict[str, Any]:
        """The file an argument names (``file-<sha256>`` or the SHA-256 alone): its name, size and hash.
        Raises when it is not a file of the store, or one that cannot leave whatever is open."""
        text = str(wanted or "").strip().lower()
        sha256 = text.removeprefix("file-")
        if not is_sha256(sha256):
            raise CommandError(
                "The file to send is named by its artifact (file-…) or its SHA-256: this is neither", retry=False
            )
        row = self.call.db.get(Sample, sha256)
        if row is None:
            raise CommandError(f"The file {sha256[:12]}… is not in the store", retry=False)
        if row.size > self.limit:
            raise CommandError(
                f"The file {sha256[:12]}… is larger than the {self.limit_mb} MB limit of a sample: it is not sent",
                retry=False,
            )
        artifact = self.call.db.get(Artifact, artifacts.artifact_id("file", sha256))
        return {"name": (artifact.name if artifact is not None else "") or sha256, "size": row.size, "sha256": sha256}

    def judge(self, found: list[dict[str, Any]]) -> bool:
        """Whether the files may leave, as the guard judges the attachments of a message. Held, it raises
        and the step fails; False on a node that drops what is held."""
        return outbound.guarded_files(self.call, found, self.decided)

    def read(self, sha256: str) -> bytes:
        """The bytes of a file of the store, as they are. Raises when they cannot be read."""
        try:
            data = read_sample(sha256)
        except (OSError, ValueError):
            raise CommandError(f"The file {sha256[:12]}… could not be read from the store", retry=False) from None
        if len(data) > self.limit:
            raise CommandError(f"The file {sha256[:12]}… is larger than the limit of a sample", retry=False)
        playbook = (self.call.run.trigger or {}).get("playbook", "")
        who = f", approved by {self.call.approved_by}" if self.call.approved_by else ""
        audit.record(
            self.call.db,
            SYSTEM_USER,
            "connector.file.send",
            f"Sent the file {sha256[:12]}… to {self.connector_name} ({self.command})"
            f' (playbook "{playbook}", run {self.call.run.id}{who})',
        )
        return data
