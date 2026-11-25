"""The files a connector's command carries, on Nik's side.

A command of a connector may give a file (``answer: file``: a sample, a
capture, a screenshot, an archive) or send one Nik holds (``files``,
``body_file``: a sample submitted to a sandbox). The runtime moves the bytes;
what happens to them here is decided in this module, for one step of a run:

- **A file that comes in** becomes a file artifact, analysed as an uploaded
  file is, in the incident the run works on when there is one. It is stored
  as it came: an archive the vendor protects with a password stays an
  archive, nothing is unpacked. What is over the limit of an upload is not
  kept, and the step says so. When the command says the file is an archive
  to unpack (``unpack``), each file inside it is kept as an artifact of its
  own, taken out of the archive (``unpack.py``): read in memory, never run,
  never written anywhere but the store. An archive that cannot be unpacked
  (a wrong password, not an archive, too much inside) is kept all the same,
  alone, and the step fails naming it.
- **A file that goes out** is one of the store, named by its artifact id
  (``file-<sha256>``) or its SHA-256. Before it leaves, the data guard judges
  it as it judges an attachment of a message (``outbound.guarded_message``): by
  what it is, never by opening it. One that is not in the store, cannot be
  read or is over the limit is refused whatever the playbook opened.

The worker that runs playbooks reads the store read-only: what it keeps is
handed to the API process (``artifact_jobs.Keeper``), and the step waits for
it. A server whose playbooks run in the API process writes at once.

The store holds live malware. A file is written under its SHA-256, read as
bytes, and never opened by the program it is meant for.
"""

from __future__ import annotations

from typing import Any

from .. import archive, artifact_jobs, artifacts, unpack
from ..core import audit
from ..core.config import settings
from ..core.models import Artifact, Incident, Sample
from ..core.permissions import SYSTEM_USER
from ..malware.samples import is_sha256, read_sample
from . import outbound, triggers
from .actions import Call
from .connector_runtime import CommandError


class Store:
    """What the runtime of a connector asks of Nik's store, for one step of a run."""

    def __init__(
        self, call: Call, connector_name: str, command: str, decided: dict, keeper: artifact_jobs.Keeper | None = None
    ):
        self.call = call
        self.keeper = keeper or artifact_jobs.Keeper.of(call, SYSTEM_USER)
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
    def keep(self, data: bytes, name: str, kind: str, unpack_as: dict[str, Any] | None = None) -> dict[str, Any]:
        """Keep the bytes a command received as a file artifact, and say what it is: ``name``, ``type``,
        ``size``, ``sha256``, ``artifact`` and whether an incident references it (``linked``).

        ``unpack_as`` (``{format, password}``) says the file is an archive to unpack: the archive is
        kept as it came, each file inside it as an artifact of its own, and what describes them is
        given too: ``files`` (each ``name``, ``type``, ``size``, ``sha256``, ``artifact``), ``count``
        and ``skipped`` (each ``name`` and ``reason``). An archive that cannot be unpacked (not one,
        a password that does not open it, more inside than an archive may hold) is evidence all the
        same: it is kept as a file that is not unpacked would be, nothing inside it is, and the step
        fails with a sentence that says why and names the artifact (``CommandError.kept``)."""
        call, db, keeper = self.call, self.call.db, self.keeper
        if len(data) > self.limit:
            raise CommandError(f"The file is larger than the {self.limit_mb} MB limit of a sample: it was not kept")
        incident_id = str(call.run.incident_id or "")
        held = db.get(Incident, incident_id) if incident_id else None
        if held is None:
            incident_id = ""
        elif held.archived_at:
            raise CommandError(archive.SENTENCE)
        origin = f"{self.connector_name} ({self.command})"
        playbook = (call.run.trigger or {}).get("playbook", "")
        who = f", approved by {call.approved_by}" if call.approved_by else ""
        found = None
        if unpack_as is not None:
            try:
                found = unpack.members(
                    data, str(unpack_as.get("password") or ""), limit=self.limit, fmt=str(unpack_as.get("format"))
                )
            except unpack.UnpackError as error:
                try:
                    kept = keeper.file(data, name, incident_id, origin)
                except artifact_jobs.JobError as unkept:
                    raise CommandError(f"{error.message}. The archive was not kept either: {unkept}") from None
                keeper.audit(
                    "connector.file.keep",
                    f"Kept the archive {name or kept['sha256']} ({kept['sha256'][:12]}…) that {origin} gave, "
                    f'not unpacked (playbook "{playbook}", run {call.run.id}{who})',
                    incident_id,
                )
                if incident_id and keeper.direct:
                    triggers.incident_changed(db, db.get(Incident, incident_id), "incident.updated", ["data"])
                failure = CommandError(
                    f"{error.message}. The archive was kept as {kept['artifact']}", retry=False, sent=True
                )
                failure.kept = kept["artifact"]  # the step fails once the archive is in the store
                raise failure from None
        try:
            kept = keeper.file(data, name, incident_id, origin)
            files = []
            for member in found.members if found is not None else ():
                inside = keeper.file(
                    member.data,
                    unpack.file_name(member.name),
                    incident_id,
                    f"{name or kept['sha256'][:12]} ({origin})",
                    parent=(kept["artifact"], "unpacked"),
                )
                files.append(
                    {"name": member.name, **{key: inside[key] for key in ("type", "size", "sha256", "artifact")}}
                )
        except artifact_jobs.JobError as error:
            raise CommandError(f"The file was not kept: {error}") from None
        inside = f" and the {len(files)} file(s) inside it" if found is not None else ""
        keeper.audit(
            "connector.file.keep",
            f"Kept the file {name or kept['sha256']} ({kept['sha256'][:12]}…){inside} that {origin} gave"
            f' (playbook "{playbook}", run {call.run.id}{who})',
            incident_id,
        )
        if incident_id and keeper.direct:
            triggers.incident_changed(db, db.get(Incident, incident_id), "incident.updated", ["data"])
        described = {
            "name": name or kept["sha256"],
            "type": kind or kept["type"],
            "size": kept["size"],
            "sha256": kept["sha256"],
            "artifact": kept["artifact"],
            "linked": kept["linked"],
        }
        if found is not None:
            described.update(files=files, count=len(files), skipped=found.skipped)
        return described

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
        if not found:
            return True
        return outbound.guarded_message(self.call, {}, found, self.decided)[1]

    def read(self, sha256: str) -> bytes:
        """The bytes of a file of the store, as they are. Raises when they cannot be read."""
        try:
            data = read_sample(sha256)
        except (OSError, ValueError) as error:
            from ..core import store
            from ..store_handover import NotServed

            if isinstance(error, (store.SealError, NotServed)):
                raise CommandError(str(error), retry=False) from None
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
