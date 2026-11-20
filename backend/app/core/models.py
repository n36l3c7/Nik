"""SQLAlchemy ORM models.

Mirrors the DB tables described in the spec. The portable ``JSON`` column type
maps to ``JSONB`` on PostgreSQL and to a TEXT-backed JSON on SQLite, so the same
models run in dev and prod. Timestamps are stored as ISO-8601 strings to match
the frontend data shape exactly.
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    event,
    false,
    func,
    select,
    text,
    true,
)
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from .db import Base


class User(Base):
    """Application user (analyst or admin)."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    # Stored as provided; case-insensitive matching is done at query time.
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    # What the account may do: a list of role names (core/permissions.py).
    roles: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Raised each time the roles change. The roles themselves are read on every
    # request; the counter is for whatever keeps a copy of them (a long-lived
    # worker, a client) to notice that its copy is old.
    session_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # A disabled account keeps its history but cannot sign in.
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    # Wrong passwords in a row, and until when the account is locked because of them.
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    locked_until: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class Session(Base):
    """Server-side session, referenced by the httpOnly cookie token."""

    __tablename__ = "sessions"

    token: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[str] = mapped_column(String, nullable=False)


# JSONB on PostgreSQL, so that a field can be searched through an index; plain JSON elsewhere.
FIELDS_JSON = JSON().with_variant(JSONB(), "postgresql")


class Incident(Base):
    """Incident document store.

    The full frontend incident object lives in ``doc``; a handful of scalar
    fields are duplicated into columns purely for listing/sorting.
    """

    __tablename__ = "incidents"

    # The uuid of the incident: its address, its key everywhere in the database and the API.
    id: Mapped[str] = mapped_column(String, primary_key=True)
    # The number people call it by (#00042): given when it is created, never used twice.
    number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    name: Mapped[str] = mapped_column(String, nullable=False, default="")
    host: Mapped[str] = mapped_column(String, nullable=False, default="")
    username: Mapped[str] = mapped_column(String, nullable=False, default="")
    os: Mapped[str] = mapped_column(String, nullable=False, default="", server_default="")
    # Ticket of the organisation's tracker (first part of the name) and the
    # analysts' severity tag (low/medium/high/critical, or empty).
    ticket_id: Mapped[str] = mapped_column(String, nullable=False, default="", server_default="")
    severity: Mapped[str] = mapped_column(String, nullable=False, default="", server_default="")
    # Where the work stands (open / in_progress / closed) and the analyst who has it.
    status: Mapped[str] = mapped_column(String, nullable=False, default="open", server_default="open")
    assignee: Mapped[str] = mapped_column(String, nullable=False, default="", server_default="")
    # The incident holds analysed e-mails (data.mail.messages): the sidebar
    # shows a mail icon without reading documents.
    has_mail: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    updated_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    # Version of the document: one more at every write, whoever makes it. It is
    # the incident's ETag, so a client that edits a stale copy is told (412).
    rev: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    doc: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # The type of the incident (``incident_types``); none means "Unclassified".
    type_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    # The custom fields of the registry (``fields``): {name: value}, validated on every write by
    # fields_service, the only writer. ``fields_rev`` is one more at each of those writes.
    fields: Mapped[dict[str, Any]] = mapped_column(FIELDS_JSON, nullable=False, default=dict, server_default="{}")
    fields_rev: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    closed_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    close_reason: Mapped[str] = mapped_column(String, nullable=False, default="", server_default="")
    close_notes: Mapped[str] = mapped_column(String, nullable=False, default="", server_default="")
    occurred_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Where it came from when a connector brought it in (4.5), and how it is kept in step.
    source_connection_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    source_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    mirror: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index(
            "uq_incidents_source",
            "source_connection_id",
            "source_id",
            unique=True,
            sqlite_where=text("source_id IS NOT NULL"),
            postgresql_where=text("source_id IS NOT NULL"),
        ),
        Index("ix_incidents_status", "status"),
        Index("uq_incidents_number", "number", unique=True),
    )


class Sequence(Base):
    """A counter that only goes up: the last number given to an incident (``name`` "incidents")."""

    __tablename__ = "sequences"

    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


def take_incident_number(connection) -> int:
    """The next number of an incident. The row of the counter is written first, so two incidents
    created at once wait for each other; a number given to an incident that was then deleted is
    not given again."""
    counter = Sequence.__table__
    incidents = Incident.__table__
    moved = connection.execute(counter.update().where(counter.c.name == "incidents").values(value=counter.c.value + 1))
    if moved.rowcount:
        return int(connection.scalar(select(counter.c.value).where(counter.c.name == "incidents")))
    # No counter yet (a database made from the models): start after the highest number there is.
    first = int(connection.scalar(select(func.max(incidents.c.number))) or 0) + 1
    connection.execute(counter.insert().values(name="incidents", value=first))
    return first


@event.listens_for(Incident, "before_insert")
def _number_incident(_mapper, connection, target: Incident) -> None:
    """Every incident gets its number as it is stored, whoever creates it. One given a number
    (a backup being restored) keeps it, and the counter is moved past it."""
    if target.number is None:
        target.number = take_incident_number(connection)
        return
    counter = Sequence.__table__
    held = connection.scalar(select(counter.c.value).where(counter.c.name == "incidents"))
    if held is None:
        connection.execute(counter.insert().values(name="incidents", value=int(target.number)))
    elif held < target.number:
        connection.execute(counter.update().where(counter.c.name == "incidents").values(value=int(target.number)))


@event.listens_for(Incident, "before_update")
def _bump_incident_revision(_mapper, _connection, target: Incident) -> None:
    """Every write of the document is a new revision, wherever it comes from."""
    if sa_inspect(target).attrs.doc.history.has_changes():
        target.rev = (target.rev or 0) + 1


class IocEntry(Base):
    """One indicator seen in one incident (see ``iocs.py``).

    Rebuilt from the incident document whenever its data changes; looked up by
    ``(type, value)`` to find every incident an indicator appears in.
    """

    __tablename__ = "ioc_index"
    __table_args__ = (Index("ix_ioc_index_type_value", "type", "value"),)

    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    type: Mapped[str] = mapped_column(String(16), primary_key=True)
    value: Mapped[str] = mapped_column(String(1024), primary_key=True)
    sources: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_seen: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)


class AuditEntry(Base):
    """Immutable audit-log entry; actor is stamped server-side from the session."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    at: Mapped[str] = mapped_column(String, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[str] = mapped_column(String, nullable=False, default="")
    incident_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    incident_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class Sample(Base):
    """A malware sample: the file sits in the sample store, named by SHA-256.

    One row per distinct file, whatever the number of incidents that reference
    it (the references live in each incident document under
    ``data.malware.samples``). ``analysis`` holds the static analysis result
    from ``parsing.malware.analyze``.
    """

    __tablename__ = "samples"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    type_id: Mapped[str] = mapped_column(String, nullable=False, default="unknown")
    type_label: Mapped[str] = mapped_column(String, nullable=False, default="")
    entropy: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    analysis: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class Mail(Base):
    """An analysed e-mail (``.eml`` / ``.msg``): the file sits in the sample
    store as ``<sha256>.mail``; ``analysis`` is ``mail.analyze.analyse_mail``'s
    result. One row per distinct file; incidents reference it under
    ``data.mail.messages``."""

    __tablename__ = "mails"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    format: Mapped[str] = mapped_column(String, nullable=False, default="eml")
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False, default="")
    sender: Mapped[str] = mapped_column(String, nullable=False, default="")
    sent_at: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    verdict: Mapped[str] = mapped_column(String, nullable=False, default="clean")
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    analysis: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class NetworkCapture(Base):
    """A packet capture: a pcap / pcapng the analyst uploaded,
    or the network log of an isolated browser session rebuilt as pcapng
    (``kind``). The file sits in ``SAMPLE_STORE/_captures/<id>/``; ``summary``
    is the packet capture worker's analysis; ``keylog`` an optional TLS key
    log, encrypted (``vault.py``). Referenced by the incident under
    ``data.network.captures``."""

    __tablename__ = "network_captures"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    # The incident that holds the capture; None for a capture analysed on its own.
    incident_id: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String, nullable=False, default="pcap")  # pcap | browser
    file_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # live (browser session open) | indexing | ready | error | stored (no worker)
    status: Mapped[str] = mapped_column(String, nullable=False, default="indexing")
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_ms: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_ms: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    keylog: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class UrlScan(Base):
    """A URL visited by the isolated browser on the analyst's behalf.

    One row per distinct address (``id`` is the first 32 hex characters of the
    SHA-256 of the normalised URL); scanning it again replaces the result.
    ``result`` holds what the visit found: the final address, the redirect
    chain, the page's forms, the findings behind the verdict. The screenshot
    sits in ``SAMPLE_STORE/_urls/<id>.jpg``; ``capture_id`` is the network
    capture of the visit (an isolated browser session).
    """

    __tablename__ = "url_scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    url: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False, default="")
    # queued | running | done | error
    status: Mapped[str] = mapped_column(String, nullable=False, default="queued")
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    verdict: Mapped[str] = mapped_column(String, nullable=False, default="")
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    scanned_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    capture_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class Artifact(Base):
    """Something analysed on its own: a file, an e-mail, a packet capture or a URL.

    The registry over ``samples``, ``mails``, ``network_captures`` and
    ``url_scans``: one row per analysed object, whether or not an incident
    references it. ``id`` is ``<kind>-<ref>`` (``file-<sha256>``,
    ``mail-<sha256>``, ``pcap-<capture id>``, ``url-<scan id>``).
    ``verdict``, ``score`` and ``detail`` are a copy of what the list shows,
    refreshed when the object is analysed again.
    """

    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[str] = mapped_column(String, nullable=False, index=True)  # file | mail | pcap | url
    ref: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False, default="")
    verdict: Mapped[str] = mapped_column(String, nullable=False, default="")
    score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(String, nullable=False, default="")
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    # The day it is deleted on (YYYY-MM-DD), when someone gave it one: there is no default.
    expires_at: Mapped[Optional[str]] = mapped_column(String(10), nullable=True, index=True)
    # Why its date was moved ("put off: an open incident references it"), and the date its going
    # was announced for (artifact_expiry.py).
    expiry_note: Mapped[str] = mapped_column(String(400), nullable=False, default="", server_default="")
    expiry_noticed: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)


class ArtifactLink(Base):
    """An incident references the artifact. An index of the incident documents,
    rebuilt each time an incident is saved (``artifacts.sync_links``)."""

    __tablename__ = "artifact_links"

    artifact_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("artifacts.id", ondelete="CASCADE"), primary_key=True
    )
    incident_id: Mapped[str] = mapped_column(
        String, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True, index=True
    )


class ArtifactRelation(Base):
    """Where an artifact comes from: ``child`` was taken out of ``parent``
    (``attachment`` of an e-mail, ``extracted`` from a capture, ``session``
    of an isolated browser opened from an e-mail)."""

    __tablename__ = "artifact_relations"

    parent_id: Mapped[str] = mapped_column(String(80), ForeignKey("artifacts.id", ondelete="CASCADE"), primary_key=True)
    child_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("artifacts.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    relation: Mapped[str] = mapped_column(String, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)


class IntegrationKey(Base):
    """One API key of a threat-intelligence source as the look-ups kept it before 6.5, encrypted
    (``vault.py``). ``provider`` is the name the source had then.

    Nothing writes here any more: a source is a connector, and its keys are those of an instance of
    it. A row stays until an instance of each connector it belongs to holds the key
    (``enrichment/old_keys.py``); one the vendor had refused (``rejected``) stays until an
    administrator removes it.
    """

    __tablename__ = "integration_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String, nullable=False, index=True)
    secret: Mapped[str] = mapped_column(Text, nullable=False)
    hint: Mapped[str] = mapped_column(String, nullable=False, default="")  # last 4 characters
    label: Mapped[str] = mapped_column(String, nullable=False, default="")
    # ok | rejected
    status: Mapped[str] = mapped_column(String, nullable=False, default="ok")
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class Enrichment(Base):
    """One source's latest answer about one indicator (``enrichment/``),
    valid for the retention of its type (Settings -> Threat intelligence).
    ``provider`` is the id of the source's connector; ``data`` the outputs of its
    reputation command as the page gets them, ``raw`` all of them, for the JSON download."""

    __tablename__ = "ioc_enrichment"

    type: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String, primary_key=True)
    # done | error | running
    status: Mapped[str] = mapped_column(String, nullable=False, default="running")
    # malicious | suspicious | harmless | unknown
    verdict: Mapped[str] = mapped_column(String, nullable=False, default="unknown")
    summary: Mapped[str] = mapped_column(String, nullable=False, default="")
    link: Mapped[str] = mapped_column(String, nullable=False, default="")
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    checked_at: Mapped[str] = mapped_column(String, nullable=False)
    raw: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    __table_args__ = (Index("ix_ioc_enrichment_value", "value"),)


class EnrichmentHistory(Base):
    """A source's earlier answers about an indicator: verdict and summary
    of each check, the last few kept, to see a reputation change over time."""

    __tablename__ = "ioc_enrichment_history"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    type: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    verdict: Mapped[str] = mapped_column(String, nullable=False, default="unknown")
    summary: Mapped[str] = mapped_column(String, nullable=False, default="")
    checked_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (Index("ix_ioc_enrichment_history_value", "value", "type"),)


class Lease(Base):
    """A lease held by one API process at a time (the enrichment worker)."""

    __tablename__ = "leases"

    name: Mapped[str] = mapped_column(String, primary_key=True)
    holder: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False)


class Backup(Base):
    """A backup Nik took, or is taking (app/backups).

    ``id`` is the name of its file in the backup directory, without the
    suffix. ``kind`` is ``full`` (the database and the store of files) or
    ``upgrade`` (the database alone, taken before a release migrated it).
    The file is the backup; this row is what Nik knows about it: how its
    restore test went, and where its copy off the server stands. The API
    process writes every column but ``offsite``, which belongs to the process
    that sends the copies, so the two never overwrite each other.
    """

    __tablename__ = "backups"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="full")
    # queued | running | done | failed
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    finished_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    nik_version: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    revision: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    # What it is, in words: "Before the upgrade from 6.6.0 to 6.7.0".
    label: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    requested_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    # What it holds, from its manifest: rows, files, bytes, how its key is derived.
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # "" | queued | running | passed | failed
    verify_state: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    verified_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # What the restore test checked, or why it failed.
    verify: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # Whether its file is in the backup directory.
    local: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    # "" (no copy asked for) | pending | copied | failed | delete (the copy is to be removed)
    offsite_state: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    offsite: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class SampleCode(Base):
    """Disassembly of a sample by the analyzer worker (rizin): one row per sample.

    ``status`` is queued → running → done | error. ``summary`` holds the
    engine, binary info, the function list with their calls and the
    decompilation stats; each function's control-flow graph and pseudo-C are
    rows of ``sample_functions``, fetched one function at a time by the UI.
    """

    __tablename__ = "sample_code"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="queued")
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    requested_at: Mapped[str] = mapped_column(String, nullable=False)
    requested_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    finished_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class SampleFunction(Base):
    """One function of a disassembled sample: its control-flow graph and, once
    decompiled (up front or on demand), its pseudo-C.

    One row per function keeps opening a function cheap on large binaries,
    whose graphs add up to tens of megabytes.
    """

    __tablename__ = "sample_functions"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    addr: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    cfg: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON(none_as_null=True), nullable=True)
    decompiled: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON(none_as_null=True), nullable=True)


class CapaRule(Base):
    """A capa rule (YAML) added by an admin, matched with capa's bundled rules when enabled.

    ``name``, ``namespace`` and ``scope`` come from the rule itself, as the capa
    worker parsed it when the rule was validated.
    """

    __tablename__ = "capa_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    namespace: Mapped[str] = mapped_column(String, nullable=False, default="")
    scope: Mapped[str] = mapped_column(String, nullable=False, default="")
    source: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False, default="")


class SampleCapa(Base):
    """capa's capabilities of a sample, from the capa worker: one row per sample.

    ``status`` is queued → running → done | error | unsupported (a file type
    capa does not analyse). ``result`` holds the reduced report: engine,
    format, and the capabilities with their ATT&CK / MBC mappings and
    addresses.
    """

    __tablename__ = "sample_capa"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="queued")
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    requested_at: Mapped[str] = mapped_column(String, nullable=False)
    requested_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    started_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    finished_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class FunctionAnnotation(Base):
    """An analyst's name and comment for one function of a sample.

    Annotations belong to the sample (by SHA-256), not to an incident, so every
    incident holding the same file sees them. They are removed with the sample.
    """

    __tablename__ = "function_annotations"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    addr: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class FlirtSignature(Base):
    """A FLIRT signature file (.sig or .pat) uploaded by an admin.

    The file lives in the sample store under ``_flirt/<id>.<kind>``; enabled
    signatures are applied by the analyzer worker on top of rizin's bundled
    ones, so library functions they match are recognised and named.
    """

    __tablename__ = "flirt_signatures"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    file_name: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False, default="")


class YaraRule(Base):
    """A YARA rule added by an admin; compiled with the built-in rules when enabled."""

    __tablename__ = "yara_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False, default="")


class Setting(Base):
    """Global shared settings (keywords + business hours). Single row, id=1."""

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    doc: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class Job(Base):
    """An async background job (currently: server-side artifact upload parsing).

    Status flow: queued → running → done | error. ``result_json`` holds the
    endpoint's normal response on success; ``error`` a message on failure.
    """

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="queued")
    incident_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    result_json: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class Webhook(Base):
    """An outbound webhook subscription. Deliveries are signed with ``secret``
    (HMAC-SHA256) so the receiver can verify authenticity. ``events`` is a
    comma-separated list of event names."""

    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    url: Mapped[str] = mapped_column(String, nullable=False)
    secret: Mapped[str] = mapped_column(String, nullable=False)
    events: Mapped[str] = mapped_column(String, nullable=False, default="")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class IdempotencyRecord(Base):
    """Stored response for a processed ``Idempotency-Key`` so a retried POST
    returns the same result instead of acting twice."""

    __tablename__ = "idempotency_keys"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_json: Mapped[str] = mapped_column(String, nullable=False)


class ApiKey(Base):
    """An API key for external, browser-less access.

    Only the SHA-256 ``key_hash`` is stored; the plaintext key is shown to the
    admin exactly once at creation. ``prefix`` is the first few characters
    (safe to display) so a key can be recognised in listings.

    Permissions are set by the admin at creation and tied to the key:
    - ``roles``  a list of role names (core/permissions.py), as on an account.
    - ``expires_at`` optional ISO timestamp after which the key is rejected.

    A revoked key has a non-null ``revoked_at`` and is rejected.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    label: Mapped[str] = mapped_column(String, nullable=False)
    prefix: Mapped[str] = mapped_column(String, nullable=False)
    key_hash: Mapped[str] = mapped_column(String, nullable=False)
    roles: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    expires_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_used_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    revoked_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class IocRecord(Base):
    """An indicator an analyst added to the library, by hand or from a file.

    Indicators seen in incidents live in ``ioc_index``; this table holds the
    ones kept on their own, and what an analyst wrote about any indicator
    (tags, a note, a TLP, a date after which it is no longer current).
    """

    __tablename__ = "iocs"

    type: Mapped[str] = mapped_column(String(16), primary_key=True)
    value: Mapped[str] = mapped_column(String(1024), primary_key=True)
    origin: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")  # manual | import
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    note: Mapped[str] = mapped_column(String, nullable=False, default="")
    tlp: Mapped[str] = mapped_column(String(8), nullable=False, default="amber")
    expires_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # YYYY-MM-DD
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class IocList(Base):
    """A named group of indicators. ``watch`` raises an alert when an incident
    comes to hold one of them."""

    __tablename__ = "ioc_lists"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    tlp: Mapped[str] = mapped_column(String(8), nullable=False, default="amber")
    watch: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class IocListItem(Base):
    """An indicator is in a list. The same indicator can be in several."""

    __tablename__ = "ioc_list_items"
    __table_args__ = (Index("ix_ioc_list_items_type_value", "type", "value"),)

    list_id: Mapped[str] = mapped_column(String, ForeignKey("ioc_lists.id", ondelete="CASCADE"), primary_key=True)
    type: Mapped[str] = mapped_column(String(16), primary_key=True)
    value: Mapped[str] = mapped_column(String(1024), primary_key=True)
    added_at: Mapped[str] = mapped_column(String, nullable=False)
    added_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class IocCheck(Base):
    """A bulk reputation check, worked through by the enrichment worker.

    ``pending`` holds what is left: ``[type, value, [source ids]]``. The
    status is ``running``, ``waiting`` (every source left has used its quota:
    it goes on by itself when one resets), ``done`` or ``stopped``.
    """

    __tablename__ = "ioc_checks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    label: Mapped[str] = mapped_column(String, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running", index=True)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    message: Mapped[str] = mapped_column(String, nullable=False, default="")
    pending: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    items: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # every [type, value] asked for
    # A check of a whole watch list: the list, and the verdict of each indicator as the check started
    # ({"type|value": verdict}), until the history of the list is written (ioc_history.py).
    list_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    baseline: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class IocAlert(Base):
    """An incident came to hold an indicator of a watched list."""

    __tablename__ = "ioc_alerts"
    __table_args__ = (Index("ix_ioc_alerts_at", "at"),)

    id: Mapped[str] = mapped_column(String, primary_key=True)
    at: Mapped[str] = mapped_column(String, nullable=False)
    list_id: Mapped[str] = mapped_column(String, ForeignKey("ioc_lists.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    seen: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())


class Mailbox(Base):
    """A file of many e-mails (mbox, a Maildir archive, an Outlook PST) kept
    as one artifact. Its messages are indexed in ``mailbox_messages``; those
    an analyst imports become e-mail artifacts of their own."""

    __tablename__ = "mailboxes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    file_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    format: Mapped[str] = mapped_column(String(16), nullable=False, default="mbox")  # mbox | maildir | pst
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # indexing | ready | importing | error
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="indexing")
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class MailboxMessage(Base):
    """One message of a mailbox: where it is in the stored file, its headers,
    the message it answers (``parent``) and its conversation (``thread``)."""

    __tablename__ = "mailbox_messages"
    __table_args__ = (Index("ix_mailbox_messages_sha256", "sha256"),)

    mailbox_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("mailboxes.id", ondelete="CASCADE"), primary_key=True
    )
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    message_id: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    parent: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    thread: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicate_of: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    subject: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    sender: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    recipients: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    date_ms: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    attachments: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())


# --------------------------------------------------------------------------- #
# Automation (app/automation): playbooks, scripts, runs                       #
# --------------------------------------------------------------------------- #
class Playbook(Base):
    """A playbook: a graph of nodes that a trigger starts.

    Every save is a version (``playbook_versions``); ``draft`` is the canvas
    as it is being edited, which may not be valid yet. What the playbook may
    reach and send is set on the playbook, not on its nodes: ``egress_mode``
    (the hosts in ``egress_hosts`` and those of its connections, or any) and
    ``data_allow`` (the classes of data opened for it, see automation/guard.py).
    """

    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    current_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    draft: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    egress_mode: Mapped[str] = mapped_column(String(8), nullable=False, default="listed")  # listed | any
    egress_hosts: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    data_allow: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    max_runs_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    one_per_object: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)
    approval_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    # The address a request from outside starts the playbook at: the SHA-256 of its token (never the token).
    hook_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, unique=True)
    hook_created_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class PlaygroundEntry(Base):
    """A line of somebody's Playground: a command typed with no incident, or what it gave (5.3).

    ``owner`` is who typed it: a Playground is each person's own. ``parent_id`` puts a result
    under its command.
    """

    __tablename__ = "playground_entries"
    __table_args__ = (Index("ix_playground_owner_at", "owner", "at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    at: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String(12), nullable=False, default="command")
    body: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    run_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    step_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    parent_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)


class PlaybookBranch(Base):
    """A copy of a playbook someone works on beside the version in use (5.2).

    Its graph need not be valid while it is edited. ``base_version`` is the version of the
    playbook it was made from, or last pushed over: when the playbook has moved on since, a push
    says so before it overwrites. Seen by whoever may edit playbooks; changed by its author.
    """

    __tablename__ = "playbook_branches"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    playbook_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    graph: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    base_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")

    __table_args__ = (UniqueConstraint("playbook_id", "name", name="uq_playbook_branches_name"),)


class PlaybookVersion(Base):
    """A saved, valid graph of a playbook. A run finishes with the version it started with."""

    __tablename__ = "playbook_versions"

    playbook_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("playbooks.id", ondelete="CASCADE"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    graph: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    note: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class Script(Base):
    """A script of the library: Python with typed arguments and outputs, run in
    the sandbox. It is in the library once a version with a passing test exists."""

    __tablename__ = "scripts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    current_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    draft: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class ScriptVersion(Base):
    __tablename__ = "script_versions"

    script_id: Mapped[str] = mapped_column(String(32), ForeignKey("scripts.id", ondelete="CASCADE"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(Text, nullable=False)
    arguments: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    outputs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    test: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    test_result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class AutomationEvent(Base):
    """The outbox of what happened in Nik, written in the transaction of the
    change itself; the automation worker turns the events into runs."""

    __tablename__ = "automation_events"
    __table_args__ = (Index("ix_automation_events_pending", "done", "created_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    object_kind: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    object_id: Mapped[str] = mapped_column(String(1100), nullable=False, default="")
    # {"data": the payload, "classes": {path: [class]}, "caused_by_run", "depth"}
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    claimed_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    done: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())


class Run(Base):
    """One execution of a version of a playbook: queued → running ⇄ waiting → done | failed | stopped."""

    __tablename__ = "runs"
    __table_args__ = (
        Index("ix_runs_playbook", "playbook_id", "started_at"),
        Index("ix_runs_status", "status"),
        Index("ix_runs_incident", "incident_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    playbook_id: Mapped[str] = mapped_column(String(32), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="queued")
    trigger: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    object_kind: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    object_id: Mapped[str] = mapped_column(String(1100), nullable=False, default="")
    incident_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    artifact_id: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # {node id: result}, the classes of what it holds, and which edges were taken or are dead.
    context: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    context_classes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    state: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    finished_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    deadline: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    waited_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    started_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    parent_run_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    parent_step_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # A run of the debugger: it stops before nodes, counts for no limit and no statistic, and is
    # shown to who started it. ``state["debug"]`` says where it stops.
    debug: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())


class RunStep(Base):
    """One node of a run being executed (several for a node inside a "for each")."""

    __tablename__ = "run_steps"
    __table_args__ = (Index("ix_run_steps_due", "status", "next_at"), Index("ix_run_steps_run", "run_id", "seq"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(32), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    node_id: Mapped[str] = mapped_column(String(32), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    kind: Mapped[str] = mapped_column(String(12), nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="pending")
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    next_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    claimed_by: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    claimed_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    timeout_s: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    input: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    output: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    request: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # The port the step left by: a choice of a question can be 24 characters long.
    port: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    finished_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    item_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # What the step waits for while it is `waiting`: {"kind": "approval" | "wait" | "run" | "each", ...}
    waiting: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)


class Approval(Base):
    """A question a run stops at until someone who may run playbooks answers."""

    __tablename__ = "approvals"
    __table_args__ = (Index("ix_approvals_status", "status"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(32), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    step_id: Mapped[str] = mapped_column(String(32), nullable=False)
    question: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="waiting")
    on_expire: Mapped[str] = mapped_column(String(8), nullable=False, default="skip")
    asked_at: Mapped[str] = mapped_column(String, nullable=False)
    asked_epoch: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    expires_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    answered_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    answered_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    comment: Mapped[str] = mapped_column(String(1000), nullable=False, default="")


class AutomationSchedule(Base):
    """When a playbook with a schedule trigger fires next."""

    __tablename__ = "automation_schedules"

    playbook_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("playbooks.id", ondelete="CASCADE"), primary_key=True
    )
    node_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cron: Mapped[str] = mapped_column(String(120), nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    next_at: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Connector(Base):
    """A connector: the YAML file that says how to talk to a product (automation/connectors.py).

    ``source`` is the file as it was uploaded or shipped; it is parsed when a
    command runs. ``builtin`` ones come with Nik (``seed/connectors``) and are
    replaced when a release changes them; one uploaded under the same id is
    the admin's and is left alone.
    """

    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(41), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    # What a connector comes with besides its file (5.1): a logo, checked by connector_logo.clean
    # before it is kept (``logo_type`` is image/png or image/svg+xml, "" for none), and a README.
    logo: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    logo_type: Mapped[str] = mapped_column(String(20), nullable=False, default="", server_default="")
    readme: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class Connection(Base):
    """A connector plus an address and credentials: one system a playbook can talk to.

    ``config`` holds the plain values (the address, a region); ``secrets`` the
    credentials, encrypted with the vault key and never returned by the API.
    The host of a connection is one its playbooks may reach: making the
    connection is the permission.
    """

    __tablename__ = "connections"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    connector_id: Mapped[str] = mapped_column(
        String(41), ForeignKey("connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    secrets: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_test: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # An instance of its connector (5.1). Off, it runs no command, fetches nothing and mirrors
    # nothing, and keeps everything it was set up with. A connector is enabled when one is on.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    # Fetching (4.5): whether this connection brings alerts in, what its last cycle left for the
    # next (``fetch.next_state`` of the connector), and how it goes: {state, error, lastAt, nextAt…}.
    fetch_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    fetch_state: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    fetch_status: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # How this instance fetches where it differs from its connector (6.4): {intervalSeconds,
    # firstFetch, lookbackMinutes}. A value left out is the connector's (fetch.settings_of).
    fetch_settings: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # More keys than one (6.1): the credentials beside the first, encrypted like ``secrets``, and how
    # the keys take turns: {mode, perMinute, perDay, whenExhausted, cacheHours, mainName}
    # (automation/instance_keys.py).
    extra_keys: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    key_policy: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class Credential(Base):
    """A secret kept once under a name and used by any number of instances (6.6).

    ``kind`` is ``secret`` (one value: an API key, a token) or ``pair`` (a user name and a
    password). ``secret`` holds the value, or the password of a pair, encrypted with the vault key
    as the credentials of a connection are, and never returned by the API; ``username`` is not
    secret and is shown. An instance names a credential where it would hold a value
    (automation/credentials.py): nothing of it is copied there.
    """

    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(10), nullable=False, default="secret")
    username: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    secret: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class InstanceKeyUse(Base):
    """What a key of an instance was used for: this minute, today, and until when the vendor refuses it."""

    __tablename__ = "instance_key_uses"

    connection_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("connections.id", ondelete="CASCADE"), primary_key=True
    )
    key_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    minute: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # the minute counted (epoch // 60)
    minute_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    day: Mapped[str] = mapped_column(String(10), nullable=False, default="")  # the day counted (UTC)
    day_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    refusals: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exhausted_until: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    last_used: Mapped[float] = mapped_column(Float, nullable=False, default=0)


class CommandAnswer(Base):
    """The answer of a command that changes nothing outside, kept for the hours its instance says."""

    __tablename__ = "command_answers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # of the instance, the command and its arguments
    connection_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("connections.id", ondelete="CASCADE"), nullable=False, index=True
    )
    command: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    outputs: Mapped[Any] = mapped_column(JSON, nullable=True)
    context: Mapped[Any] = mapped_column(JSON, nullable=True)
    created_epoch: Mapped[float] = mapped_column(Float, nullable=False, default=0)


class Field(Base):
    """A field of the registry: one name for one thing, whatever sets it.

    System fields are seeded and map onto columns Nik already has; custom ones
    are made in Settings and live in ``incidents.fields``. A name is never
    changed once it exists: playbooks, mappers and queries refer to it.
    """

    __tablename__ = "fields"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(41), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    type: Mapped[str] = mapped_column(String(16), nullable=False, default="text")
    # choice / multi_choice: {"choices": [...]}; list: {"columns": [{name, label, type}]}.
    options: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    applies_to: Mapped[str] = mapped_column(String(12), nullable=False, default="incident")
    # On every type of incident without being listed by each.
    all_types: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class IncidentType(Base):
    """A type of incident: its fields, how its page is laid out, how it is closed.

    ``fields`` is the ordered list of the custom fields of this type:
    ``[{"name", "required", "required_on_close"}]``. ``layout`` arranges the
    Summary in sections and orders the tabs (none: one is generated).
    """

    __tablename__ = "incident_types"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    colour: Mapped[str] = mapped_column(String(16), nullable=False, default="slate")
    icon: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    default_playbook_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    auto_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    layout: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    sla: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    close_reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    visible_to_roles: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String, nullable=False, default="")


class IncidentContext(Base):
    """What is known of an incident, as data playbooks read and write (see ``context.py``).

    One document per incident; ``version`` is one more at every write, and a
    write replaces the document only if the version is still the one it read.
    """

    __tablename__ = "incident_context"

    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(FIELDS_JSON, nullable=False, default=dict)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[str] = mapped_column(String, nullable=False, default="")


class IncidentContextMeta(Base):
    """Who last set an item of the context (``Ticket:<its key>``, ``ext.<connector>.<name>``)."""

    __tablename__ = "incident_context_meta"

    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    path_key: Mapped[str] = mapped_column(String(400), primary_key=True)
    source: Mapped[str] = mapped_column(String(120), nullable=False)  # nik | connector:<id> | user:<name> | run:<id>
    at: Mapped[str] = mapped_column(String, nullable=False)


class WarRoomEntry(Base):
    """One line of the War Room of an incident: a note, a command and its result, what a playbook did.

    ``body`` is text (markdown) for a note and JSON for a result. An entry
    with a ``parent_id`` belongs under another (the result of a command).
    """

    __tablename__ = "war_room_entries"
    __table_args__ = (Index("ix_war_room_incident_at", "incident_id", "at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    at: Mapped[str] = mapped_column(String, nullable=False)
    author: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # note | command | result | error | task | approval | mirror | file | system
    kind: Mapped[str] = mapped_column(String(12), nullable=False, default="note")
    body: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    run_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    step_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    parent_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)


class Task(Base):
    """Something a person does for an incident: a task, or a question to answer.

    Made by a ``task`` or an ``ask`` node of a playbook (the step waits for it:
    ``run_id``, ``step_id``), or by hand on an incident. It is for one user,
    for whoever holds a role, or for the owner of the incident at the moment
    it is done. ``form`` is what is filled on completion: the choices of a
    question, the fields to give.
    """

    __tablename__ = "tasks"
    __table_args__ = (Index("ix_tasks_incident", "incident_id"), Index("ix_tasks_status_due", "status", "due_at"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    run_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    step_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    kind: Mapped[str] = mapped_column(String(8), nullable=False, default="task")  # task | ask
    title: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    instructions: Mapped[str] = mapped_column(String, nullable=False, default="")
    assignee_user: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    assignee_role: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    # The owner of the incident, whoever that is when the task is done.
    assignee_owner: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    status: Mapped[str] = mapped_column(String(8), nullable=False, default="open")  # open | done | skipped | overdue
    form: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    answer: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    due_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    reminder_s: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    next_reminder_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # An ask node gives up at this time and leaves by its "timeout" port.
    timeout_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    completed_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    completed_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class Notification(Base):
    """Something an account is told inside Nik: a task given, an approval asked, an SLA breached."""

    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_user", "username", "read_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    text: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    link: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    at: Mapped[str] = mapped_column(String, nullable=False)
    read_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class NamedList(Base):
    """A list a feature or a playbook reads by its name: values, key → value pairs,
    or one JSON document. What Nik kept as fixed lists in its settings lives here."""

    __tablename__ = "lists"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(12), nullable=False, default="values")  # values | key_value | json
    # What its items are, for whoever edits it: text, domain, cidr, email, user…
    item_type: Mapped[str] = mapped_column(String(16), nullable=False, default="text")
    # The columns of the value of a key → value list, when it has a fixed shape.
    columns: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    writable_by_automation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class NamedListItem(Base):
    __tablename__ = "list_items"
    __table_args__ = (Index("ix_list_items_expires", "expires_at"),)

    list_id: Mapped[str] = mapped_column(String(32), ForeignKey("lists.id", ondelete="CASCADE"), primary_key=True)
    key: Mapped[str] = mapped_column(String(500), primary_key=True)
    value: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    note: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    added_at: Mapped[str] = mapped_column(String, nullable=False)
    added_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    expires_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


class Classifier(Base):
    """For a connection that fetches: which type of incident an item becomes.
    ``rules``: ``[{"when": {"all": [...]}, "type": <type id>}]``, the first that holds wins."""

    __tablename__ = "classifiers"

    connection_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    rules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    default_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class Mapper(Base):
    """How what a connector's product calls things becomes Nik's fields and context, and back.

    ``direction`` ``incoming``: ``rules`` are ``[{"to": <field or context path>, "from":
    <template over item>, "authoritative": bool}]``. ``outgoing``: ``[{"to": <the product's
    name>, "from": <template over incident and context>}]``. One mapper for each type of
    incident, and ``*`` for every type that has none of its own."""

    __tablename__ = "mappers"
    __table_args__ = (UniqueConstraint("connector_id", "direction", "incident_type", name="uq_mappers_target"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    connector_id: Mapped[str] = mapped_column(String(41), nullable=False)
    direction: Mapped[str] = mapped_column(String(8), nullable=False)  # incoming | outgoing
    incident_type: Mapped[str] = mapped_column(String(32), nullable=False, default="*")
    rules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class FetchedItem(Base):
    """An item a connection fetched, by the id the other side gives it: what keeps one alert
    from becoming two incidents, and what Fetch status lists."""

    __tablename__ = "fetched_items"
    __table_args__ = (Index("ix_fetched_items_at", "connection_id", "fetched_at"),)

    connection_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    item_id: Mapped[str] = mapped_column(String(300), primary_key=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # created | incomplete (created with fields missing) | dropped | linked | duplicate
    outcome: Mapped[str] = mapped_column(String(12), nullable=False, default="created")
    note: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    fetched_at: Mapped[str] = mapped_column(String, nullable=False)


class PreprocessRule(Base):
    """What is done with a fetched item before it becomes an incident, in order."""

    __tablename__ = "preprocess_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    when: Mapped[str] = mapped_column(String, nullable=False, default="")  # a query on the incident to be
    action: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # drop | link_to_existing | close_duplicate | run_script
    params: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class MirrorJob(Base):
    """Something to send to the other side of a mirrored incident: a change of fields, a comment."""

    __tablename__ = "mirror_queue"
    __table_args__ = (Index("ix_mirror_queue_due", "status", "next_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, nullable=False)
    connection_id: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)  # update | comment
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_at: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default="pending")  # pending | done | failed
    error: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class Dashboard(Base):
    """Widgets on a grid, each a question asked of what Nik holds. Personal until it is shared;
    the ones Nik ships are ``builtin``. ``layout`` is the list of its widgets:
    ``{id, title, type, entity, query, groupBy, measure, options, x, y, w, h}``."""

    __tablename__ = "dashboards"
    __table_args__ = (Index("ix_dashboards_owner", "owner"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    owner: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # Who else sees it: {"everyone": bool, "roles": [...], "users": [...]}.
    shared_with: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    layout: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    time_range: Mapped[str] = mapped_column(String(20), nullable=False, default="30d")
    refresh_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # A query every widget of ``filter_entity`` is narrowed by, unless it opts out.
    filter_query: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    filter_entity: Mapped[str] = mapped_column(String(40), nullable=False, default="incidents")
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class Pack(Base):
    """A content pack that is installed: its manifest. What it brought is in ``pack_items``."""

    __tablename__ = "packs"

    id: Mapped[str] = mapped_column(String(49), primary_key=True)  # the id its pack.yml gives
    name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(20), nullable=False, default="0.0.0")
    description: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    author: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    # Where it came from: "nik" (part of Nik), "catalogue", "file", "folder" (NIK_PACKS_DIR), "nik-5" (what
    # came inside Nik before 6.0).
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="file", server_default="file")
    logo: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    logo_type: Mapped[str] = mapped_column(String(20), nullable=False, default="", server_default="")
    installed_at: Mapped[str] = mapped_column(String, nullable=False)
    installed_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class PackItem(Base):
    """An item and the pack it came from last. An item is known by its kind and its name, never by an id."""

    __tablename__ = "pack_items"

    kind: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), primary_key=True)
    pack_id: Mapped[str] = mapped_column(String(49), ForeignKey("packs.id", ondelete="CASCADE"), nullable=False)
    # What the item was when the pack gave it (packs.digest): another value now means it was changed here.
    digest: Mapped[str] = mapped_column(String(64), nullable=False, default="", server_default="")


class PackUpload(Base):
    """A pack file between its inspection and its application: kept an hour, for who inspected it."""

    __tablename__ = "pack_uploads"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    file_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    created_epoch: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class ScriptSignature(Base):
    """A signature the scripts of a scanned page are checked against. The ones Nik ships are
    ``builtin``: turned off or changed here, never deleted. ``updated_by == "nik"`` says nobody
    changed it here, so it follows the releases."""

    __tablename__ = "script_signatures"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    key: Mapped[str] = mapped_column(String(61), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    points: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pattern: Mapped[str] = mapped_column(Text, nullable=False, default="")
    also: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=true())
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False, default="")


class IocListHistory(Base):
    """What one check of a watch list found: how many indicators, how many changed verdict, how many
    of each verdict."""

    __tablename__ = "ioc_list_history"
    __table_args__ = (Index("ix_ioc_list_history_list", "list_id", "checked_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    list_id: Mapped[str] = mapped_column(String, ForeignKey("ioc_lists.id", ondelete="CASCADE"), nullable=False)
    check_id: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    checked_at: Mapped[str] = mapped_column(String, nullable=False)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    by_verdict: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class IocVerdictChange(Base):
    """An indicator of a watch list whose verdict a check changed."""

    __tablename__ = "ioc_verdict_changes"
    __table_args__ = (Index("ix_ioc_verdict_changes_check", "check_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    list_id: Mapped[str] = mapped_column(String, ForeignKey("ioc_lists.id", ondelete="CASCADE"), nullable=False)
    check_id: Mapped[str] = mapped_column(String, nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    old: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    new: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    at: Mapped[str] = mapped_column(String, nullable=False)


class SavedFilter(Base):
    """A query of a list kept under a name, with the sort and the columns that were on screen.
    Its owner's alone until an administrator shares it with everyone."""

    __tablename__ = "saved_filters"
    __table_args__ = (Index("ix_saved_filters_owner", "owner", "entity"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    # The list it filters, by the name the query language gives it ("incidents").
    entity: Mapped[str] = mapped_column(String(40), nullable=False, default="incidents")
    query: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # {"key": a column, "dir": "asc" | "desc"}, or null for the order of the list itself.
    sort: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # The columns in their order, by name; empty for those the person has chosen for themselves.
    columns: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class SavedFilterDefault(Base):
    """The filter a list opens with for one person: one for each list at most."""

    __tablename__ = "saved_filter_defaults"

    username: Mapped[str] = mapped_column(String(200), primary_key=True)
    entity: Mapped[str] = mapped_column(String(40), primary_key=True)
    filter_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("saved_filters.id", ondelete="CASCADE"), nullable=False
    )


class ArtifactJob(Base):
    """Something a playbook asked the API process to do with a file: keep one, or analyse one again.

    The automation worker reads the store of files read-only and is on no network with the analysis
    workers, so a node writes what it wants here and the API process does it (``artifact_jobs.py``).
    ``status`` is queued → running → done | error. The bytes of a file to keep are in
    ``artifact_job_parts``, only until it is kept; ``result`` is what the node reads back. A row is
    deleted a day after it was made.
    """

    __tablename__ = "artifact_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # store | attachment | analyse
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    actor: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # The run that asked, and how deep it is: what the job sets off says so, which stops a loop.
    run_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_epoch: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    finished_epoch: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


class ArtifactJobPart(Base):
    """A part of the bytes a job carries. A file can be as large as an upload, so it crosses the
    database in parts of a few megabytes, put together by the API process and deleted once the
    file is in the store."""

    __tablename__ = "artifact_job_parts"

    job_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("artifact_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


# Created by migration 0047_playbook_files where missing, in this order.
PLAYBOOK_FILE_TABLES = ("artifact_jobs", "artifact_job_parts")

# Created by migration 0046_credentials where missing.
CREDENTIAL_TABLES = ("credentials",)

# Created by migration 0041_saved_filters where missing, in this order.
SAVED_FILTER_TABLES = ("saved_filters", "saved_filter_defaults")

# Created by migration 0040_instance_keys where missing.
INSTANCE_KEY_TABLES = ("instance_key_uses", "command_answers")
INSTANCE_KEY_COLUMNS = {"connections": ("extra_keys", "key_policy")}

# Created by migration 0038_incident_page where missing.
INCIDENT_PAGE_TABLES = ("playground_entries",)

# Created by migration 0037_branches where missing.
BRANCH_TABLES = ("playbook_branches",)

# The columns migration 0036_instances adds where missing.
INSTANCE_COLUMNS: dict[str, tuple[str, ...]] = {
    "connections": ("enabled",),
    "connectors": ("logo", "logo_type", "readme"),
}

# The column migration 0043_instance_fetch adds where missing.
INSTANCE_FETCH_COLUMNS: dict[str, tuple[str, ...]] = {"connections": ("fetch_settings",)}

# Created by migration 0035_incident_numbers where missing; and the column it adds.
NUMBER_TABLES = ("sequences",)
NUMBER_COLUMNS: dict[str, tuple[str, ...]] = {"incidents": ("number",)}

# Created by migration 0034_misc where missing, in this order; and the columns it adds.
MISC_TABLES = ("script_signatures", "ioc_list_history", "ioc_verdict_changes")
MISC_COLUMNS: dict[str, tuple[str, ...]] = {
    "ioc_checks": ("list_id", "baseline"),
    "artifacts": ("expires_at", "expiry_note", "expiry_noticed"),
}

# Created by migration 0033_dashboards_packs where missing, in this order.
DASHBOARD_PACK_TABLES = ("dashboards", "packs", "pack_items", "pack_uploads")
DASHBOARD_PACK_COLUMNS = {"runs": ("debug",)}

# Created by migration 0032_fetch_mappers where missing, in this order; and the columns it adds.
FETCH_TABLES = ("classifiers", "mappers", "fetched_items", "preprocess_rules", "mirror_queue")
FETCH_COLUMNS = {"connections": ("fetch_enabled", "fetch_state", "fetch_status")}

# Created by migration 0031_lists where missing, in this order.
LIST_TABLES = ("lists", "list_items")

# Created by migration 0030_tasks_sla where missing, in this order.
TASK_TABLES = ("tasks", "notifications")

# Created by migration 0029_context_war_room where missing, in this order.
CONTEXT_TABLES = ("incident_context", "incident_context_meta", "war_room_entries")

# Created by migration 0028_fields_types where missing, in this order.
FIELD_TABLES = ("fields", "incident_types")

# Created by migration 0027_connectors where missing, in this order.
CONNECTOR_TABLES = ("connectors", "connections")

AUTOMATION_TABLES = (
    "playbooks",
    "playbook_versions",
    "scripts",
    "script_versions",
    "automation_events",
    "runs",
    "run_steps",
    "approvals",
    "automation_schedules",
)

# Created by migration 0048_backups where missing.
BACKUP_TABLES = ("backups",)
