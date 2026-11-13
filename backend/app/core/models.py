"""SQLAlchemy ORM models.

Mirrors the DB tables described in the spec. The portable ``JSON`` column type
maps to ``JSONB`` on PostgreSQL and to a TEXT-backed JSON on SQLite, so the same
models run in dev and prod. Timestamps are stored as ISO-8601 strings to match
the frontend data shape exactly.
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import BigInteger, Boolean, Float, ForeignKey, Index, Integer, String, Text, event, false
from sqlalchemy import inspect as sa_inspect
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
    role: Mapped[str] = mapped_column(String, nullable=False, default="analyst")
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


class Incident(Base):
    """Incident document store.

    The full frontend incident object lives in ``doc``; a handful of scalar
    fields are duplicated into columns purely for listing/sorting.
    """

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
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
    """One API key of a threat-intelligence provider, encrypted (``vault.py``).

    A provider can have several: lookups rotate over them, each with its own
    rate limit and daily quota. A key the provider refuses several times in a
    row (``failures``) is marked ``rejected``, with what it answered, and
    skipped until an admin replaces it.
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
    """One provider's latest answer about one indicator (``enrichment/``),
    valid for the retention of its type (Settings -> Threat intelligence).
    ``raw`` is the provider's own answer, for the JSON download."""

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
    """A provider's earlier answers about an indicator: verdict and summary
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
    - ``role``   'admin' | 'analyst' — an admin key can reach the admin-data
      endpoints (users, backup, keys); an analyst key cannot.
    - ``scopes`` comma-separated subset of read/write/admin controlling which
      operations the key may perform.
    - ``expires_at`` optional ISO timestamp after which the key is rejected.

    A revoked key has a non-null ``revoked_at`` and is rejected.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    label: Mapped[str] = mapped_column(String, nullable=False)
    prefix: Mapped[str] = mapped_column(String, nullable=False)
    key_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="analyst")
    scopes: Mapped[str] = mapped_column(String, nullable=False, default="read,write")
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

    ``pending`` holds what is left: ``[type, value, [provider ids]]``. The
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
