"""The entities a query can be asked of, and the fields each exposes.

Incidents, artifacts and the audit log are tables; the indicator library is
assembled in rows (``ioc_library.library``), so its fields read a row. Later
releases add entities here (runs, tasks, the War Room, connections) and let
the field registry add the custom fields of incidents.
"""

from __future__ import annotations

from sqlalchemy import select

from ..core.models import Artifact, ArtifactLink, AuditEntry, Incident
from .fields import Context, Entity, FieldSpec, _bad, _boolean, text_matches
from .parser import Value

SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("open", "in_progress", "closed")
ARTIFACT_KINDS = ("file", "mail", "pcap", "url", "mailbox")
INDICATOR_TYPES = ("ip", "domain", "url", "email", "md5", "sha1", "sha256")
VERDICTS = ("unknown", "harmless", "suspicious", "malicious")
ORIGINS = ("incident", "manual", "import", "artifact")
TLPS = ("clear", "green", "amber", "red")


# --------------------------------------------------------------------------- #
# Incidents                                                                   #
# --------------------------------------------------------------------------- #
INCIDENTS = Entity(
    name="incidents",
    label="Incidents",
    permission="read",
    model=Incident,
    text_fields=("name", "host", "username", "ticket"),
    fields=(
        FieldSpec("id", "keyword", "The incident's identifier", column=Incident.id),
        FieldSpec("name", "text", "The name shown in the list", column=Incident.name),
        FieldSpec("ticket", "text", "The ticket of your tracker", aliases=("ticketId",), column=Incident.ticket_id),
        FieldSpec("host", "text", "The host the incident is about", column=Incident.host),
        FieldSpec("username", "text", "The account the incident is about", aliases=("user",), column=Incident.username),
        FieldSpec("os", "keyword", "The operating system", column=Incident.os),
        FieldSpec("severity", "ordered", "low, medium, high or critical", column=Incident.severity, values=SEVERITIES),
        FieldSpec("status", "keyword", "open, in_progress or closed", column=Incident.status, values=STATUSES),
        FieldSpec(
            "owner",
            "keyword",
            'Who has the incident; owner:"" is nobody',
            aliases=("assignee",),
            column=Incident.assignee,
        ),
        FieldSpec("hasMail", "bool", "It holds analysed e-mails", aliases=("mail",), column=Incident.has_mail),
        FieldSpec("created", "date", "When it was created", aliases=("createdAt",), column=Incident.created_at),
        FieldSpec(
            "modified", "date", "When it last changed", aliases=("updated", "updatedAt"), column=Incident.updated_at
        ),
    ),
)


# --------------------------------------------------------------------------- #
# Artifacts                                                                   #
# --------------------------------------------------------------------------- #
def _has_link():
    return select(ArtifactLink.artifact_id).where(ArtifactLink.artifact_id == Artifact.id).exists()


def _linked_sql(op: str, value: Value, ctx: Context):
    if op not in ("=", "!"):
        raise _bad("bad_operator", 0, '"linked" is true or false')
    wanted = _boolean(value, 0) == (op == "=")
    return _has_link() if wanted else ~_has_link()


def _incident_sql(op: str, value: Value, ctx: Context):
    """``incident:<id>``: referenced by that incident; ``incident:*`` by any."""
    if op not in ("=", "!"):
        raise _bad("bad_operator", 0, '"incident" takes an incident\'s id')
    if value.is_any or value.is_empty:
        found = _has_link()
        positive = value.is_any == (op == "=")
    else:
        found = (
            select(ArtifactLink.artifact_id)
            .where(ArtifactLink.artifact_id == Artifact.id, ArtifactLink.incident_id == value.text)
            .exists()
        )
        positive = op == "="
    return found if positive else ~found


ARTIFACTS = Entity(
    name="artifacts",
    label="Artifacts",
    permission="read",
    model=Artifact,
    text_fields=("name", "hash", "detail", "tags"),
    fields=(
        FieldSpec("id", "keyword", "The artifact's identifier", column=Artifact.id),
        FieldSpec(
            "kind",
            "keyword",
            "file, mail, pcap, url or mailbox",
            aliases=("type",),
            column=Artifact.kind,
            values=ARTIFACT_KINDS,
        ),
        FieldSpec("name", "text", "Its name", column=Artifact.name),
        FieldSpec(
            "hash",
            "text",
            "Its SHA-256, or the id of a capture or a scan",
            aliases=("sha256", "ref"),
            column=Artifact.ref,
        ),
        FieldSpec("verdict", "keyword", "What the analysis concluded", column=Artifact.verdict),
        FieldSpec("score", "number", "The score of the analysis", column=Artifact.score),
        FieldSpec("detail", "text", "The line under the name", column=Artifact.detail),
        FieldSpec("size", "number", "Its size in bytes", column=Artifact.size),
        FieldSpec("tags", "tags", "Its tags", aliases=("tag",), column=Artifact.tags),
        FieldSpec("created", "date", "When it was added", aliases=("createdAt",), column=Artifact.created_at),
        FieldSpec("createdBy", "keyword", "Who added it", aliases=("by",), column=Artifact.created_by),
        FieldSpec("linked", "bool", "An incident references it", sql=_linked_sql),
        FieldSpec("incident", "keyword", "The id of an incident that references it", sql=_incident_sql),
    ),
)


# --------------------------------------------------------------------------- #
# Audit log                                                                   #
# --------------------------------------------------------------------------- #
AUDIT = Entity(
    name="audit",
    label="Audit log",
    permission="audit.read",
    model=AuditEntry,
    text_fields=("actor", "action", "details", "incident"),
    fields=(
        FieldSpec("at", "date", "When it happened", aliases=("date", "when"), column=AuditEntry.at),
        FieldSpec(
            "actor",
            "text",
            "Who did it: a username, or api:<key label>",
            aliases=("user", "by"),
            column=AuditEntry.actor,
        ),
        FieldSpec(
            "action", "keyword", "What was done, for example user.update or incident.*", column=AuditEntry.action
        ),
        FieldSpec("target", "text", "What it was done to", column=AuditEntry.target, nullable=True),
        FieldSpec("details", "text", "The sentence of the entry", column=AuditEntry.details),
        FieldSpec(
            "incident", "text", "The name of the incident concerned", column=AuditEntry.incident_name, nullable=True
        ),
        FieldSpec(
            "incidentId", "keyword", "The id of the incident concerned", column=AuditEntry.incident_id, nullable=True
        ),
    ),
)


# --------------------------------------------------------------------------- #
# Indicators (rows of the library)                                            #
# --------------------------------------------------------------------------- #
def _list_test(op: str, value: Value, ctx: Context):
    """``list:<name or id>``: kept in that watch list."""
    if op not in ("=", "!"):
        raise _bad("bad_operator", 0, '"list" takes the name of a list')

    def held(row: dict) -> bool:
        lists = row.get("lists") or []
        if value.is_empty:
            return not lists
        if value.is_any:
            return bool(lists)
        return any(
            entry.get("id") == value.text or text_matches(value, entry.get("name", ""), contains=False)
            for entry in lists
        )

    return lambda row: held(row) == (op == "=")


INDICATORS = Entity(
    name="indicators",
    label="Indicators",
    permission="read",
    text_fields=("value", "note", "tags", "listNames"),
    fields=(
        FieldSpec(
            "type",
            "keyword",
            "ip, domain, url, email, md5, sha1 or sha256",
            aliases=("kind",),
            getter=lambda r: r["type"],
            values=INDICATOR_TYPES,
        ),
        FieldSpec("value", "text", "The indicator itself", getter=lambda r: r["value"]),
        FieldSpec(
            "verdict",
            "ordered",
            'What the sources say; verdict:"" is not checked yet',
            getter=lambda r: r.get("verdict"),
            values=VERDICTS,
        ),
        FieldSpec("score", "number", "The reputation score", getter=lambda r: r.get("score")),
        FieldSpec(
            "origin", "keyword", "incident, manual, import or artifact", getter=lambda r: r["origin"], values=ORIGINS
        ),
        FieldSpec("incidents", "number", "In how many incidents it was seen", getter=lambda r: r.get("incidents") or 0),
        FieldSpec("tags", "tags", "Its tags", aliases=("tag",), getter=lambda r: r.get("tags") or []),
        FieldSpec("note", "text", "The note an analyst wrote", getter=lambda r: r.get("note") or ""),
        FieldSpec("tlp", "keyword", "clear, green, amber or red", getter=lambda r: r.get("tlp"), values=TLPS),
        FieldSpec("list", "keyword", "A watch list that keeps it (name or id)", aliases=("lists",), test=_list_test),
        FieldSpec(
            "listNames",
            "tags",
            "The names of its lists",
            getter=lambda r: [e.get("name", "") for e in r.get("lists") or []],
        ),
        FieldSpec("expired", "bool", "Its date has passed", getter=lambda r: r.get("expired")),
        FieldSpec("expires", "date", "The date after which it is no longer current", getter=lambda r: r.get("expires")),
        FieldSpec(
            "firstSeen",
            "date",
            "When Nik first met it",
            aliases=("first_seen", "seen"),
            getter=lambda r: r.get("firstSeen"),
        ),
        FieldSpec(
            "checked",
            "date",
            "When its reputation was last asked",
            aliases=("checkedAt",),
            getter=lambda r: r.get("checkedAt"),
        ),
        FieldSpec("allowlisted", "bool", "It is in the allowlist", getter=lambda r: r.get("allowlisted")),
        FieldSpec(
            "analysed",
            "bool",
            "Nik analysed it itself (a URL it visited)",
            aliases=("analyzed",),
            getter=lambda r: bool(r.get("analysis")),
        ),
        FieldSpec("addedBy", "keyword", "Who added it by hand", getter=lambda r: r.get("addedBy")),
    ),
)

ENTITIES: dict[str, Entity] = {entity.name: entity for entity in (INCIDENTS, ARTIFACTS, INDICATORS, AUDIT)}
