"""The query language: reading it, what each kind of field means (in SQL and
on rows, which must agree), and the endpoints that take it."""

# ruff: noqa: E501 (rows of test data read better on one line)

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import query
from app.core.db import SessionLocal
from app.core.models import Artifact, ArtifactLink, AuditEntry, Incident
from app.main import app as fastapi_app
from app.query import dates
from app.query.fields import Entity, FieldSpec
from app.query.parser import MAX_LENGTH, QueryError, parse, to_json
from tests.conftest import make_key

VECTORS = json.loads((Path(__file__).parent / "data" / "query_vectors.json").read_text(encoding="utf-8"))["vectors"]
NOW = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["query"][:40] or "(empty)")
def test_the_parser_reads_the_shared_vectors(vector):
    """The same file is read by the frontend's parser (domain/query/parse.test.js)."""
    if "error" in vector:
        with pytest.raises(QueryError) as caught:
            parse(vector["query"])
        assert {"code": caught.value.code, "position": caught.value.position} == vector["error"]
    else:
        assert to_json(parse(vector["query"])) == vector["tree"]


def test_the_vectors_cover_every_error_the_parser_raises():
    from app.query.parser import MESSAGES

    assert {v["error"]["code"] for v in VECTORS if "error" in v} == set(MESSAGES)
    assert len(VECTORS) > 60 and any(len(v["query"]) > MAX_LENGTH for v in VECTORS)


def test_is_not_written_as_before_is_rewritten_and_means_the_same():
    """``field:!value`` was "is not" until 5.0. It is still read; ``modern`` gives today's writing."""
    for old, new in {
        "status:!closed": "!status:closed",
        "status:open name:!x": "status:open !name:x",
        '(owner:!"" or tags:!phish) severity:>=high': '(!owner:"" or !tags:phish) severity:>=high',
        "-name:!x": "-!name:x",
        "not status:!closed": "not !status:closed",
    }.items():
        assert query.modern(old) == new
        assert to_json(parse(new)) == _without_positions_moved(old, new)
        assert query.modern(new) == new
    # Nothing to rewrite, and what cannot be read, come back as they are.
    for text in ("", "status:open", "!status:closed", "status IN (a, b)", "(status:!closed", 'name:"a:!b"'):
        assert query.modern(text) == text
    assert query.modern(None) == ""


def _without_positions_moved(old: str, new: str):
    """The tree of the old writing with the positions of the new one: the two differ in nothing else."""

    def strip(node):
        if isinstance(node, dict):
            return {key: strip(value) for key, value in node.items() if key != "position"}
        if isinstance(node, list):
            return [strip(item) for item in node]
        return node

    assert strip(to_json(parse(old))) == strip(to_json(parse(new)))
    return to_json(parse(new))


def test_a_long_run_of_spaces_after_a_name_costs_nothing():
    """What follows a name is read a character at a time: a query made of spaces is read at once."""
    import time

    for text in ("status" + " \t" * 900 + "x", "status" + " " * 900 + "not" + " " * 900 + "x", "a" + " " * 1500 + "in"):
        started = time.perf_counter()
        parse(text)
        assert time.perf_counter() - started < 0.5, text[:20]
    # And a list is still a list, however it is spaced.
    assert to_json(parse("status \t\n NOT \t in \n ( a ,, b )")) == to_json(parse("status not in (a, b)"))
    assert to_json(parse("status notin (a)"))["and"][0]["text"]["text"] == "status"
    assert "and" in to_json(parse("status india (a)"))


def test_dates_are_spans_of_time():
    def span(text):
        return dates.span(text, NOW)

    assert span("2026-11-10") == ("2026-11-10T00:00:00", "2026-11-11T00:00:00")
    assert span("2026-12") == ("2026-12-01T00:00:00", "2027-01-01T00:00:00")
    assert span("2026-11-10T14:30") == ("2026-11-10T14:30:00", "2026-11-10T14:31:00")
    assert span("2026-11-10 14:30:05") == ("2026-11-10T14:30:05", "2026-11-10T14:30:06")
    assert span("2026-11-10T14:30:05.123Z") == ("2026-11-10T14:30:05", "2026-11-10T14:30:06")
    assert span("2026-11-10T14:30:00+02:00")[0] == "2026-11-10T12:30:00"
    assert span("today") == ("2026-11-17T00:00:00", "2026-11-18T00:00:00")
    assert span("Yesterday") == ("2026-11-16T00:00:00", "2026-11-17T00:00:00")
    assert span("now") == ("2026-11-17T12:00:00", "2026-11-17T12:00:00")
    assert span("now-7d")[0] == "2026-11-10T12:00:00"
    assert span("now-90m")[0] == "2026-11-17T10:30:00"
    assert span("7 days ago")[0] == "2026-11-10T12:00:00"
    assert span("1 day ago") == span("now-1d")
    assert span("2  weeks   ago")[0] == "2026-11-03T12:00:00"
    assert span("3 hours ago")[0] == "2026-11-17T09:00:00"
    assert span("1 month ago")[0] == "2026-10-18T12:00:00"
    for bad in (
        "",
        "soon",
        "2026-13-01",
        "2026-02-30",
        "7 parsecs ago",
        "now-7x",
        "99999999999 days ago",
        "10/11/2026",
    ):
        assert span(bad) is None, bad


# --------------------------------------------------------------------------- #
# What a condition means: the same in SQL and on rows                         #
# --------------------------------------------------------------------------- #
ARTIFACTS = [
    # id, kind, ref, name, verdict, score, detail, size, tags, created_at, created_by
    (
        "file-a",
        "file",
        "aa11",
        "Invoice_2026.exe",
        "malicious",
        90,
        "PE32 dropper",
        5000,
        ["dropper", "c2"],
        "2026-11-17T08:00:00+00:00",
        "anna",
    ),
    (
        "file-b",
        "file",
        "bb22",
        "notes 100%_done.txt",
        "",
        None,
        "plain text",
        12,
        [],
        "2026-11-16T23:59:59.000Z",
        "bob",
    ),
    (
        "mail-c",
        "mail",
        "cc33",
        "Re: your invoice",
        "phishing",
        70,
        "from evil.example",
        2048,
        ["phish"],
        "2026-11-10T12:00:00+00:00",
        "anna",
    ),
    ("pcap-d", "pcap", "dd44", "capture.pcapng", "", 0, "", 9_000_000, None, "2026-10-01T00:00:00+00:00", "api:feed"),
    (
        "url-e",
        "url",
        "ee55",
        "http://evil.example/login",
        "suspicious",
        40,
        r"C:\Temp\a_b",
        0,
        ["PHISH", "kit"],
        "2025-12-31T10:00:00+00:00",
        "anna",
    ),
]

# A row entity with the very fields of the artifacts table: what holds on one must hold on the other.
_ROW_FIELDS = tuple(
    FieldSpec(
        spec.name,
        spec.kind,
        aliases=spec.aliases,
        values=spec.values,
        getter=(lambda row, column=spec.column.key: row[column]),
    )
    for spec in query.ENTITIES["artifacts"].fields
    if spec.column is not None
)
ROW_ARTIFACTS = Entity(
    name="rowartifacts",
    label="Artifacts",
    permission="read",
    fields=_ROW_FIELDS,
    text_fields=("name", "hash", "detail", "tags"),
)

CASES = {
    # text: contains, case-insensitive; wildcards anchor; LIKE's own wildcards are text
    "name:invoice": {"file-a", "mail-c"},
    "name:INVOICE*": {"file-a"},
    "name:*.exe": {"file-a"},
    "name:!invoice": {"file-b", "pcap-d", "url-e"},
    'name:"your invoice"': {"mail-c"},
    "name:100%": {"file-b"},
    "name:100%_d": {"file-b"},
    "name:c?pture*": {"pcap-d"},
    r"detail:C:\Temp\a_b": {"url-e"},
    r"detail:*\Temp\a?b": {"url-e"},  # with a wildcard the value is matched whole
    r"detail:\Temp\a?b": set(),
    'detail:""': {"pcap-d"},
    "detail:*": {"file-a", "file-b", "mail-c", "url-e"},
    # keyword: equals; wildcards allowed
    "kind:file": {"file-a", "file-b"},
    "type:FILE": {"file-a", "file-b"},
    "kind:!file": {"mail-c", "pcap-d", "url-e"},
    # "Is not" before the field (5.0), and lists.
    "!kind:file": {"mail-c", "pcap-d", "url-e"},
    "!name:invoice": {"file-b", "pcap-d", "url-e"},
    "!tag:phish": {"file-a", "file-b", "pcap-d"},
    "kind IN (file, mail)": {"file-a", "file-b", "mail-c"},
    "kind in (pcap)": {"pcap-d"},
    "kind NOT IN (file, mail)": {"pcap-d", "url-e"},
    "kind IN (file, mail) !name:invoice": {"file-b"},
    "!(kind:file or kind:mail)": {"pcap-d", "url-e"},
    "kind IN (p*, url)": {"pcap-d", "url-e"},
    "kind:p*": {"pcap-d"},
    "verdict:phishing": {"mail-c"},
    'verdict:""': {"file-b", "pcap-d"},
    "verdict:*": {"file-a", "mail-c", "url-e"},
    "by:anna": {"file-a", "mail-c", "url-e"},
    "createdBy:api:feed": {"pcap-d"},
    "by:api*": {"pcap-d"},
    # number
    "score:90": {"file-a"},
    "score:>=70": {"file-a", "mail-c"},
    "score:<40": {"pcap-d"},
    "score:!0": {"file-a", "file-b", "mail-c", "url-e"},
    "score:[40 TO 70]": {"mail-c", "url-e"},
    "score:[* TO 40]": {"pcap-d", "url-e"},
    'score:""': {"file-b"},
    "score:*": {"file-a", "mail-c", "pcap-d", "url-e"},
    "size:>1000000": {"pcap-d"},
    # date (now is 2026-11-17 12:00 UTC)
    "created:today": {"file-a"},
    "created:yesterday": {"file-b"},
    "created:2026-11-10": {"mail-c"},
    "created:2026-11": {"file-a", "file-b", "mail-c"},
    "created:>=2026-11-16": {"file-a", "file-b"},
    "created:>2026-11-16": {"file-a"},
    "created:<2026-11-10": {"pcap-d", "url-e"},
    "created:<=2026-11-10": {"mail-c", "pcap-d", "url-e"},
    "created:>=now-7d": {"file-a", "file-b", "mail-c"},
    'created:>"7 days ago"': {"file-a", "file-b"},
    'created:"7 days ago"': {"mail-c"},  # an instant asked with ":" is its day
    "created:[2026-10-01 TO 2026-11-10]": {"mail-c", "pcap-d"},
    "created:[2026-11-16 TO *]": {"file-a", "file-b"},
    "created:!today": {"file-b", "mail-c", "pcap-d", "url-e"},
    # tags
    "tags:phish": {"mail-c", "url-e"},
    "tag:PHISH": {"mail-c", "url-e"},
    "tag:ph*": {"mail-c", "url-e"},
    "tag:phi": set(),  # a tag is matched whole
    "tag:!phish": {"file-a", "file-b", "pcap-d"},
    'tags:""': {"file-b", "pcap-d"},
    "tags:*": {"file-a", "mail-c", "url-e"},
    # free text: any of name, hash, detail, tags
    "invoice": {"file-a", "mail-c"},
    "evil.example": {"mail-c", "url-e"},
    "kit": {"url-e"},
    "DD44": {"pcap-d"},
    '"plain text"': {"file-b"},
    "http://evil.example/login": {"url-e"},  # an address is text, not a field named http
    "100%": {"file-b"},
    "a_b": {"url-e"},
    "*.txt": {"file-b"},
    # and, or, not, groups
    "kind:file invoice": {"file-a"},
    "kind:file or kind:mail": {"file-a", "file-b", "mail-c"},
    "kind:file -invoice": {"file-b"},
    "not (kind:file or kind:mail)": {"pcap-d", "url-e"},
    "(kind:file or kind:mail) score:>=70 by:anna": {"file-a", "mail-c"},
    "kind:file and not verdict:* or kind:pcap": {"file-b", "pcap-d"},
    "": {"file-a", "file-b", "mail-c", "pcap-d", "url-e"},
}


@pytest.fixture()
def stored(client):
    """The artifacts above, in the table and as rows."""
    with SessionLocal() as db:
        for row in ARTIFACTS:
            keys = (
                "id",
                "kind",
                "ref",
                "name",
                "verdict",
                "score",
                "detail",
                "size",
                "tags",
                "created_at",
                "created_by",
            )
            db.add(Artifact(**dict(zip(keys, row, strict=True))))
        db.add(Incident(id="inc-1", name="one", doc={}))
        db.flush()
        db.add(ArtifactLink(artifact_id="mail-c", incident_id="inc-1"))
        db.commit()
    keys = ("id", "kind", "ref", "name", "verdict", "score", "detail", "size", "tags", "created_at", "created_by")
    return [dict(zip(keys, row, strict=True)) for row in ARTIFACTS]


@pytest.mark.parametrize("text", CASES, ids=lambda t: t or "(empty)")
def test_a_condition_means_the_same_in_sql_and_on_rows(stored, monkeypatch, text):
    expected = CASES[text]
    with SessionLocal() as db:
        found = set(db.scalars(select(Artifact.id).where(*query.sql("artifacts", text, now=NOW))))
    assert found == expected, "SQL"
    monkeypatch.setitem(query.ENTITIES, "rowartifacts", ROW_ARTIFACTS)
    keep = query.rows("rowartifacts", text, now=NOW)
    assert {row["id"] for row in stored if keep(row)} == expected, "rows"


def test_fields_that_are_not_a_column(stored):
    def ids(text):
        with SessionLocal() as db:
            return set(db.scalars(select(Artifact.id).where(*query.sql("artifacts", text))))

    assert ids("linked:true") == ids("linked:yes") == {"mail-c"}
    assert ids("linked:false") == ids("linked:!true") == {"file-a", "file-b", "pcap-d", "url-e"}
    assert ids("incident:inc-1") == {"mail-c"} and ids("incident:nope") == set()
    assert ids("incident:*") == {"mail-c"} and ids('incident:""') == ids("-incident:*")
    assert ids("incident:!inc-1") == {"file-a", "file-b", "pcap-d", "url-e"}


def test_ordered_fields_compare_by_rank(admin: TestClient):
    for name, severity in (("a", "low"), ("b", "medium"), ("c", "high"), ("d", "critical"), ("e", "")):
        doc = {"id": name, "name": name, "severity": severity, "data": {}}
        assert admin.post("/api/incidents", json=doc).status_code == 201

    def names(q):
        res = admin.get("/api/incidents", params={"view": "summary", "q": q})
        assert res.status_code == 200, res.text
        return sorted(row["name"] for row in res.json()["incidents"])

    assert names("severity:>=high") == ["c", "d"]
    assert names("severity:>low") == ["b", "c", "d"]
    assert names("severity:<medium") == ["a"]
    assert names("severity:<=medium") == ["a", "b"]
    assert names("severity:[medium TO high]") == ["b", "c"]
    assert names("severity:high") == ["c"] and names("severity:!high") == ["a", "b", "d", "e"]
    assert names('severity:""') == ["e"] and names("severity:*") == ["a", "b", "c", "d"]
    assert names("severity:<low") == []


# --------------------------------------------------------------------------- #
# Errors: a position and a fixed sentence                                     #
# --------------------------------------------------------------------------- #
def _error(entity: str, text: str) -> QueryError:
    with pytest.raises(QueryError) as caught:
        if query.ENTITIES[entity].model is None:
            query.rows(entity, text)
        else:
            query.sql(entity, text)
    return caught.value


def test_what_cannot_be_compiled_says_where_and_why():
    error = _error("incidents", "status:open stauts:closed")
    assert (error.code, error.position, error.suggestion) == ("unknown_field", 12, "status")
    assert error.message == '"stauts" is not a field of incidents: did you mean "status"?'
    assert _error("incidents", "zzzzzz:1").suggestion is None

    error = _error("incidents", "name:x status:opne")
    assert (error.code, error.position, error.suggestion) == ("bad_value", 7, "open")
    assert error.message == '"status" is one of: open, in_progress, closed'
    assert _error("incidents", "severity:>=urgent").code == "bad_value"
    assert _error("incidents", "severity:>=h*").code == "bad_value"
    assert _error("artifacts", "score:high").message == "A number is expected here"
    assert _error("artifacts", "score:nan").code == "bad_value"
    assert _error("artifacts", "created:soon").code == "bad_value"
    assert _error("artifacts", "linked:maybe").message == "true or false is expected here"
    assert _error("incidents", "hasMail:>true").code == "bad_operator"
    assert _error("incidents", "name:>a").code == "bad_operator"
    assert _error("artifacts", "tags:<a").code == "bad_operator"
    assert _error("incidents", 'owner:>""').code == "bad_operator"
    assert _error("incidents", "name:[a TO b]").code == "bad_range"
    assert _error("artifacts", "linked:[a TO b]").code == "bad_range"
    assert _error("incidents", "name:" + "*a" * 9).code == "too_many_wildcards"
    assert _error("indicators", "verdict:bad").suggestion is None
    assert _error("indicators", "tpye:ip").suggestion == "type"
    with pytest.raises(QueryError) as caught:
        query.entity_of("incident")
    assert caught.value.code == "unknown_entity" and caught.value.suggestion == "incidents"
    # The indicator library is not a table.
    with pytest.raises(QueryError):
        query.sql("indicators", "type:ip")


def test_what_reads_as_an_address_or_a_path_is_text_not_an_unknown_field(stored):
    def ids(text):
        with SessionLocal() as db:
            return set(db.scalars(select(Artifact.id).where(*query.sql("artifacts", text))))

    assert ids("http://evil.example/login") == {"url-e"}
    assert ids(r"C:\Temp\a_b") == {"url-e"}
    assert ids("fe80::1") == set() and ids("aa:bb:cc:dd:ee:ff") == set()
    # Anything else with a colon names a field, and an unknown one is an error.
    assert _error("artifacts", "evil:example").code == "unknown_field"


# --------------------------------------------------------------------------- #
# Indicators: rows                                                            #
# --------------------------------------------------------------------------- #
INDICATORS = [
    {"type": "ip", "value": "185.220.101.47", "verdict": "malicious", "score": 95, "origin": "incident", "incidents": 3,
     "tags": ["c2"], "note": "seen in WKS-1", "tlp": "amber", "lists": [{"id": "l1", "name": "Blocklist"}],
     "expired": False, "expires": None, "firstSeen": "2026-11-10T09:00:00+00:00", "checkedAt": "2026-11-17T08:00:00+00:00",
     "allowlisted": False, "analysis": None, "addedBy": None},
    {"type": "domain", "value": "evil.example", "verdict": "suspicious", "score": 40, "origin": "manual", "incidents": 0,
     "tags": ["phish", "kit"], "note": "", "tlp": None, "lists": [], "expired": True, "expires": "2026-01-01",
     "firstSeen": "2026-11-16T09:00:00+00:00", "checkedAt": None, "allowlisted": False, "analysis": {"id": "x"},
     "addedBy": "anna"},
    {"type": "domain", "value": "intranet.corp", "verdict": None, "score": None, "origin": "import", "incidents": 0,
     "tags": [], "note": "ours", "tlp": "red", "lists": [{"id": "l2", "name": "Watch"}, {"id": "l1", "name": "Blocklist"}],
     "expired": False, "expires": None, "firstSeen": None, "checkedAt": None, "allowlisted": True, "analysis": None,
     "addedBy": "bob"},
    {"type": "sha256", "value": "a" * 64, "verdict": "harmless", "score": 0, "origin": "artifact", "incidents": 1,
     "tags": [], "note": "", "tlp": "clear", "lists": [], "expired": False, "expires": "2027-06-01",
     "firstSeen": "2025-01-01T00:00:00+00:00", "checkedAt": "2026-11-01T00:00:00+00:00", "allowlisted": False,
     "analysis": None, "addedBy": None},
]  # fmt: skip


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("type:domain", ["evil.example", "intranet.corp"]),
        ("kind:ip or type:sha256", ["185.220.101.47", "a" * 64]),
        ("verdict:>=suspicious", ["185.220.101.47", "evil.example"]),
        ("verdict:<suspicious", ["a" * 64]),
        ('verdict:""', ["intranet.corp"]),
        ("verdict:*", ["185.220.101.47", "evil.example", "a" * 64]),
        ("score:>=40", ["185.220.101.47", "evil.example"]),
        ("-score:*", ["intranet.corp"]),
        ("origin:manual or origin:import", ["evil.example", "intranet.corp"]),
        ("incidents:>0", ["185.220.101.47", "a" * 64]),
        ("tag:phish", ["evil.example"]),
        ("tlp:red", ["intranet.corp"]),
        ('tlp:""', ["evil.example"]),
        ("list:blocklist", ["185.220.101.47", "intranet.corp"]),
        ("list:l2", ["intranet.corp"]),
        ("list:*", ["185.220.101.47", "intranet.corp"]),
        ('list:""', ["evil.example", "a" * 64]),
        ("-list:blocklist", ["evil.example", "a" * 64]),
        ("expired:true", ["evil.example"]),
        ("expires:>2026-12-31", ["a" * 64]),
        ("firstSeen:>=2026-11-10", ["185.220.101.47", "evil.example"]),
        ("firstSeen:>=now-7d", ["evil.example"]),
        ("checked:today", ["185.220.101.47"]),
        ("-checked:*", ["evil.example", "intranet.corp"]),
        ("allowlisted:yes", ["intranet.corp"]),
        ("analysed:true", ["evil.example"]),
        ("addedBy:anna", ["evil.example"]),
        # Free text: the value, the note, the tags, the names of the lists.
        ("evil", ["evil.example"]),
        ("wks-1", ["185.220.101.47"]),
        ("kit", ["evil.example"]),
        ("watch", ["intranet.corp"]),
        ("185.220.*", ["185.220.101.47"]),
        ("type:domain -allowlisted:true verdict:>=suspicious", ["evil.example"]),
    ],
)
def test_indicators_are_queried_as_rows(text, expected):
    keep = query.rows("indicators", text, now=NOW)
    assert [row["value"] for row in INDICATORS if keep(row)] == expected


# --------------------------------------------------------------------------- #
# The endpoints                                                               #
# --------------------------------------------------------------------------- #
def test_the_incident_list_takes_a_query_and_the_older_parameters_still_work(admin: TestClient):
    docs = [
        {"id": "i1", "name": "INC-1 · WKS-FINANCE-01", "host": "WKS-FINANCE-01", "username": "m.rossi", "ticketId": "INC-1",
         "severity": "high", "status": "open", "assignee": "admin", "data": {}},
        {"id": "i2", "name": "SRV-DB-02", "host": "SRV-DB-02", "username": "svc_sql", "severity": "low",
         "status": "closed", "assignee": "", "data": {}},
        {"id": "i3", "name": "WKS-HR-07", "host": "WKS-HR-07", "username": "a.bianchi", "severity": "critical",
         "status": "in_progress", "assignee": "", "data": {}},
    ]  # fmt: skip
    stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")  # as the browser writes it
    for doc in docs:
        created = admin.post("/api/incidents", json={**doc, "createdAt": stamp, "updatedAt": stamp})
        assert created.status_code == 201

    def ids(**params):
        res = admin.get("/api/incidents", params={"view": "summary", **params})
        assert res.status_code == 200, res.text
        assert res.headers["X-Total-Count"] == str(res.json()["total"])
        return sorted(row["id"] for row in res.json()["incidents"])

    # Plain words are what `q` always took: name, host, user, ticket.
    assert ids(q="wks") == ["i1", "i3"] and ids(q="INC-1") == ["i1"] and ids(q="svc_sql") == ["i2"]
    assert ids(q="wks finance") == ["i1"]
    # The language.
    assert ids(q="status:open") == ["i1"]
    assert ids(q="-status:closed severity:>=high") == ["i1", "i3"]
    assert ids(q='owner:"" -status:closed') == ["i3"]
    assert ids(q="assignee:admin or host:srv-*") == ["i1", "i2"]
    assert ids(q="user:rossi ticket:inc-1 created:today") == ["i1"]
    assert ids(q="modified:<yesterday") == []
    assert ids(q="hasMail:false") == ["i1", "i2", "i3"]
    # The older parameters add to it; whole documents come back as before.
    assert ids(q="wks", status="open") == ["i1"]
    assert ids(q="severity:>=low", assignee="") == ["i2", "i3"]
    assert ids(host="hr") == ["i3"]
    full = admin.get("/api/incidents", params={"q": "status:closed"}).json()["incidents"]
    assert [doc["id"] for doc in full] == ["i2"] and "data" in full[0]

    # What cannot be read is a 422 that says where and why, in a fixed sentence.
    res = admin.get("/api/incidents", params={"q": "status:open and stauts:closed"})
    assert res.status_code == 422
    assert res.json() == {
        "detail": '"stauts" is not a field of incidents: did you mean "status"?',
        "query": {
            "code": "unknown_field",
            "position": 16,
            "message": '"stauts" is not a field of incidents: did you mean "status"?',
            "suggestion": "status",
        },
    }
    assert admin.get("/api/incidents", params={"q": '(name:"x'}).json()["query"]["code"] == "unclosed_quote"
    assert admin.get("/api/incidents", params={"q": "x" * 2001}).status_code == 422


def test_the_artifact_list_and_the_audit_log_take_a_query(admin: TestClient, stored):
    def ids(**params):
        res = admin.get("/api/artifacts", params=params)
        assert res.status_code == 200, res.text
        return sorted(row["id"] for row in res.json()["artifacts"]), res.json()

    assert ids(q="invoice")[0] == ["file-a", "mail-c"]
    assert ids(q="kind:mail or verdict:malicious")[0] == ["file-a", "mail-c"]
    assert ids(q="score:>=40 -kind:file")[0] == ["mail-c", "url-e"]
    # The older parameters add to it, and the counts per kind follow the query.
    found, body = ids(q="by:anna", kind="file")
    assert found == ["file-a"] and body["total"] == 1
    assert body["counts"] == {"file": 1, "mail": 1, "pcap": 0, "url": 1, "mailbox": 0}
    assert ids(q="tag:phish", linked="true")[0] == ["mail-c"]
    assert ids(tag="c2")[0] == ["file-a"]
    assert admin.get("/api/artifacts", params={"q": "knid:file"}).json()["query"]["suggestion"] == "kind"

    with SessionLocal() as db:
        db.add(AuditEntry(id="old", at="2026-01-05T10:00:00+00:00", actor="anna", action="incident.delete",
                          target=None, details="Deleted WKS-1", incident_id="i9", incident_name="WKS-1"))  # fmt: skip
        db.commit()

    def actions(**params):
        res = admin.get("/api/audit", params=params)
        assert res.status_code == 200, res.text
        return [entry["action"] for entry in res.json()["entries"]]

    assert actions(q="action:incident.*") == ["incident.delete"]
    assert actions(q="at:2026-01 actor:ann") == ["incident.delete"]
    assert actions(q="wks-1") == ["incident.delete"]  # plain words, as before
    assert actions(q='target:"" incidentId:i9') == ["incident.delete"]
    assert "incident.delete" not in actions(q="at:>=today")
    assert actions(q="-action:incident.delete", actor="anna") == []
    assert admin.get("/api/audit", params={"q": "actoin:x"}).json()["query"]["suggestion"] == "action"


def test_a_filter_of_the_library_reads_its_text_as_a_query_wherever_it_is_used():
    """The list and the scopes of export, bulk check and lists share select_rows."""
    from app import ioc_library as lib

    def values(q):
        return sorted(row["value"] for row in lib.select_rows(INDICATORS, {"q": q}))

    assert values("type:domain -tag:phish") == ["intranet.corp"]
    assert values("#phish") == ["evil.example"]  # the older way to ask for a tag
    assert values("evil") == ["evil.example"] and len(values("")) == 4
    assert values("type:domain") == sorted(
        row["value"] for row in lib.select_rows(INDICATORS, {"q": "", "type": "domain"})
    )
    with pytest.raises(QueryError):
        lib.select_rows(INDICATORS, {"q": "tpye:ip"})


def test_the_indicator_library_takes_a_query(admin: TestClient):
    added = admin.post(
        "/api/iocs", json={"text": "185.220.101.47\nevil.example.org\nhttp://evil.example.org/kit", "tags": ["phish"]}
    )
    assert added.status_code in (200, 201), added.text

    def values(**params):
        res = admin.get("/api/iocs", params=params)
        assert res.status_code == 200, res.text
        return sorted(row["value"] for row in res.json()["iocs"])

    assert values(q="type:ip") == ["185.220.101.47"]
    assert values(q="type:domain or type:url") == ["evil.example.org", "http://evil.example.org/kit"]
    assert values(q="evil -type:url") == ["evil.example.org"]
    assert values(q="http://evil.example.org/kit") == ["http://evil.example.org/kit"]
    assert values(q='verdict:"" tag:phish origin:manual') == sorted(
        ["185.220.101.47", "evil.example.org", "http://evil.example.org/kit"]
    )
    assert values(q="#phish", type="ip") == ["185.220.101.47"]  # the older ways still work
    assert values(q="incidents:>0") == []
    res = admin.get("/api/iocs", params={"q": "verdict:>=bad"})
    assert res.status_code == 422 and res.json()["query"]["code"] == "bad_value"


def test_the_query_endpoints_say_what_can_be_asked_and_run_it(admin: TestClient, stored):
    entities = {e["entity"]: e for e in admin.get("/api/query/schema").json()["entities"]}
    assert sorted(entities) == ["approvals", "artifacts", "audit", "incidents", "indicators", "runs", "tasks"]
    severity = next(f for f in entities["incidents"]["fields"] if f["name"] == "severity")
    assert severity["kind"] == "ordered" and severity["values"] == ["low", "medium", "high", "critical"]
    owner = next(f for f in entities["incidents"]["fields"] if f["name"] == "owner")
    assert owner["aliases"] == ["assignee"] and owner["description"]
    assert entities["incidents"]["textFields"] == ["name", "host", "username", "ticket"]
    for entity in entities.values():  # every field says what it is
        assert all(f["kind"] and f["description"] for f in entity["fields"]), entity["entity"]
    one = admin.get("/api/query/schema", params={"entity": "artifacts"}).json()["entities"]
    assert [e["entity"] for e in one] == ["artifacts"]
    assert admin.get("/api/query/schema", params={"entity": "nope"}).status_code == 422

    res = admin.post("/api/query", json={"entity": "artifacts", "query": "kind:file", "limit": 1})
    assert res.status_code == 200
    assert res.json()["total"] == 2 and [row["id"] for row in res.json()["items"]] == ["file-a"]  # newest first
    page = admin.post("/api/query", json={"entity": "artifacts", "query": "kind:file", "limit": 1, "offset": 1})
    assert [row["id"] for row in page.json()["items"]] == ["file-b"]
    assert admin.post("/api/query", json={"entity": "incidents", "query": "one"}).json()["total"] == 1
    assert admin.post("/api/query", json={"entity": "audit", "query": "action:user.create"}).json()["total"] == 1
    assert admin.post("/api/query", json={"entity": "indicators", "query": "type:ip"}).json() == {
        "entity": "indicators",
        "total": 0,
        "items": [],
    }
    assert admin.post("/api/query", json={"entity": "artifacts", "query": "x", "limit": 501}).status_code == 422
    assert admin.post("/api/query", json={"entity": "nope", "query": ""}).json()["query"]["code"] == "unknown_entity"

    ok = admin.post("/api/query/check", json={"entity": "incidents", "query": "status:open -owner:*"})
    assert ok.json()["ok"] is True and ok.json()["tree"]["and"][1] == {
        "not": {
            "field": "owner",
            "op": "=",
            "value": {"text": "*", "quoted": False, "pattern": [{"wild": "*"}]},
            "position": 13,
        }
    }
    bad = admin.post("/api/query/check", json={"entity": "incidents", "query": "status:nope"})
    assert bad.status_code == 422 and bad.json()["query"]["position"] == 0


def test_the_permission_of_an_entity_is_part_of_the_query(admin: TestClient, stored):
    viewer = make_key(admin, label="v", roles=["viewer"])
    auditor = make_key(admin, label="a", roles=["audit"])
    caller = TestClient(fastapi_app)

    def status(key, entity):
        return caller.post("/api/query", headers=key, json={"entity": entity, "query": ""}).status_code

    assert [status(viewer, e) for e in ("incidents", "artifacts", "indicators", "audit")] == [200, 200, 200, 403]
    assert [status(auditor, e) for e in ("incidents", "artifacts", "indicators", "audit")] == [403, 403, 403, 200]
    # The schema lists what the caller may query, and a check does not get round it.
    listed = caller.get("/api/query/schema", headers=auditor).json()["entities"]
    assert [e["entity"] for e in listed] == ["audit"]
    assert caller.get("/api/query/schema", headers=auditor, params={"entity": "incidents"}).status_code == 403
    assert caller.post("/api/query/check", headers=viewer, json={"entity": "audit", "query": "x"}).status_code == 403
    assert caller.post("/api/query", json={"entity": "incidents", "query": ""}).status_code == 401
