"""The views of host evidence (7.0): the histogram, the stack, the fields, the viewer, a page of bytes
and the download of the original.

The worker is not there: ``parse._events`` and ``views.ask_view`` are what it would have said.
"""

# ruff: noqa: F811 - the fixture ``env`` is imported, and each test names it as its argument
from __future__ import annotations

import io
import urllib.error

import pytest
import pyzipper
from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import AuditEntry, EvidenceRecord, EvidenceSource
from app.evidence import originals, views
from app.workers import handover
from tests.conftest import make_key
from tests.test_evidence_api import BASE, SOURCE, end, env, event, get, make_source  # noqa: F401 - env is a fixture

BASE_URL = "/api/incidents/ev-api/evidence"
MINUTE = 60_000


def at(offset: int, **more) -> dict:
    """A record at ``BASE + offset`` ms, with a key of its own."""
    return event(offset, key=f"k:{offset}:{more.get('type', '')}:{more.get('host', '')}", ts=BASE + offset, **more)


def undated(number: int) -> dict:
    return event(number, key=f"undated:{number}", ts=None)


def histogram(env, **params) -> dict:
    res = get(env, "ev-api/evidence/histogram", **params)
    assert res.status_code == 200, res.text
    return res.json()


# --------------------------------------------------------------------------- #
# The histogram                                                               #
# --------------------------------------------------------------------------- #
def test_a_bucket_is_a_whole_division_and_counts_its_kinds_and_the_undated(env):
    # 1000 ms in 10 buckets: width 100. 150 is in bucket 1 (a rounding would put it in 2), 99 in 0.
    offsets = [0, 99, 100, 150, 199, 200, 999]
    make_source(env, [SOURCE, *(at(o) for o in offsets if o != 150), undated(1), undated(2), end(8)], data=b"a")
    make_source(env, [at(150), end(1)], data=b"b", kind="browser")
    answer = histogram(env, buckets=10)
    assert (answer["from"], answer["to"], answer["width"]) == (BASE, BASE + 999, 100)
    assert answer["undated"] == 2 and answer["total"] == 9
    assert [(b["t"] - BASE, b["count"]) for b in answer["buckets"]] == [(0, 2), (100, 3), (200, 1), (900, 1)]
    assert answer["buckets"][1]["byKind"] == {"eventlog": 2, "browser": 1}
    assert answer["buckets"][0]["byKind"] == {"eventlog": 2}


def test_a_width_that_does_not_divide_the_range_cuts_at_the_same_places_on_both_databases(env):
    # 1001 ms in 10 buckets: width 101; 505 / 101 = 5.0 and 504 / 101 = 4.99: 5 and 4, never rounded.
    make_source(env, [SOURCE, at(0), at(504), at(505), at(1000), end(4)])
    answer = histogram(env, buckets=10)
    assert answer["width"] == 101
    assert [(b["t"] - BASE) // 101 for b in answer["buckets"]] == [0, 4, 5, 9]


def test_the_range_of_the_filter_is_the_range_of_the_buckets(env):
    make_source(env, [SOURCE, at(0), at(500), at(999), end(3)])
    answer = histogram(env, buckets=10, **{"from": BASE + 400, "to": BASE + 600})
    assert (answer["from"], answer["to"], answer["width"]) == (BASE + 400, BASE + 600, 21)
    assert [b["count"] for b in answer["buckets"]] == [1]
    assert answer["total"] == 1


def test_a_gap_at_the_threshold_counts_and_one_just_under_does_not_longest_first(env):
    steps = [0, 60 * MINUTE, 60 * MINUTE - 1, 180 * MINUTE, 120 * MINUTE, 60 * MINUTE]
    times, now = [], 0
    for step in steps:
        now += step
        times.append(now)
    make_source(env, [SOURCE, *(at(t) for t in times), end(len(times))])
    gaps = histogram(env, gapMinutes=60)["gaps"]
    assert [g["minutes"] for g in gaps] == [180, 120, 60, 60]
    assert [(g["from"] - BASE, g["to"] - BASE) for g in gaps[2:]] == [
        (times[0], times[1]),
        (times[4], times[5]),
    ]
    assert histogram(env, gapMinutes=181)["gaps"] == []


def test_a_burst_is_a_bucket_far_over_the_median_and_over_twenty(env):
    counts = ((0, 1), (1, 1), (2, 1), (3, 1), (4, 19), (5, 30))
    rows = [at(n * 100 + j) for n, count in counts for j in range(count)]
    make_source(env, [SOURCE, *rows, at(999), end(len(rows) + 1)])
    answer = histogram(env, buckets=10)
    assert [b["count"] for b in answer["buckets"]] == [1, 1, 1, 1, 19, 30, 1]
    assert answer["bursts"] == [{"t": BASE + 500, "count": 30, "factor": 30.0}]
    assert histogram(env, buckets=10, burstFactor=31)["bursts"] == []


def test_the_histogram_follows_the_filters(env):
    make_source(env, [SOURCE, at(0), at(100, host="H2"), end(2)], data=b"a")
    make_source(env, [at(500), at(999), end(2)], data=b"b", kind="browser")
    assert histogram(env, kind="browser")["total"] == 2
    assert histogram(env, host="H2")["total"] == 1
    assert histogram(env, kind="browser", buckets=10)["from"] == BASE + 500


def test_an_incident_with_no_dated_record_has_nothing_to_draw(env):
    assert get(env, "ev-other/evidence/histogram").json() == {
        "from": None,
        "to": None,
        "width": 0,
        "buckets": [],
        "gaps": [],
        "bursts": [],
        "undated": 0,
        "total": 0,
    }
    make_source(env, [SOURCE, undated(1), end(1)])
    answer = histogram(env)
    assert answer["from"] is None and answer["buckets"] == [] and answer["undated"] == 1


def test_the_parameters_of_the_histogram_have_their_limits(env):
    for params in ({"buckets": 9}, {"buckets": 501}, {"gapMinutes": 0}, {"gapMinutes": 100001}, {"burstFactor": 1}):
        assert get(env, "ev-api/evidence/histogram", **params).status_code == 422, params


# --------------------------------------------------------------------------- #
# The stack                                                                   #
# --------------------------------------------------------------------------- #
def stack(env, field: str, **params):
    return get(env, "ev-api/evidence/stack", field=field, **params)


@pytest.fixture()
def stacked(env):
    rows = [
        at(
            1,
            host="H1",
            username="u1",
            channel="Security",
            event_id=4624,
            data={"Ip": "10.0.0.1", "Port": 443, "On": True, "a.b": "x"},
        ),
        at(2, host="H1", username="u1", channel="Security", event_id=4624, data={"Ip": "10.0.0.1"}),
        at(3, host="H1", username="u1", channel="Security", event_id=4624, data={"Ip": "10.0.0.2", "Port": None}),
        at(4, host="H2", username="u2", channel="System", event_id=4625, type="logon", data={"Ip": ""}),
        at(5, host="H2", username="u3", channel="System", event_id=None, type="logon", data={"Ip": "10.0.0.2"}),
        at(6, host="", username="", channel="", event_id=None, data={}),
    ]
    make_source(env, [SOURCE, *rows, end(6)], data=b"one")
    make_source(env, [{**SOURCE, "source": "chrome.history"}, at(7, host="H3"), end(1)], data=b"two", kind="browser")
    return env


def values(answer: dict) -> list[tuple]:
    return [(v["value"], v["count"]) for v in answer["values"]]


def test_each_column_is_stacked_with_its_missing_and_its_times(stacked):
    answer = stack(stacked, "username").json()
    assert values(answer) == [("u2", 1), ("u3", 1), ("u1", 3)]
    assert (answer["distinct"], answer["distinctCapped"], answer["missing"], answer["field"]) == (
        3,
        False,
        2,
        "username",
    )
    u1 = stack(stacked, "username", order="common").json()["values"][0]
    assert (u1["value"], u1["count"], u1["first"], u1["last"]) == ("u1", 3, BASE + 1, BASE + 3)
    assert values(stack(stacked, "username", order="common").json()) == [("u1", 3), ("u2", 1), ("u3", 1)]
    assert values(stack(stacked, "host").json()) == [("H3", 1), ("WKS-042", 1), ("H2", 2), ("H1", 3)]
    assert stack(stacked, "host").json()["missing"] == 0
    assert values(stack(stacked, "channel").json()) == [("System", 2), ("Security", 4)]
    assert values(stack(stacked, "type").json()) == [("logon", 2), ("event", 5)]
    assert values(stack(stacked, "kind").json()) == [("browser", 1), ("eventlog", 6)]
    assert values(stack(stacked, "source").json()) == [("chrome.history", 1), ("evtx", 6)]
    events = stack(stacked, "eventId").json()
    assert values(events) == [(4625, 1), (4624, 4)] and events["missing"] == 2
    assert values(stack(stacked, "username", limit=1).json()) == [("u2", 1)]


def test_a_field_of_the_data_is_stacked_as_text_on_both_databases(stacked):
    assert values(stack(stacked, "data.Ip").json()) == [("10.0.0.1", 2), ("10.0.0.2", 2)]
    ip = stack(stacked, "data.Ip").json()
    assert ip["missing"] == 3 and ip["distinct"] == 2  # the empty one, and the two with no Ip
    port = stack(stacked, "data.Port", order="common").json()
    assert values(port) == [("443", 1)] and port["missing"] == 6
    assert values(stack(stacked, "data.On").json()) == [("true", 1)]
    assert values(stack(stacked, "data.a.b").json()) == [("x", 1)]


def test_the_stack_follows_the_filters(stacked):
    assert values(stack(stacked, "username", host="H1").json()) == [("u1", 3)]
    assert values(stack(stacked, "host", kind="browser").json()) == [("H3", 1)]
    assert values(stack(stacked, "data.Ip", channel="System").json()) == [("10.0.0.2", 1)]
    assert stack(stacked, "host", **{"from": BASE + 4, "to": BASE + 5}).json()["missing"] == 0


def test_a_bad_field_or_order_is_a_400(stacked):
    for field in ("bogus", "data.", "data.has space", 'data.x"y', "data.a$", "data." + "k" * 81, "summary", "id"):
        assert stack(stacked, field).status_code == 400, field
    assert stack(stacked, "host", order="odd").status_code == 400
    assert stack(stacked, "host", limit=0).status_code == 422
    assert get(stacked, "ev-api/evidence/stack").status_code == 422


# --------------------------------------------------------------------------- #
# The fields                                                                  #
# --------------------------------------------------------------------------- #
def test_the_fields_are_those_of_the_first_500_records_most_seen_first(env):
    rows = [event(n, data={"a": 1, **({"c": 1} if n % 2 else {})}) for n in range(500)]
    rows += [event(n, data={"late": 1}) for n in range(500, 510)]
    make_source(env, [SOURCE, *rows, end(510)])
    fields = get(env, "ev-api/evidence/fields").json()["fields"]
    assert fields == [{"name": "a", "seen": 500}, {"name": "c", "seen": 250}]
    assert get(env, "ev-api/evidence/fields", kind="browser").json() == {"fields": []}


# --------------------------------------------------------------------------- #
# The viewer                                                                  #
# --------------------------------------------------------------------------- #
def a_record(env, data: bytes = b"original of a record"):
    source_id = make_source(env, [SOURCE, event(1, loc={"offset": 4096, "length": 512}), end(1)], data=data)
    with SessionLocal() as db:
        record_id = db.scalar(select(EvidenceRecord.id).where(EvidenceRecord.source_id == source_id))
    return source_id, record_id


def change(source_id: str, **values_):
    with SessionLocal() as db:
        row = db.get(EvidenceSource, source_id)
        for name, value in values_.items():
            setattr(row, name, value)
        db.commit()
        return row.sha256


def test_the_view_is_the_answer_of_the_worker_with_its_file(env):
    source_id, record_id = a_record(env)
    asked = []

    def ask(sha256, body):
        asked.append((sha256, body))
        return 200, {"kind": "text", "title": "Event 1", "where": "offset 4096", "cut": False}

    env["monkeypatch"].setattr(views, "ask_view", ask)
    res = get(env, f"ev-api/evidence/records/{record_id}/view")
    assert res.status_code == 200
    assert res.json() == {
        "kind": "text",
        "title": "Event 1",
        "where": "offset 4096",
        "cut": False,
        "sourceId": source_id,
        "fileName": "Security.evtx",
    }
    assert asked[0][1]["loc"] == {"offset": 4096, "length": 512}


def test_the_view_says_why_there_is_no_original_to_show(env):
    source_id, record_id = a_record(env)
    env["monkeypatch"].setattr(views, "ask_view", lambda *_: (200, {"kind": "text"}))
    path = f"ev-api/evidence/records/{record_id}/view"
    change(source_id, legacy=True)
    res = get(env, path)
    assert res.status_code == 404 and res.json()["detail"] == views.LEGACY
    assert "imported before 7.0" in res.json()["detail"]
    sha256 = change(source_id, legacy=False, state="absent")
    assert get(env, path).json()["detail"] == views.NO_ORIGINAL
    change(source_id, state="archived")
    res = get(env, path)
    assert res.status_code == 404 and res.json()["detail"] == views.ARCHIVED
    change(source_id, state="done")
    assert get(env, path).status_code == 200
    originals.remove(sha256)
    res = get(env, path)
    assert res.status_code == 404 and res.json()["detail"] == views.NO_ORIGINAL


def test_the_view_needs_a_worker_and_passes_its_refusals_on(env):
    _source_id, record_id = a_record(env)
    path = f"ev-api/evidence/records/{record_id}/view"
    answers = [
        (404, {"detail": "no such place"}),
        (422, {"detail": "bad loc"}),
        (503, {"detail": "busy"}),
        (504, {"detail": "slow"}),
        (409, {"missing": ["x"]}),
        (500, {}),
        (502, {"detail": "down"}),
    ]
    env["monkeypatch"].setattr(views, "ask_view", lambda *_: answers.pop(0))
    seen = []
    while answers:
        res = get(env, path)
        seen.append((res.status_code, res.json()["detail"]))
    assert seen[:4] == [(404, "no such place"), (422, "bad loc"), (503, "busy"), (504, "slow")]
    assert [code for code, _ in seen[4:]] == [502, 502, 502] and seen[6][1] == "down"
    env["monkeypatch"].setattr(settings, "FORENSICS_URL", "")
    res = get(env, path)
    assert res.status_code == 503 and "FORENSICS_URL" in res.json()["detail"]


def test_ask_view_gives_the_original_when_the_worker_lacks_it_and_asks_again(env):
    sha256 = originals.keep_bytes(b"for the worker")
    calls, given = [], []

    class Answer:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return b'{"kind": "xml"}'

    def urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        if len(calls) == 1:
            raise urllib.error.HTTPError(request.full_url, 409, "missing", {}, io.BytesIO(b'{"missing": ["x.bin"]}'))
        return Answer()

    env["monkeypatch"].setattr(views.urllib.request, "urlopen", urlopen)
    env["monkeypatch"].setattr(handover, "give", lambda *args, **_: given.append(args[3]))
    assert views.ask_view(sha256, {"parser": "evtx", "loc": {}}) == (200, {"kind": "xml"})
    assert calls == [("http://forensics.test/view", 40)] * 2 and given == [f"{sha256}.bin"]
    # A worker that still lacks the file the second time is a 409 for the caller to make a 502 of.
    calls.clear()

    def lacking(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 409, "missing", {}, io.BytesIO(b'{"missing": ["x.bin"]}'))

    env["monkeypatch"].setattr(views.urllib.request, "urlopen", lacking)
    assert views.ask_view(sha256, {})[0] == 409


# --------------------------------------------------------------------------- #
# A page of the original                                                      #
# --------------------------------------------------------------------------- #
def page(env, source_id: str, **params):
    return get(env, f"ev-api/evidence/sources/{source_id}/page", **params)


def test_a_page_is_bytes_of_the_sealed_original_as_hex_or_text(env):
    data = bytes(range(256))
    source_id, _ = a_record(env, data)
    res = page(env, source_id, offset=0, length=4)
    assert res.json() == {"offset": 0, "length": 4, "size": 256, "as": "hex", "data": "00010203"}
    assert page(env, source_id, offset=250, length=100).json() == {
        "offset": 250,
        "length": 6,
        "size": 256,
        "as": "hex",
        "data": "fafbfcfdfeff",
    }
    assert page(env, source_id).json()["data"] == data.hex()
    for offset in (256, 1000):
        assert page(env, source_id, offset=offset).json() == {
            "offset": offset,
            "length": 0,
            "size": 256,
            "as": "hex",
            "data": "",
        }
    text, _ = a_record(env, "héllo wörld".encode())
    assert page(env, text, **{"as": "text"}).json()["data"] == "héllo wörld"
    # The page ends inside the two bytes of "é": the half character shows as a replacement.
    cut = page(env, text, offset=0, length=2, **{"as": "text"}).json()
    assert cut["data"] == "h�" and cut["length"] == 2


def test_a_page_has_its_limits_and_needs_its_original(env):
    source_id, _ = a_record(env, b"abc")
    for params in ({"length": 0}, {"length": 1048577}, {"offset": -1}, {"as": "base64"}):
        assert page(env, source_id, **params).status_code == 422, params
    assert page(env, source_id, length=1048576).status_code == 200
    change(source_id, legacy=True)
    res = page(env, source_id)
    assert res.status_code == 404 and res.json()["detail"] == views.LEGACY
    sha256 = change(source_id, legacy=False, state="absent")
    assert page(env, source_id).json()["detail"] == views.NO_ORIGINAL
    change(source_id, state="done")
    originals.remove(sha256)
    assert page(env, source_id).json()["detail"] == views.NO_ORIGINAL


# --------------------------------------------------------------------------- #
# The download                                                                #
# --------------------------------------------------------------------------- #
def test_the_download_needs_its_permission_and_gives_an_encrypted_zip_and_an_audit_entry(env, admin):
    data = b"MZ the original of a file " * 100
    source_id, _ = a_record(env, data)
    url = f"{BASE_URL}/sources/{source_id}/download"
    client = env["client"]
    for who in ("r", "w"):
        assert client.get(url, headers=env[who]).status_code == 403
    allowed = make_key(admin, roles=["evidence"])
    res = client.get(url, headers=allowed)
    assert res.status_code == 200 and res.headers["content-type"] == "application/zip"
    assert "Security.evtx.zip" in res.headers["content-disposition"]
    with pyzipper.AESZipFile(io.BytesIO(res.content)) as archive:
        assert archive.namelist() == ["Security.evtx"]
        with pytest.raises(RuntimeError):
            archive.read("Security.evtx", pwd=b"wrong")
        assert archive.read("Security.evtx", pwd=b"infected") == data
    assert client.get(url, headers=make_key(admin, roles=["admin"])).status_code == 200
    with SessionLocal() as db:
        entries = list(db.scalars(select(AuditEntry).where(AuditEntry.action == "evidence.download")))
        sha256 = db.get(EvidenceSource, source_id).sha256
    assert len(entries) == 2 and entries[0].incident_id == "ev-api"
    assert entries[0].details == f"Downloaded the original of Security.evtx ({sha256})"
    change(source_id, legacy=True)
    assert client.get(url, headers=allowed).status_code == 404


def test_nothing_is_left_of_the_zip_in_the_store(env, admin):
    from app import artifact_transfer

    source_id, _ = a_record(env, b"x" * 1000)
    env["client"].get(f"{BASE_URL}/sources/{source_id}/download", headers=make_key(admin, roles=["evidence"]))
    assert not [p for p in artifact_transfer.workdir().glob("nik-evidence-*")]


# --------------------------------------------------------------------------- #
# Of another incident                                                         #
# --------------------------------------------------------------------------- #
def test_the_ids_of_another_incident_and_unknown_incidents_are_404_on_every_route(env, admin):
    source_id, record_id = a_record(env)
    allowed = make_key(admin, roles=["evidence"])
    env["monkeypatch"].setattr(views, "ask_view", lambda *_: (200, {"kind": "text"}))
    client = env["client"]
    for incident in ("ev-other", "nope"):
        base = f"/api/incidents/{incident}/evidence"
        assert client.get(f"{base}/records/{record_id}/view", headers=env["r"]).status_code == 404
        assert client.get(f"{base}/sources/{source_id}/page", headers=env["r"]).status_code == 404
        assert client.get(f"{base}/sources/{source_id}/download", headers=allowed).status_code == 404
    for path in ("histogram", "fields"):
        assert client.get(f"/api/incidents/nope/evidence/{path}", headers=env["r"]).status_code == 404
    assert (
        client.get("/api/incidents/nope/evidence/stack", headers=env["r"], params={"field": "host"}).status_code == 404
    )
    assert get(env, "ev-api/evidence/records/999999/view").status_code == 404
    assert get(env, "ev-api/evidence/sources/unknown/page").status_code == 404
    assert client.get(f"{BASE_URL}/sources/unknown/download", headers=allowed).status_code == 404
