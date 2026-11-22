"""Where mirroring and the indicators found by themselves meet.

An incident a fetch makes is read for indicators once, when it is whole; the mirror its instance
starts reads the same object again and that finds nothing new to read. An update that changes
several things (fields, context, comments) is read once and leaves one line. What the other side
says (a comment, a reply to a mail) is read too. Nothing that was found is ever sent out, and an
object that is gone is not read.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.db import SessionLocal
from app.core.models import FetchedItem, FoundScan, Incident
from tests.test_indicators_found import found_lines, iocs, listing, setting
from tests.test_mail_connector import box  # noqa: F401 - box is a fixture
from tests.test_mirror_instance import INCOMING, choose, fetch_now, fetched, helpdesk, jobs, push_all, shown, sync
from tests.test_mirror_mail import ID as MAILBOX
from tests.test_mirror_mail import choose as choose_mail
from tests.test_mirror_mail import cycle, inbox, incidents, lines  # noqa: F401 - inbox is a fixture

FIRST = "<m1@partner.example>"


def read_at(incident_id: str) -> tuple[str, str]:
    """When an incident was last read for indicators, and through which door."""
    with SessionLocal() as db:
        state = db.get(FoundScan, incident_id)
        return state.at, state.door


def with_a_note(admin: TestClient, outside) -> tuple[dict, object]:
    """Helpdesk, its instance told In-out, its mapper keeping the note of a ticket in the context."""
    connection, world = helpdesk(admin, outside)
    rules = [*INCOMING, {"to": "ext.helpdesk.note", "from": "{{ item.note }}"}]
    body = {"connectorId": "helpdesk", "direction": "incoming", "rules": rules}
    assert admin.put("/api/mappers", json=body).status_code == 200
    world.tickets["T-101"].update(title="Laptop of finance talks to evil-site.com", note="Seen with bad-domain.net")
    assert choose(admin, connection, mirror="both").status_code == 200
    return connection, world


def test_an_incident_its_instance_mirrors_is_read_once_and_an_update_leaves_one_line(admin: TestClient, outside):
    connection, world = with_a_note(admin, outside)
    assert fetch_now(admin, connection)["created"] == 2
    one = fetched("101")
    assert shown(admin, one)["origin"] == "instance"
    assert [(row["value"], row["path"], row["door"]) for row in listing(admin, one)["found"]] == [
        ("bad-domain.net", "context.ext.helpdesk.note", "fetch"),
        ("evil-site.com", "incident.name", "fetch"),
    ]
    assert found_lines(admin, one) == ["2 indicators found: 2 domains."]
    first_reading = read_at(one)

    # The first read of the mirror brings the object the fetch brought: nothing changed, so the
    # incident is not read again, and nothing is said twice.
    done = sync(admin, one)
    assert done["changed"] == [] and done["problems"] == []
    assert read_at(one) == first_reading and len(found_lines(admin, one)) == 1

    # The other side changes two fields, the context, and says something: one reading, one line.
    world.tickets["T-101"].update(
        title="Laptop of finance talks to evil-site.com and other-site.org",
        state="work",
        note="Seen with bad-domain.net, then 185.220.101.47",
    )
    said = "The loader came from hxxp://c2-host[.]net/gate.php"
    world.comments["T-101"] = [{"id": "c1", "body": said, "by": "desk", "at": "2026-11-21T09:00:00Z"}]
    done = sync(admin, one)
    assert sorted(done["changed"]) == ["name", "status"] and done["comments"] == 1
    assert found_lines(admin, one) == [
        "2 indicators found: 2 domains.",
        "4 indicators found: 2 domains, 1 URL, 1 address.",
    ]
    new = {row["value"]: (row["path"], row["door"]) for row in listing(admin, one)["found"] if row["door"] == "mirror"}
    assert new == {
        "other-site.org": ("incident.name", "mirror"),
        "185.220.101.47": ("context.ext.helpdesk.note", "mirror"),
        "c2-host.net": ("warroom.mirror", "mirror"),
        "http://c2-host.net/gate.php": ("warroom.mirror", "mirror"),
    }
    assert iocs(admin, one)[("domain", "c2-host.net")] == ["found:warroom.mirror"]
    # What was found is no change of a field: nothing is queued for the other side, nothing is sent.
    assert jobs() == []
    push_all()
    assert world.sent == []

    # A person's no holds for what the other side says again.
    gone = admin.post(f"/api/incidents/{one}/iocs/found/remove", json={"type": "domain", "value": "c2-host.net"})
    assert gone.status_code == 200
    world.comments["T-101"].append(
        {"id": "c2", "body": "Still talking to c2-host[.]net", "by": "desk", "at": "2026-11-21T09:05:00Z"}
    )
    assert sync(admin, one)["comments"] == 1
    assert ("domain", "c2-host.net") not in iocs(admin, one) and len(found_lines(admin, one)) == 2
    assert listing(admin, one)["scan"]["removed"] == 1

    # A change made here goes out once, and reading it back is no update to read for indicators.
    assert admin.patch(f"/api/incidents/{one}", json={"status": "open"}).status_code == 200
    push_all()
    assert len(world.updates()) == 1
    last_reading = read_at(one)
    assert sync(admin, one)["changed"] == [] and read_at(one) == last_reading

    # The object is gone: there is nothing to read, and the incident is not read for indicators.
    world.tickets.pop("T-101")
    assert sync(admin, one)["gone"] is True
    assert read_at(one) == last_reading and len(found_lines(admin, one)) == 2
    assert jobs() == [("update", "done")]


def test_what_a_reply_to_a_mail_says_is_read_for_the_incident_it_joins(admin: TestClient, inbox):  # noqa: F811
    assert choose_mail(admin, "in").status_code == 200
    inbox.put(1, "Invoice overdue", "Please pay.")
    assert cycle()["created"] == 1
    (one,) = incidents(admin).values()
    before = len(found_lines(admin, one))
    assert read_at(one)[1] == "fetch"

    # The reply makes no incident: it is a line of the first, kept as its evidence, and what it
    # says is read for that incident once, with one line.
    inbox.put(
        2,
        "Re: Invoice overdue",
        "We paid at hxxps://pay-portal[.]top/receipt, from 185.220.101.47.",
        sender="bruno@acme.example",
        In_Reply_To=FIRST,
        References=FIRST,
    )
    done = cycle()
    assert (done["created"], done["mirrored"]) == (0, 1)
    assert list(incidents(admin)) == ["Invoice overdue"] and len(lines(admin, one)) == 1
    held = iocs(admin, one)
    assert held[("domain", "pay-portal.top")] == ["found:warroom.mirror"]
    assert ("url", "https://pay-portal.top/receipt") in held and ("ip", "185.220.101.47") in held
    rows = {row["value"]: row["door"] for row in listing(admin, one)["found"]}
    assert rows["pay-portal.top"] == "mirror" and read_at(one)[1] == "mirror"
    assert len(found_lines(admin, one)) == before + 1
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Incident)) == 1
        assert db.get(FetchedItem, (MAILBOX, "<m2@partner.example>2")).outcome == "mirrored"

    # Removed by a person, it does not come back with the next reply that names it.
    gone = admin.post(f"/api/incidents/{one}/iocs/found/remove", json={"type": "domain", "value": "pay-portal.top"})
    assert gone.status_code == 200
    inbox.put(3, "Re: Invoice overdue", "The receipt is at pay-portal[.]top.", In_Reply_To="<m2@partner.example>")
    assert cycle()["mirrored"] == 1
    assert ("domain", "pay-portal.top") not in iocs(admin, one) and len(found_lines(admin, one)) == before + 1

    # The limit of an incident holds for what replies say, and is said.
    setting(admin, cap=len(listing(admin, one)["found"]))
    inbox.put(4, "Re: Invoice overdue", "Or try late-site.org.", In_Reply_To="<m3@partner.example>")
    assert cycle()["mirrored"] == 1
    assert ("domain", "late-site.org") not in iocs(admin, one)
    assert listing(admin, one)["scan"]["over"] == 1 and "1 more were not kept" in found_lines(admin, one)[-1]


def test_a_reply_to_an_incident_that_was_never_read_is_not_read(admin: TestClient, inbox):  # noqa: F811
    assert choose_mail(admin, "in").status_code == 200
    inbox.put(1, "Invoice overdue", "Please pay.")
    cycle()
    (one,) = incidents(admin).values()
    # As an incident from before incidents were read: no mark of a reading.
    with SessionLocal() as db:
        db.delete(db.get(FoundScan, one))
        db.commit()
    lines_before = len(found_lines(admin, one))
    inbox.put(2, "Re: Invoice overdue", "See pay-portal[.]top.", In_Reply_To=FIRST)
    assert cycle()["mirrored"] == 1
    assert listing(admin, one)["scan"] is None and ("domain", "pay-portal.top") not in iocs(admin, one)
    assert len(found_lines(admin, one)) == lines_before
