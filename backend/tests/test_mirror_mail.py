"""Mirroring a mailbox in: the replies to a message an incident was made from become its lines.

The Mail connector is native and its mirror is fed by its fetch (``mirror.thread``): nothing is read
at an interval and nothing is ever sent. What decides that a message goes on with an incident is
what it names in ``In-Reply-To`` and ``References``, never its subject.
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest
from sqlalchemy import func, select

from app import fetch, mirror
from app.core.db import SessionLocal
from app.core.models import Connection, FetchedItem, Incident, Mail, MirrorJob
from tests.test_mail_connector import box, instance  # noqa: F401 - box is a fixture

ID = "m" * 32
BASE = "/api/automation"


def mail(uid: int, subject: str, text: str, *, sender: str = "anna@partner.example", **headers) -> bytes:
    made = EmailMessage()
    made["From"] = f"<{sender}>"
    made["To"] = "soc@acme.example"
    made["Subject"] = subject
    made["Date"] = f"Thu, 19 Nov 2026 09:{uid:02d}:00 +0000"
    made["Message-ID"] = headers.pop("message_id", f"<m{uid}@partner.example>")
    for name, value in headers.items():
        made[name.replace("_", "-")] = value
    made.set_content(text)
    return made.as_bytes()


@pytest.fixture()
def inbox(admin, box):  # noqa: F811 - the fixture of the mail tests
    """The mailbox of the tests, emptied, with its instance; ``inbox.put`` delivers a message."""
    box.folders["INBOX"] = {}
    with SessionLocal() as db:
        instance(db)

    def put(uid: int, subject: str, text: str = "Hello", **more) -> None:
        box.folders["INBOX"][uid] = [mail(uid, subject, text, **more), set()]

    box.put = put
    box.admin = admin
    return box


def choose(admin, direction: str):
    return admin.put(f"{BASE}/instances/{ID}", json={"fetch": {"mirror": direction}})


def cycle() -> dict:
    with SessionLocal() as db:
        return fetch.cycle(db, db.get(Connection, ID))


def incidents(admin) -> dict[str, str]:
    return {row["name"]: row["id"] for row in admin.get("/api/incidents?view=summary").json()["incidents"]}


def lines(admin, incident_id: str) -> list[dict]:
    entries = admin.get(f"/api/incidents/{incident_id}/war-room").json()["entries"]
    return [entry["body"] for entry in entries if entry["kind"] == "mirror"]


def outcomes() -> dict[str, tuple[str, str]]:
    with SessionLocal() as db:
        return {row.item_id: (row.outcome, row.note) for row in db.scalars(select(FetchedItem))}


def test_with_no_choice_every_message_is_an_incident_as_before(admin, inbox):
    inbox.put(1, "Invoice overdue")
    inbox.put(2, "Re: Invoice overdue", In_Reply_To="<m1@partner.example>", References="<m1@partner.example>")
    done = cycle()
    assert (done["created"], done["mirrored"]) == (2, 0)
    assert sorted(incidents(admin)) == ["Invoice overdue", "Re: Invoice overdue"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Incident).where(Incident.mirror.isnot(None))) == 0


def test_the_replies_to_a_message_become_lines_of_its_incident(admin, inbox):
    assert choose(admin, "in").status_code == 200
    inbox.put(1, "Invoice overdue", "Please pay.")
    assert cycle()["created"] == 1
    (one,) = incidents(admin).values()
    said = admin.get(f"/api/incidents/{one}/mirror").json()
    assert (said["id"], said["direction"], said["origin"], said["fed"]) == (
        "<m1@partner.example>",
        "in",
        "instance",
        True,
    )
    assert said["can"] == {"fieldsIn": False, "commentsIn": True, "fieldsOut": False, "commentsOut": False}

    # A reply, then a reply to the reply whose References name the whole chain, then one that names
    # only the message before it: each goes on with the same incident.
    first = "<m1@partner.example>"
    inbox.put(
        2, "Re: Invoice overdue", "We paid on Monday.", sender="bruno@acme.example", In_Reply_To=first, References=first
    )
    inbox.put(3, "RE: Invoice overdue", "No, you did not.", In_Reply_To="<m2@partner.example>",
              References=f"{first} <m2@partner.example>")  # fmt: skip
    inbox.put(
        4, "Different subject now", "See the receipt.", sender="bruno@acme.example", In_Reply_To="<m3@partner.example>"
    )
    done = cycle()
    assert (done["fetched"], done["created"], done["mirrored"]) == (3, 0, 3)
    assert list(incidents(admin)) == ["Invoice overdue"]
    assert [
        (line["from"], line["text"].strip(), line["direction"], line["connection"]) for line in lines(admin, one)
    ] == [
        ("bruno@acme.example", "We paid on Monday.", "in", "SOC mailbox"),
        ("anna@partner.example", "No, you did not.", "in", "SOC mailbox"),
        ("bruno@acme.example", "See the receipt.", "in", "SOC mailbox"),
    ]
    assert lines(admin, one)[0]["at"].startswith("2026-11-19T09:02:00")
    # Each is kept as evidence of the incident, as the message it was made from is.
    kept = admin.get(f"/api/incidents/{one}").json()["data"]["mail"]["messages"]
    assert sorted(ref["fileName"] for ref in kept) == [f"message-{uid}.eml" for uid in (1, 2, 3, 4)]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Mail)) == 4
    assert outcomes()["<m2@partner.example>2"] == ("mirrored", "A line of the incident it goes on with")
    assert admin.get(f"/api/fetch/{ID}/items?outcome=mirrored").json()["items"][0]["incidentId"] == one

    # Nothing is read at an interval, and nothing is there to read by hand.
    with SessionLocal() as db:
        assert mirror.due(db, 9e12) == []
    refused = admin.post(f"/api/incidents/{one}/mirror/sync")
    assert (refused.status_code, refused.json()["detail"]) == (
        409,
        "This mirror is fed by what its instance fetches: there is nothing to read now",
    )


def test_a_reply_that_arrives_before_what_it_answers(admin, inbox):
    assert choose(admin, "in").status_code == 200
    # The reply is read first (the original was delayed): it is the incident.
    inbox.put(
        5, "Re: Wire transfer", "Done as asked.", In_Reply_To="<m9@partner.example>", References="<m9@partner.example>"
    )
    assert cycle()["created"] == 1
    inbox.put(9, "Wire transfer", "Please wire 10 000 today.")
    done = cycle()
    assert (done["created"], done["mirrored"]) == (0, 1)
    (one,) = incidents(admin).values()
    assert [line["text"].strip() for line in lines(admin, one)] == ["Please wire 10 000 today."]
    # And a later answer to the original finds the same incident.
    inbox.put(10, "Re: Wire transfer", "Which account?", In_Reply_To="<m9@partner.example>")
    assert cycle()["mirrored"] == 1 and len(incidents(admin)) == 1


def test_a_forward_and_a_like_subject_are_not_replies(admin, inbox):
    assert choose(admin, "in").status_code == 200
    inbox.put(1, "Invoice overdue")
    cycle()
    # Forwarded by someone, with no word of what it goes on from; and a new message that only looks like an answer.
    inbox.put(2, "Fwd: Invoice overdue", "FYI, see below.\n\n> Please pay.", sender="carla@acme.example")
    inbox.put(3, "Re: Invoice overdue", "Unrelated, same words.", sender="mallory@evil.example")
    done = cycle()
    assert (done["created"], done["mirrored"]) == (2, 0)
    found = incidents(admin)
    assert sorted(found) == ["Fwd: Invoice overdue", "Invoice overdue", "Re: Invoice overdue"]
    assert lines(admin, found["Invoice overdue"]) == []
    # Each of them starts a conversation of its own.
    inbox.put(4, "Re: Fwd: Invoice overdue", "Thanks.", In_Reply_To="<m2@partner.example>")
    assert cycle()["mirrored"] == 1
    assert len(lines(admin, found["Fwd: Invoice overdue"])) == 1 and lines(admin, found["Invoice overdue"]) == []


def test_the_same_message_twice_is_said_once(admin, inbox):
    assert choose(admin, "in").status_code == 200
    inbox.put(1, "Invoice overdue")
    cycle()
    first = "<m1@partner.example>"
    inbox.put(2, "Re: Invoice overdue", "We paid.", In_Reply_To=first)
    # The same message delivered a second time (another copy in the folder), and the first one again.
    inbox.put(3, "Re: Invoice overdue", "We paid.", In_Reply_To=first, message_id="<m2@partner.example>")
    inbox.put(4, "Invoice overdue", message_id=first)
    done = cycle()
    assert (done["created"], done["mirrored"]) == (0, 3)
    (one,) = incidents(admin).values()
    assert [line["text"].strip() for line in lines(admin, one)] == ["We paid."]
    said = outcomes()
    assert said["<m2@partner.example>3"] == ("mirrored", "It was there already")
    assert said[f"{first}4"] == ("mirrored", "It was there already")
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Mail)) == 2  # the first and its one reply


def test_a_mailbox_is_never_written_to_by_mirroring(admin, inbox):
    said = next(item for item in admin.get(f"{BASE}/instances").json()["instances"] if item["id"] == ID)
    assert said["fetch"]["mirror"]["offered"] == ["none", "in"] and said["fetch"]["mirror"]["fed"] is True
    for direction in ("out", "both"):
        refused = choose(admin, direction)
        assert (refused.status_code, refused.json()["detail"]) == (
            400,
            "Mail listener / sender is read and never written to: mirroring with it is None or In",
        )
    assert choose(admin, "in").status_code == 200
    inbox.put(1, "Invoice overdue")
    cycle()
    (one,) = incidents(admin).values()
    assert admin.patch(f"/api/incidents/{one}/mirror", json={"direction": "both"}).status_code == 400
    noted = admin.post(f"/api/incidents/{one}/war-room", json={"text": "Thank you, received.", "tags": ["mirror"]})
    assert noted.status_code == 201
    assert admin.patch(f"/api/incidents/{one}", json={"status": "in_progress"}).status_code == 200
    with SessionLocal() as db:
        assert db.scalars(select(MirrorJob)).all() == []
    told = [
        entry["body"].get("text", "")
        for entry in admin.get(f"/api/incidents/{one}/war-room").json()["entries"]
        if entry["kind"] == "system"
    ]
    assert (
        "The note tagged mirror was not sent: SOC mailbox is read and never written to. "
        "Use the reply command of the instance to answer."
    ) in told
    assert inbox.calls and not [call for call in inbox.calls if call[0] in ("append", "store")]
    # Stopped on the incident: its replies are incidents again.
    assert admin.delete(f"/api/incidents/{one}/mirror").status_code == 204
    inbox.put(2, "Re: Invoice overdue", In_Reply_To="<m1@partner.example>")
    assert cycle()["created"] == 1
