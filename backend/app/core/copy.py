"""A copy of a server (``NIK_COPY=true``, 7.0): it reaches nothing outside itself.

A release is tried on a copy of the real server, restored from one of its
backups (``deploy/restore.sh --as-copy``; docs/admin/try-on-a-copy.md). Such a
copy holds the real server's connections, schedules, webhooks, mail settings
and backup destinations. Started as it is, it would fetch from the real
systems, write back to them, send mail and webhooks, delete the real off-site
backups by its own retention and ship to the real standby.

So on a copy every door to the outside is shut here, at the point where each
would open, and says so with one sentence (``CopyRefused``): connectors and
mailboxes (fetch, mirror, actions), mail, webhooks, the off-site backup and its
retention, the copies to the standby, the audit log forwarded to syslog,
threat-intelligence look-ups, address scans, and the playbooks that start by
themselves (schedules, events, hooks). A playbook is run by hand only as a dry
run. What stays is what the copy is for: everything a person does inside it,
the analysis workers, the local backups.

The screens show a banner, "COPY of <server>", from ``describe``.
"""

from __future__ import annotations

from .config import settings


class CopyRefused(Exception):
    """What a copy of a server does not do: the sentence says what was not done."""


def is_copy() -> bool:
    return bool(settings.NIK_COPY)


def refuse(what: str) -> None:
    """Raise ``CopyRefused`` on a copy: ``what`` is what would have reached outside ("send a webhook")."""
    if settings.NIK_COPY:
        raise CopyRefused(f"This server is a copy of {settings.NIK_COPY_OF or 'another server'}: it does not {what}")


def describe() -> dict[str, object]:
    """What the screens need for the banner."""
    return {"copy": bool(settings.NIK_COPY), "copyOf": settings.NIK_COPY_OF if settings.NIK_COPY else ""}
