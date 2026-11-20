"""The audit log from the command line of the server.

    python -m app.auditlog verify-audit [--full] [--head SEQ:HASH]
    python -m app.auditlog export [FILE]
    python -m app.auditlog key [--derived]

``verify-audit`` walks the chain of this server's database as the screen's
*Verify now* does (``--full`` reads every entry; ``--head`` holds the end of
the log against a head noted elsewhere, such as the last checkpoint a syslog
receiver got) and exits 1 when something does not hold. ``export`` prints
every entry as one JSON object a line, in the order of the chain: the file
``verifier.py`` checks on another machine. ``key`` says which key signs the
entries now (its id, never the key) and which earlier keys this server can
still make; ``key --derived`` prints the key derived from ``SECRET_KEY``, as
it is written in ``AUDIT_KEY_PREVIOUS``: to keep before ``SECRET_KEY`` is
changed for good, so that the entries it signed can still be checked.
"""

from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import select

from . import chain, verifier
from . import key as signing
from .verifier import _head


def _export(target) -> int:
    from ..core.db import SessionLocal
    from ..core.models import AuditEntry

    table = AuditEntry.__table__
    written, last = 0, 0
    with SessionLocal() as db:
        while True:
            rows = (
                db.execute(select(table).where(table.c.seq > last).order_by(table.c.seq).limit(chain.BATCH))
                .mappings()
                .all()
            )
            if not rows:
                break
            for row in rows:
                entry = {name: row[name] for name in verifier.FIELDS}
                if row["origin"] is not None:
                    entry["origin"] = row["origin"]
                entry.update(seq=row["seq"], prev=row["prev_hash"], hash=row["hash"])
                entry.update(mac=row["mac"], key_id=row["key_id"])
                target.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
            written += len(rows)
            last = int(rows[-1]["seq"])
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.auditlog", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("verify-audit", help="walk the chain of the audit log")
    check.add_argument("--full", action="store_true", help="read every entry, not only what is new")
    check.add_argument("--head", type=_head, help="a head noted elsewhere, as SEQ:HASH")
    export = commands.add_parser("export", help="every entry as one JSON object a line")
    export.add_argument("file", nargs="?", help="where to write (the output, when left out)")
    keys = commands.add_parser("key", help="which key signs the entries")
    keys.add_argument("--derived", action="store_true", help="print the key derived from SECRET_KEY (a secret)")
    args = parser.parse_args(argv)
    if args.command == "key":
        if args.derived:
            from ..core.config import settings

            print("hex:" + signing.derived(settings.SECRET_KEY).hex())
            return 0
        current, _secret = signing.current()
        print(f"Entries are signed with the key {current}.")
        others = sorted(set(signing.known()) - {current.rsplit("-", 1)[-1]})
        print(
            "Entries signed with these earlier keys can still be checked: " + ", ".join(others)
            if others
            else "No earlier key is known to this server."
        )
        return 0
    if args.command == "export":
        if args.file:
            with open(args.file, "w", encoding="utf-8", newline="\n") as target:
                count = _export(target)
            sys.stderr.write(f"{count} entries written to {args.file}\n")
        else:
            _export(sys.stdout)
        return 0
    from ..core.db import SessionLocal

    linked = chain.link_strays()
    with SessionLocal() as db:
        state = chain.verify(db, full=args.full, outside=args.head)
        db.commit()
        found = chain.out(db)
    if linked:
        print(f"{linked} entries that had no number were linked first.")
    problem = state.get("problem")
    verified = state.get("verified") or {}
    if problem:
        print(f"PROBLEM ({problem['kind']}, entry {problem['seq']}): {problem['text']}")
        if verified.get("seq"):
            print(f"The chain held up to entry {verified['seq']} at the last good pass.")
        return 1
    print(
        f"The chain holds: {found['entries']} entries, head {verified.get('seq')}:{verified.get('hash')}"
        + (" (every entry was read)." if args.full else ".")
    )
    unchecked = state.get("unchecked") or {}
    for name, count in sorted(unchecked.items()):
        print(f"{count} entries cannot be checked: this server can no longer make the key {name or '(none named)'}.")
    if not args.head:
        print(
            "Held against the head row, the file of heads in the backup directory and the forwarding cursor. "
            "Give --head with the last checkpoint of the syslog receiver to hold it against a copy off the server."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
