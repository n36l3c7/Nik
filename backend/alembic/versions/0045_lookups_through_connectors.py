"""the answers of the look-ups are filed under the connectors that give them now

Release 6.5. A look-up of an indicator is the reputation command of a
source's connector, and an answer is stored under the id of that connector.
The answers stored before are kept, under the id their source has now:

    internetdb    -> shodan
    registration  -> rdap
    abusech       -> malwarebazaar, urlhaus or threatfox: the service that had
                     flagged the value (its line starts with the name of the
                     service). An abuse.ch answer that flagged nothing says
                     nothing of any one of the three and is dropped; the
                     services are asked again, each for itself.

The other sources keep their id (virustotal, abuseipdb, otx, urlscan,
greynoise, safebrowsing). Nothing else changes: the verdict, the line, the
link and the date of each answer stand, and the API keys stay where they are
(``integration_keys``) until an instance of a connector takes them, which is
done by the application when the connector is installed
(``app/enrichment/old_keys.py``), never here.

Run again, it finds nothing to do. Going back renames shodan and rdap; the
answers of the three abuse.ch services stay under their own ids.

Revision ID: 0045_lookups_through_connectors
Revises: 0044_no_legacy_roles
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0045_lookups_through_connectors"
down_revision = "0044_no_legacy_roles"
branch_labels = None
depends_on = None

RENAMED = {"internetdb": "shodan", "registration": "rdap"}
# What the line of an abuse.ch answer starts with, and the service that gave it.
ABUSE_CH = {"MalwareBazaar:": "malwarebazaar", "URLhaus:": "urlhaus", "ThreatFox:": "threatfox"}


def _rename(bind, table: str, old: str, new: str, where: str = "", unique: bool = False) -> None:
    """File the rows of ``old`` under ``new``; where an answer is already there under ``new`` (the table of
    the latest answers holds one per source), the old one is left for the caller to drop."""
    free = (
        f" AND NOT EXISTS (SELECT 1 FROM {table} AS other WHERE other.type = {table}.type "
        f"AND other.value = {table}.value AND other.provider = :new)"
        if unique
        else ""
    )
    bind.execute(
        sa.text(f"UPDATE {table} SET provider = :new WHERE provider = :old{where}{free}"),  # noqa: S608 - fixed names
        {"old": old, "new": new},
    )


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for table, unique in (("ioc_enrichment", True), ("ioc_enrichment_history", False)):
        if table not in tables:
            continue
        for old, new in RENAMED.items():
            _rename(bind, table, old, new, unique=unique)
        for prefix, new in ABUSE_CH.items():
            _rename(bind, table, "abusech", new, f" AND summary LIKE '{prefix}%'", unique=unique)
        # What is left under an old id has no source any more: an abuse.ch answer that named no service,
        # or an answer whose place was taken.
        bind.execute(
            sa.text(f"DELETE FROM {table} WHERE provider IN ('abusech', 'internetdb', 'registration')")  # noqa: S608
        )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for table, unique in (("ioc_enrichment", True), ("ioc_enrichment_history", False)):
        if table not in tables:
            continue
        for old, new in RENAMED.items():
            _rename(bind, table, new, old, unique=unique)
