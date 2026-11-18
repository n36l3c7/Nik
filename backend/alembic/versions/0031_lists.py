"""lists: what Nik kept as fixed lists in its settings, by name

Tables ``lists`` and ``list_items``, each created only where it is missing
(the baseline creates the schema from the models). Then the lists Nik ships
are added and what the settings held is moved into them (``lists.seed``): the
indicator allowlist, your organisation's domains, the mail servers whose
authentication is trusted, the suspicious keywords, the business hours, the
hosts every playbook may reach. A setting that was moved holds
``{"list": "<name>"}`` from then on. Moving is done once: a list that exists
is left as it is, so running this again changes nothing.

Revision ID: 0031_lists
Revises: 0030_tasks_sla
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.orm import Session

from alembic import op

revision = "0031_lists"
down_revision = "0030_tasks_sla"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import LIST_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in LIST_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)
    if "settings" in existing:
        from app import lists

        with Session(bind=bind) as db:
            lists.seed(db)
            db.flush()


def downgrade() -> None:
    from app.core.models import LIST_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    if "lists" in existing and "settings" in existing:
        from app import lists

        # The settings get back what the lists hold, in the shape they had.
        with Session(bind=bind) as db:
            lists.unseed(db)
            db.flush()
    for name in reversed(LIST_TABLES):
        if name in existing:
            op.drop_table(name)
