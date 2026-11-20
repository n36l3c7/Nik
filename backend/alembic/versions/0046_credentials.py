"""stored credentials

Release 6.6. A secret is kept once under a name (``credentials``) and an
instance of a connector names it where it would hold a value. The table is
created only where missing; nothing that is stored changes: an instance keeps
the secrets that were typed into it until someone turns one into a credential.

Going back drops the table. An instance that named a credential then fails
its commands with a sentence that says which one is missing, until the value
is typed into the instance again.

Revision ID: 0046_credentials
Revises: 0045_lookups_through_connectors
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0046_credentials"
down_revision = "0045_lookups_through_connectors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import CREDENTIAL_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in CREDENTIAL_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import CREDENTIAL_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in reversed(CREDENTIAL_TABLES):
        if name in tables:
            op.drop_table(name)
