"""artifacts: files, e-mails and captures analysed on their own

A registry over ``samples``, ``mails`` and ``network_captures`` (``artifacts``),
the incidents that reference each one (``artifact_links``) and where each one
comes from (``artifact_relations``). A capture no longer needs an incident
(``network_captures.incident_id`` becomes nullable). The rows for what is
already stored are written by the application on its next start
(``artifacts.backfill``).

Revision ID: 0017_artifacts
Revises: 0016_network_captures
Create Date: 2026-11-11
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0017_artifacts"
down_revision = "0016_network_captures"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = sa.inspect(op.get_bind()).get_table_names()
    if "artifacts" not in tables:
        op.create_table(
            "artifacts",
            sa.Column("id", sa.String(length=80), primary_key=True),
            sa.Column("kind", sa.String(), nullable=False),
            sa.Column("ref", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(), nullable=False, server_default=""),
            sa.Column("verdict", sa.String(), nullable=False, server_default=""),
            sa.Column("score", sa.Integer(), nullable=True),
            sa.Column("detail", sa.String(), nullable=False, server_default=""),
            sa.Column("size", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("tags", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        )
        op.create_index("ix_artifacts_kind", "artifacts", ["kind"])
        op.create_index("ix_artifacts_created_at", "artifacts", ["created_at"])
    if "artifact_links" not in tables:
        op.create_table(
            "artifact_links",
            sa.Column(
                "artifact_id",
                sa.String(length=80),
                sa.ForeignKey("artifacts.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("incident_id", sa.String(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
        )
        op.create_index("ix_artifact_links_incident_id", "artifact_links", ["incident_id"])
    if "artifact_relations" not in tables:
        op.create_table(
            "artifact_relations",
            sa.Column(
                "parent_id", sa.String(length=80), sa.ForeignKey("artifacts.id", ondelete="CASCADE"), primary_key=True
            ),
            sa.Column(
                "child_id", sa.String(length=80), sa.ForeignKey("artifacts.id", ondelete="CASCADE"), primary_key=True
            ),
            sa.Column("relation", sa.String(), nullable=False, server_default=""),
            sa.Column("created_at", sa.String(), nullable=False),
        )
        op.create_index("ix_artifact_relations_child_id", "artifact_relations", ["child_id"])
    with op.batch_alter_table("network_captures") as batch:
        batch.alter_column("incident_id", existing_type=sa.String(), nullable=True)


def downgrade() -> None:
    # Captures analysed on their own have no incident to go back to.
    op.execute("DELETE FROM network_captures WHERE incident_id IS NULL")
    with op.batch_alter_table("network_captures") as batch:
        batch.alter_column("incident_id", existing_type=sa.String(), nullable=False)
    op.drop_index("ix_artifact_relations_child_id", table_name="artifact_relations")
    op.drop_table("artifact_relations")
    op.drop_index("ix_artifact_links_incident_id", table_name="artifact_links")
    op.drop_table("artifact_links")
    op.drop_index("ix_artifacts_created_at", table_name="artifacts")
    op.drop_index("ix_artifacts_kind", table_name="artifacts")
    op.drop_table("artifacts")
