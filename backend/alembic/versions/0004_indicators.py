"""indicators: hashes, URLs and hosts published as malicious

Revision ID: 9c2e7b41fd08
Revises: 3f61c0a8d74e
Create Date: 2026-10-17

Shaped for lookup rather than for listing: ``value_norm`` and ``host`` carry
the indexes, because the question the page answers is "is this one known",
not "show me everything".

Indexes go inside ``batch_alter_table`` so the revision applies to SQLite as
well as to PostgreSQL. A revision that only runs on one of them is a revision
nobody verifies.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "9c2e7b41fd08"
down_revision = "3f61c0a8d74e"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "indicators",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("source_key", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("value_norm", sa.String(600), nullable=False),
        sa.Column("host", sa.String(300), nullable=True),
        sa.Column("family", sa.String(200), nullable=True),
        sa.Column("attack_stix_id", sa.String(100), nullable=True),
        sa.Column("threat", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32), nullable=True),
        sa.Column("file_type", sa.String(64), nullable=True),
        sa.Column("mime_type", sa.String(120), nullable=True),
        sa.Column("related", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("reporter", sa.String(120), nullable=True),
        sa.Column("reference_url", sa.Text(), nullable=True),
        sa.Column("tier", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("first_seen_at", TZ, nullable=True),
        sa.Column("last_seen_at", TZ, nullable=True),
        sa.Column("collected_at", TZ, nullable=False),
        sa.UniqueConstraint("source_key", "kind", "value_norm", name="uq_indicator"),
    )
    with op.batch_alter_table("indicators") as batch:
        batch.create_index("ix_indicators_source_key", ["source_key"])
        batch.create_index("ix_indicators_kind", ["kind"])
        batch.create_index("ix_indicators_value_norm", ["value_norm"])
        batch.create_index("ix_indicators_host", ["host"])
        batch.create_index("ix_indicators_family", ["family"])
        batch.create_index("ix_indicators_attack_stix_id", ["attack_stix_id"])
        batch.create_index("ix_indicators_status", ["status"])
        batch.create_index("ix_indicators_first_seen_at", ["first_seen_at"])
        batch.create_index("ix_indicators_collected_at", ["collected_at"])


def downgrade() -> None:
    with op.batch_alter_table("indicators") as batch:
        for name in ("ix_indicators_collected_at", "ix_indicators_first_seen_at",
                     "ix_indicators_status", "ix_indicators_attack_stix_id",
                     "ix_indicators_family", "ix_indicators_host",
                     "ix_indicators_value_norm", "ix_indicators_kind",
                     "ix_indicators_source_key"):
            batch.drop_index(name)
    op.drop_table("indicators")
