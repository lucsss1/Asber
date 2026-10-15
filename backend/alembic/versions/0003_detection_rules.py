"""detection_rules: Sigma (and later YARA) rules, stored inert

Revision ID: 3f61c0a8d74e
Revises: 7a4e2d905b31
Create Date: 2026-10-15

The rule body is stored as text and never executed. Correlation to ATT&CK and
CVE is not stored here: it goes to ``entity_links`` like every other edge, so
it carries its method and evidence and is queryable through the same graph.

Indexes are created inside ``batch_alter_table`` so the revision applies to
SQLite as well as to PostgreSQL — the test database is SQLite, and a revision
that only runs on one of them is a revision nobody verifies.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "3f61c0a8d74e"
down_revision = "7a4e2d905b31"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("source_key", sa.String(64), nullable=False),
        sa.Column("external_id", sa.String(300), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("rule_format", sa.String(16), nullable=False, server_default="sigma"),
        sa.Column("status", sa.String(32), nullable=True),
        sa.Column("level", sa.String(32), nullable=True),
        sa.Column("logsource", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("detection", sa.Text(), nullable=True),
        sa.Column("falsepositives", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("references", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("techniques", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("cve_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("author", sa.String(300), nullable=True),
        sa.Column("release", sa.String(64), nullable=True),
        sa.Column("tier", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("published_at", TZ, nullable=True),
        sa.Column("collected_at", TZ, nullable=False),
        sa.UniqueConstraint("source_key", "external_id", name="uq_detection_rule"),
    )
    with op.batch_alter_table("detection_rules") as batch:
        batch.create_index("ix_detection_rules_source_key", ["source_key"])
        batch.create_index("ix_detection_rules_rule_format", ["rule_format"])
        batch.create_index("ix_detection_rules_status", ["status"])
        batch.create_index("ix_detection_rules_level", ["level"])
        batch.create_index("ix_detection_rules_published_at", ["published_at"])
        batch.create_index("ix_detection_rules_collected_at", ["collected_at"])


def downgrade() -> None:
    with op.batch_alter_table("detection_rules") as batch:
        for name in ("ix_detection_rules_collected_at", "ix_detection_rules_published_at",
                     "ix_detection_rules_level", "ix_detection_rules_status",
                     "ix_detection_rules_rule_format", "ix_detection_rules_source_key"):
            batch.drop_index(name)
    op.drop_table("detection_rules")
