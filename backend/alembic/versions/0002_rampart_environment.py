"""rampart: the owner's environment

Revision ID: 7a4e2d905b31
Revises: 1c11b00139ef
Create Date: 2026-09-28 23:58:00.000000

Three tables for the owner's technology inventory and its CVE matches.

Written by hand rather than taken from autogenerate, per the convention the
baseline sets. Every table carries ``owner_id`` from this first revision: the
inventory is a map of somebody's attack surface, and adding ownership later
would mean backfilling rows that were never scoped.

Indexes are created inside ``batch_alter_table`` so the same revision applies to
the SQLite databases the test suite uses.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = '7a4e2d905b31'
down_revision = '1c11b00139ef'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'environments',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('owner_id', sa.String(length=320), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('owner_id', 'name', name='uq_environment_owner_name'),
    )
    with op.batch_alter_table('environments', schema=None) as batch_op:
        batch_op.create_index('ix_environment_owner', ['owner_id'], unique=False)

    op.create_table(
        'environment_assets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('owner_id', sa.String(length=320), nullable=False),
        sa.Column('environment_id', sa.Integer(), nullable=False),
        sa.Column('label', sa.String(length=120), nullable=False),
        sa.Column('category', sa.String(length=32), nullable=False),
        sa.Column('vendor', sa.String(length=200), nullable=False),
        sa.Column('product', sa.String(length=300), nullable=False),
        sa.Column('version', sa.String(length=64), nullable=True),
        sa.Column('cpe', sa.String(length=400), nullable=True),
        sa.Column('catalogued', sa.Boolean(), nullable=False),
        sa.Column('hardware_model', sa.String(length=120), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['environment_id'], ['environments.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('environment_assets', schema=None) as batch_op:
        batch_op.create_index('ix_asset_owner_environment', ['owner_id', 'environment_id'], unique=False)
        batch_op.create_index('ix_asset_vendor_product', ['vendor', 'product'], unique=False)
        batch_op.create_index(batch_op.f('ix_environment_assets_environment_id'), ['environment_id'], unique=False)

    op.create_table(
        'environment_matches',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('owner_id', sa.String(length=320), nullable=False),
        sa.Column('environment_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(length=32), nullable=False),
        sa.Column('state', sa.String(length=24), nullable=False),
        sa.Column('method', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.String(length=16), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('exposure', sa.Integer(), nullable=False),
        sa.Column('matched_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['environment_assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['environment_id'], ['environments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['cve_id'], ['vulnerabilities.cve_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('asset_id', 'cve_id', name='uq_environment_match'),
    )
    with op.batch_alter_table('environment_matches', schema=None) as batch_op:
        batch_op.create_index('ix_match_owner_environment_state', ['owner_id', 'environment_id', 'state'],
                              unique=False)
        batch_op.create_index('ix_match_cve', ['cve_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_environment_matches_asset_id'), ['asset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_environment_matches_environment_id'), ['environment_id'], unique=False)


def downgrade() -> None:
    # Dropped children first: the matches reference both of the others.
    op.drop_table('environment_matches')
    op.drop_table('environment_assets')
    op.drop_table('environments')
