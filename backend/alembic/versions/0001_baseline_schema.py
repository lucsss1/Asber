"""baseline schema

Revision ID: 1c11b00139ef
Revises: 
Create Date: 2026-09-22 19:24:17.159335
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '1c11b00139ef'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Baseline: the schema as of the first release. Generated from app.models
    # and reviewed by hand; later revisions are written explicitly.
    op.create_table('attack_objects',
    sa.Column('stix_id', sa.String(length=128), nullable=False),
    sa.Column('obj_type', sa.String(length=32), nullable=False),
    sa.Column('external_id', sa.String(length=32), nullable=True),
    sa.Column('name', sa.String(length=300), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('aliases', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('platforms', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('tactics', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('shortname', sa.String(length=64), nullable=True),
    sa.Column('is_subtechnique', sa.Boolean(), nullable=False),
    sa.Column('parent_external_id', sa.String(length=32), nullable=True),
    sa.Column('url', sa.Text(), nullable=True),
    sa.Column('deprecated', sa.Boolean(), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.Column('created', sa.DateTime(timezone=True), nullable=True),
    sa.Column('modified', sa.DateTime(timezone=True), nullable=True),
    sa.Column('extra', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.PrimaryKeyConstraint('stix_id')
    )
    with op.batch_alter_table('attack_objects', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_attack_objects_external_id'), ['external_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_attack_objects_name'), ['name'], unique=False)
        batch_op.create_index(batch_op.f('ix_attack_objects_obj_type'), ['obj_type'], unique=False)

    op.create_table('attack_relationships',
    sa.Column('stix_id', sa.String(length=128), nullable=False),
    sa.Column('relationship_type', sa.String(length=32), nullable=False),
    sa.Column('source_ref', sa.String(length=128), nullable=False),
    sa.Column('target_ref', sa.String(length=128), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('stix_id')
    )
    with op.batch_alter_table('attack_relationships', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_attack_relationships_relationship_type'), ['relationship_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_attack_relationships_source_ref'), ['source_ref'], unique=False)
        batch_op.create_index(batch_op.f('ix_attack_relationships_target_ref'), ['target_ref'], unique=False)

    op.create_table('documents',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('source_key', sa.String(length=64), nullable=False),
    sa.Column('url', sa.Text(), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('doc_type', sa.String(length=32), nullable=False),
    sa.Column('tier', sa.Integer(), nullable=False),
    sa.Column('authors', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('categories', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('reports_exploitation', sa.Boolean(), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('extraction_version', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('url')
    )
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_documents_collected_at'), ['collected_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_documents_doc_type'), ['doc_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_documents_published_at'), ['published_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_documents_source_key'), ['source_key'], unique=False)

    op.create_table('entity_links',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('subject_type', sa.String(length=32), nullable=False),
    sa.Column('subject_id', sa.String(length=128), nullable=False),
    sa.Column('object_type', sa.String(length=32), nullable=False),
    sa.Column('object_id', sa.String(length=128), nullable=False),
    sa.Column('relation', sa.String(length=32), nullable=False),
    sa.Column('method', sa.String(length=32), nullable=False),
    sa.Column('confidence', sa.String(length=16), nullable=False),
    sa.Column('source_key', sa.String(length=64), nullable=False),
    sa.Column('evidence', sa.Text(), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('subject_type', 'subject_id', 'object_type', 'object_id', 'relation', name='uq_link')
    )
    with op.batch_alter_table('entity_links', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_entity_links_observed_at'), ['observed_at'], unique=False)
        batch_op.create_index('ix_link_object', ['object_type', 'object_id'], unique=False)
        batch_op.create_index('ix_link_subject', ['subject_type', 'subject_id'], unique=False)

    op.create_table('exploits',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('source_key', sa.String(length=64), nullable=False),
    sa.Column('external_id', sa.String(length=300), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('url', sa.Text(), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('platform', sa.String(length=64), nullable=True),
    sa.Column('exploit_type', sa.String(length=64), nullable=True),
    sa.Column('author', sa.String(length=300), nullable=True),
    sa.Column('verified', sa.Boolean(), nullable=False),
    sa.Column('stars', sa.Integer(), nullable=True),
    sa.Column('language', sa.String(length=64), nullable=True),
    sa.Column('cve_ids', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('tier', sa.Integer(), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('source_updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source_key', 'external_id', name='uq_exploit')
    )
    with op.batch_alter_table('exploits', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_exploits_collected_at'), ['collected_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_exploits_published_at'), ['published_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_exploits_source_key'), ['source_key'], unique=False)

    op.create_table('http_cache',
    sa.Column('url', sa.Text(), nullable=False),
    sa.Column('etag', sa.Text(), nullable=True),
    sa.Column('last_modified', sa.Text(), nullable=True),
    sa.Column('content_sha256', sa.String(length=64), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('url')
    )
    op.create_table('nvd_cache',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('found', sa.Boolean(), nullable=False),
    sa.Column('payload', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.PrimaryKeyConstraint('cve_id')
    )
    op.create_table('sources',
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('homepage', sa.Text(), nullable=False),
    sa.Column('endpoint', sa.Text(), nullable=False),
    sa.Column('category', sa.String(length=64), nullable=False),
    sa.Column('source_type', sa.String(length=64), nullable=False),
    sa.Column('tier', sa.Integer(), nullable=False),
    sa.Column('method', sa.String(length=32), nullable=False),
    sa.Column('phase', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('requires_auth', sa.Boolean(), nullable=False),
    sa.Column('interval_seconds', sa.Integer(), nullable=False),
    sa.Column('last_attempt', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_successful_fetch', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_status', sa.String(length=32), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('items_fetched', sa.Integer(), nullable=False),
    sa.Column('items_new', sa.Integer(), nullable=False),
    sa.Column('items_updated', sa.Integer(), nullable=False),
    sa.Column('latency_ms', sa.Integer(), nullable=True),
    sa.Column('consecutive_failures', sa.Integer(), nullable=False),
    sa.Column('state', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('vulnerabilities',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('title', sa.Text(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('vuln_status', sa.String(length=64), nullable=True),
    sa.Column('published', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_modified', sa.DateTime(timezone=True), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.Column('cvss_severity', sa.String(length=16), nullable=True),
    sa.Column('cvss_vector', sa.String(length=200), nullable=True),
    sa.Column('cvss_version', sa.String(length=8), nullable=True),
    sa.Column('ssvc_exploitation', sa.String(length=16), nullable=True),
    sa.Column('ssvc_automatable', sa.String(length=8), nullable=True),
    sa.Column('ssvc_technical_impact', sa.String(length=16), nullable=True),
    sa.Column('cwes', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('vendor', sa.String(length=200), nullable=True),
    sa.Column('product', sa.String(length=300), nullable=True),
    sa.Column('in_kev', sa.Boolean(), nullable=False),
    sa.Column('kev_name', sa.Text(), nullable=True),
    sa.Column('kev_date_added', sa.Date(), nullable=True),
    sa.Column('kev_due_date', sa.Date(), nullable=True),
    sa.Column('kev_required_action', sa.Text(), nullable=True),
    sa.Column('kev_ransomware', sa.String(length=16), nullable=True),
    sa.Column('kev_notes', sa.Text(), nullable=True),
    sa.Column('actively_exploited', sa.Boolean(), nullable=False),
    sa.Column('has_exploit', sa.Boolean(), nullable=False),
    sa.Column('has_poc', sa.Boolean(), nullable=False),
    sa.Column('exploit_count', sa.Integer(), nullable=False),
    sa.Column('poc_count', sa.Integer(), nullable=False),
    sa.Column('source_count', sa.Integer(), nullable=False),
    sa.Column('tags', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('platforms', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('relevance_score', sa.Integer(), nullable=False),
    sa.Column('relevance_reasons', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('techniques', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('nvd_fetched_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('github_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('cve_id')
    )
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vulnerabilities_actively_exploited'), ['actively_exploited'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_cvss_severity'), ['cvss_severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_first_seen'), ['first_seen'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_has_exploit'), ['has_exploit'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_has_poc'), ['has_poc'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_in_kev'), ['in_kev'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_kev_date_added'), ['kev_date_added'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_last_activity_at'), ['last_activity_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_product'), ['product'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_published'), ['published'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_relevance_score'), ['relevance_score'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_updated_at'), ['updated_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_vulnerabilities_vendor'), ['vendor'], unique=False)

    op.create_table('affected_products',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('vendor', sa.String(length=200), nullable=False),
    sa.Column('product', sa.String(length=300), nullable=False),
    sa.Column('cpe', sa.String(length=400), nullable=False),
    sa.Column('versions', sa.Text(), nullable=True),
    sa.Column('source_key', sa.String(length=64), nullable=False),
    sa.ForeignKeyConstraint(['cve_id'], ['vulnerabilities.cve_id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('cve_id', 'vendor', 'product', 'cpe', name='uq_affected')
    )
    with op.batch_alter_table('affected_products', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_affected_products_cve_id'), ['cve_id'], unique=False)

    op.create_table('ingestion_runs',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('source_key', sa.String(length=64), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('items_fetched', sa.Integer(), nullable=False),
    sa.Column('items_new', sa.Integer(), nullable=False),
    sa.Column('items_updated', sa.Integer(), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['source_key'], ['sources.key'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('ingestion_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ingestion_runs_source_key'), ['source_key'], unique=False)

    op.create_table('source_references',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('source_key', sa.String(length=64), nullable=False),
    sa.Column('url', sa.Text(), nullable=False),
    sa.Column('title', sa.Text(), nullable=True),
    sa.Column('ref_type', sa.String(length=32), nullable=False),
    sa.Column('tags', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['cve_id'], ['vulnerabilities.cve_id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('cve_id', 'url', name='uq_source_ref')
    )
    with op.batch_alter_table('source_references', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_source_references_cve_id'), ['cve_id'], unique=False)



    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_documents_fts ON documents USING gin "
            "(to_tsvector('english', coalesce(title,'') || ' ' || coalesce(summary,'')))"
        )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_documents_fts")
    # Baseline: the schema as of the first release. Generated from app.models
    # and reviewed by hand; later revisions are written explicitly.
    with op.batch_alter_table('source_references', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_source_references_cve_id'))

    op.drop_table('source_references')
    with op.batch_alter_table('ingestion_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ingestion_runs_source_key'))

    op.drop_table('ingestion_runs')
    with op.batch_alter_table('affected_products', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_affected_products_cve_id'))

    op.drop_table('affected_products')
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_vendor'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_updated_at'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_relevance_score'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_published'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_product'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_last_activity_at'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_kev_date_added'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_in_kev'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_has_poc'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_has_exploit'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_first_seen'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_cvss_severity'))
        batch_op.drop_index(batch_op.f('ix_vulnerabilities_actively_exploited'))

    op.drop_table('vulnerabilities')
    op.drop_table('sources')
    op.drop_table('nvd_cache')
    op.drop_table('http_cache')
    with op.batch_alter_table('exploits', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_exploits_source_key'))
        batch_op.drop_index(batch_op.f('ix_exploits_published_at'))
        batch_op.drop_index(batch_op.f('ix_exploits_collected_at'))

    op.drop_table('exploits')
    with op.batch_alter_table('entity_links', schema=None) as batch_op:
        batch_op.drop_index('ix_link_subject')
        batch_op.drop_index('ix_link_object')
        batch_op.drop_index(batch_op.f('ix_entity_links_observed_at'))

    op.drop_table('entity_links')
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_documents_source_key'))
        batch_op.drop_index(batch_op.f('ix_documents_published_at'))
        batch_op.drop_index(batch_op.f('ix_documents_doc_type'))
        batch_op.drop_index(batch_op.f('ix_documents_collected_at'))

    op.drop_table('documents')
    with op.batch_alter_table('attack_relationships', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_attack_relationships_target_ref'))
        batch_op.drop_index(batch_op.f('ix_attack_relationships_source_ref'))
        batch_op.drop_index(batch_op.f('ix_attack_relationships_relationship_type'))

    op.drop_table('attack_relationships')
    with op.batch_alter_table('attack_objects', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_attack_objects_obj_type'))
        batch_op.drop_index(batch_op.f('ix_attack_objects_name'))
        batch_op.drop_index(batch_op.f('ix_attack_objects_external_id'))

    op.drop_table('attack_objects')
