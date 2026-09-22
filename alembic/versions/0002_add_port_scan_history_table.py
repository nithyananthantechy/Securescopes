"""add port scan history table

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-24 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'port_scan_history',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('target_host', sa.String(255), nullable=False),
        sa.Column('target_ip', sa.String(45), nullable=True),
        sa.Column('scan_type', sa.String(50), nullable=False, default='quick'),
        sa.Column('ports_scanned', sa.String(1024), nullable=False),
        sa.Column('open_ports', sa.JSON, nullable=True),
        sa.Column('risk_score', sa.Integer, nullable=True),
        sa.Column('risk_level', sa.String(20), nullable=True),
        sa.Column('findings_count', sa.Integer, default=0),
        sa.Column('services_detected', sa.JSON, nullable=True),
        sa.Column('timestamp', sa.DateTime, nullable=False),
        sa.Column('duration_seconds', sa.Float, nullable=True),
        sa.Column('status', sa.String(20), default='completed'),
        sa.Column('notes', sa.Text, nullable=True),
        sa.Column('report_path', sa.String(512), nullable=True),
        sa.Column('remediation_suggestions', sa.JSON, nullable=True),
        sa.Index('idx_user_id', 'user_id'),
        sa.Index('idx_target_host', 'target_host'),
        sa.Index('idx_timestamp', 'timestamp'),
        sa.Index('idx_risk_score', 'risk_score'),
        sa.Index('idx_status', 'status'),
    )

def downgrade():
    op.drop_table('port_scan_history')
