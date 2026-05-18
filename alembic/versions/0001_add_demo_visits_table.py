"""add demo visits table

Revision ID: 0001
Revises: 
Create Date: 2026-05-17 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'demo_visits',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('ip_address', sa.String()),
        sa.Column('user_agent', sa.String()),
        sa.Column('timestamp', sa.String(), nullable=False),
        sa.Column('pages_viewed', sa.Integer(), default=0)
    )

def downgrade():
    op.drop_table('demo_visits')
