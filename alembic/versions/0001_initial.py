"""initial findings table

Revision ID: 0001_initial
Revises:
Create Date: 2026-02-17
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("scanner", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False, server_default="default"),
        sa.Column("category", sa.String(), nullable=False, server_default="security"),
        sa.Column("severity", sa.String(), nullable=False, server_default="medium"),
        sa.Column("rule_id", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("title", sa.String(), nullable=False, server_default="Unnamed finding"),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
        sa.Column("recommendation", sa.String(), nullable=False, server_default=""),
        sa.Column("file_path", sa.String(), nullable=False, server_default=""),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("source", sa.String(), nullable=False, server_default="ci"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"], unique=True)
    op.create_index("ix_findings_scanner", "findings", ["scanner"], unique=False)
    op.create_index("ix_findings_project_id", "findings", ["project_id"], unique=False)
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_project_id", table_name="findings")
    op.drop_index("ix_findings_scanner", table_name="findings")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_table("findings")
