"""add assessment_stages

Revision ID: 3f2a9c1d4b7e
Revises: caaa71487895
Create Date: 2026-10-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import sqlmodel

# revision identifiers, used by Alembic.
revision: str = "3f2a9c1d4b7e"
down_revision: Union[str, Sequence[str], None] = "caaa71487895"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the per-scan assessment stage outcome table."""
    op.create_table(
        "assessment_stages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column(
            "stage_name", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("reason", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "recorded_at", sqlmodel.sql.sqltypes.UTCDateTime(), nullable=False
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id",
            "stage_name",
            name="uq_assessment_stages_scan_id_stage_name",
        ),
    )


def downgrade() -> None:
    """Drop the assessment stage outcome table."""
    op.drop_table("assessment_stages")
