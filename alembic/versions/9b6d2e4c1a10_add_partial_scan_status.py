"""add partial scan status

Revision ID: 9b6d2e4c1a10
Revises: 3f2a9c1d4b7e
Create Date: 2026-10-26 00:00:00.000000

A completed assessment whose security stages partially failed must be
distinguishable from a clean completion. PostgreSQL stores scan status as a
plain string with a check constraint, so the constraint is replaced here
rather than converting the column to a native enum.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9b6d2e4c1a10"
down_revision: Union[str, Sequence[str], None] = "3f2a9c1d4b7e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Allow the 'partial' assessment status."""
    op.drop_constraint("ck_scans_status", "scans", type_="check")
    op.create_check_constraint(
        "ck_scans_status",
        "scans",
        "status IN ('pending','running','completed','partial','failed')",
    )


def downgrade() -> None:
    """Remove the 'partial' assessment status.

    Existing partial rows are converted to completed so the old constraint
    can be recreated without discarding assessment records.
    """
    op.execute("UPDATE scans SET status = 'completed' WHERE status = 'partial'")
    op.drop_constraint("ck_scans_status", "scans", type_="check")
    op.create_check_constraint(
        "ck_scans_status",
        "scans",
        "status IN ('pending','running','completed','failed')",
    )
