"""Add scan_result_id to verifications table.

Allows auto-verify jobs to record which ScanResult triggered them,
improving traceability from scan result → verification → finding.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-03-12 17:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "verifications",
        sa.Column("scan_result_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_verifications_scan_result_id",
        "verifications",
        "scan_results",
        ["scan_result_id"],
        ["id"],
    )
    op.create_index(
        op.f("ix_verifications_scan_result_id"),
        "verifications",
        ["scan_result_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_verifications_scan_result_id"), table_name="verifications")
    op.drop_constraint("fk_verifications_scan_result_id", "verifications", type_="foreignkey")
    op.drop_column("verifications", "scan_result_id")
