"""Add human-review fields to findings table and update status lifecycle.

Adds:
  - reviewed_by_human (Boolean, default False)
  - reviewed_at       (DateTime, nullable)
  - reviewer          (String,   nullable)
  - review_notes      (Text,     nullable)
  - log_text          (Text,     nullable)

Also updates the FindingStatus lifecycle:
  draft → needs_review → ready_to_submit → submitted

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-03-12 13:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("reviewed_by_human", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "findings",
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("reviewer", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("review_notes", sa.Text(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("log_text", sa.Text(), nullable=True),
    )

    # Migrate legacy 'ready' status to 'ready_to_submit'
    op.execute(
        "UPDATE findings SET status = 'ready_to_submit' WHERE status = 'ready'"
    )


def downgrade() -> None:
    # Restore legacy 'ready' status
    op.execute(
        "UPDATE findings SET status = 'ready' WHERE status = 'ready_to_submit'"
    )

    op.drop_column("findings", "log_text")
    op.drop_column("findings", "review_notes")
    op.drop_column("findings", "reviewer")
    op.drop_column("findings", "reviewed_at")
    op.drop_column("findings", "reviewed_by_human")
