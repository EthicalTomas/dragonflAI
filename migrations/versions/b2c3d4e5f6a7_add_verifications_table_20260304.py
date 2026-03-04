"""add verifications table

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-04 17:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verifications",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("method", sa.String(length=64), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=True),
        sa.Column("log_text", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_verifications_target_id"), "verifications", ["target_id"], unique=False)
    op.create_index(op.f("ix_verifications_run_id"), "verifications", ["run_id"], unique=False)
    op.create_index(op.f("ix_verifications_finding_id"), "verifications", ["finding_id"], unique=False)
    op.create_index(op.f("ix_verifications_status"), "verifications", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_verifications_status"), table_name="verifications")
    op.drop_index(op.f("ix_verifications_finding_id"), table_name="verifications")
    op.drop_index(op.f("ix_verifications_run_id"), table_name="verifications")
    op.drop_index(op.f("ix_verifications_target_id"), table_name="verifications")
    op.drop_table("verifications")
