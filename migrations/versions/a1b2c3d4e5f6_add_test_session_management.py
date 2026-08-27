"""Add test session management

Revision ID: a1b2c3d4e5f6
Revises: 7fe8b5951400
Create Date: 2026-07-05 00:00:00.000000

NOTE: This migration creates a 'Sesi Legacy' session for backward compatibility.
This legacy session is created for existing data migration purposes only.
After migration, sessions should ONLY be created by user action via 'Mulai Skenario Baru' button.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision = "a1b2c3d4e5f6"
down_revision = "7fe8b5951400"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "test_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_name", sa.String(length=150), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    conn = op.get_bind()
    conn.execute(
        text(
            "INSERT INTO test_sessions (session_name, description, started_at, status) "
            "VALUES ('Sesi Legacy', 'Data pengujian sebelum session management', NOW(), 'finished')"
        )
    )
    legacy_id = conn.execute(text("SELECT id FROM test_sessions ORDER BY id ASC LIMIT 1")).scalar()

    with op.batch_alter_table("security_logs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("session_id", sa.Integer(), nullable=True))
    conn.execute(text("UPDATE security_logs SET session_id = :sid WHERE session_id IS NULL"), {"sid": legacy_id})
    with op.batch_alter_table("security_logs", schema=None) as batch_op:
        batch_op.alter_column("session_id", nullable=False)
        batch_op.create_index("ix_security_logs_session_id", ["session_id"])
        batch_op.create_foreign_key("fk_security_logs_session", "test_sessions", ["session_id"], ["id"])

    with op.batch_alter_table("csp_reports", schema=None) as batch_op:
        batch_op.add_column(sa.Column("session_id", sa.Integer(), nullable=True))
    conn.execute(text("UPDATE csp_reports SET session_id = :sid WHERE session_id IS NULL"), {"sid": legacy_id})
    with op.batch_alter_table("csp_reports", schema=None) as batch_op:
        batch_op.alter_column("session_id", nullable=False)
        batch_op.create_index("ix_csp_reports_session_id", ["session_id"])
        batch_op.create_foreign_key("fk_csp_reports_session", "test_sessions", ["session_id"], ["id"])


def downgrade():
    with op.batch_alter_table("csp_reports", schema=None) as batch_op:
        batch_op.drop_constraint("fk_csp_reports_session", type_="foreignkey")
        batch_op.drop_index("ix_csp_reports_session_id")
        batch_op.drop_column("session_id")

    with op.batch_alter_table("security_logs", schema=None) as batch_op:
        batch_op.drop_constraint("fk_security_logs_session", type_="foreignkey")
        batch_op.drop_index("ix_security_logs_session_id")
        batch_op.drop_column("session_id")

    op.drop_table("test_sessions")
