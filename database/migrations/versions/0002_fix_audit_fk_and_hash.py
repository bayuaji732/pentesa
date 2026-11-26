"""fix_audit_fk_and_hash

Revision ID: 0002_fix_audit_fk_and_hash
Revises: 0001_initial_schema
Create Date: 2026-11-26 10:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002_fix_audit_fk_and_hash"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind is not None and bind.dialect.name == "postgresql"
    insp = sa.inspect(bind)
    cols = [c["name"] for c in insp.get_columns("audit_logs")]

    if is_postgres:
        # Add columns to audit_logs if not already present
        if "hash_version" not in cols:
            op.add_column("audit_logs", sa.Column("hash_version", sa.Integer(), server_default="1", nullable=False))
        if "user_email" not in cols:
            op.add_column("audit_logs", sa.Column("user_email", sa.String(length=255), nullable=True))

        # Alter foreign keys from SET NULL to RESTRICT
        try:
            op.drop_constraint("audit_logs_user_id_fkey", "audit_logs", type_="foreignkey")
            op.drop_constraint("audit_logs_project_id_fkey", "audit_logs", type_="foreignkey")
        except Exception:
            pass

        op.create_foreign_key(
            "audit_logs_user_id_fkey",
            "audit_logs",
            "users",
            ["user_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.create_foreign_key(
            "audit_logs_project_id_fkey",
            "audit_logs",
            "projects",
            ["project_id"],
            ["id"],
            ondelete="RESTRICT",
        )
    else:
        # SQLite batch mode
        with op.batch_alter_table("audit_logs") as batch_op:
            if "hash_version" not in cols:
                batch_op.add_column(sa.Column("hash_version", sa.Integer(), server_default="1", nullable=False))
            if "user_email" not in cols:
                batch_op.add_column(sa.Column("user_email", sa.String(length=255), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind is not None and bind.dialect.name == "postgresql"

    if is_postgres:
        op.drop_constraint("audit_logs_user_id_fkey", "audit_logs", type_="foreignkey")
        op.drop_constraint("audit_logs_project_id_fkey", "audit_logs", type_="foreignkey")

        op.create_foreign_key(
            "audit_logs_user_id_fkey",
            "audit_logs",
            "users",
            ["user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.create_foreign_key(
            "audit_logs_project_id_fkey",
            "audit_logs",
            "projects",
            ["project_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.drop_column("audit_logs", "user_email")
        op.drop_column("audit_logs", "hash_version")
    else:
        with op.batch_alter_table("audit_logs") as batch_op:
            batch_op.drop_column("user_email")
            batch_op.drop_column("hash_version")
