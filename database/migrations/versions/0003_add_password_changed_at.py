"""add_password_changed_at

Revision ID: 0003_add_password_changed_at
Revises: 0002_fix_audit_fk_and_hash
Create Date: 2026-11-26 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_add_password_changed_at"
down_revision: Union[str, None] = "0002_fix_audit_fk_and_hash"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = [c["name"] for c in insp.get_columns("users")]

    if "password_changed_at" not in cols:
        is_postgres = bind is not None and bind.dialect.name == "postgresql"
        if is_postgres:
            op.add_column(
                "users",
                sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
            )
        else:
            with op.batch_alter_table("users") as batch_op:
                batch_op.add_column(
                    sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True)
                )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind is not None and bind.dialect.name == "postgresql"

    if is_postgres:
        op.drop_column("users", "password_changed_at")
    else:
        with op.batch_alter_table("users") as batch_op:
            batch_op.drop_column("password_changed_at")
