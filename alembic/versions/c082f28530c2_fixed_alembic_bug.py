"""Fixed alembic bug

Revision ID: c082f28530c2
Revises: d36121c1149b
Create Date: 2023-06-09 22:53:26.333946

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c082f28530c2'
down_revision = 'd36121c1149b'
branch_labels = None
depends_on = None


def upgrade():
    # Create a new temporary column
    op.add_column('users', sa.Column('role_new', sa.Enum('ADMIN', 'USER', 'INSTITUTION', name='role'), nullable=False))

    # Update the new column with the existing values
    op.execute("UPDATE users SET role_new = role")

    # Drop the old column
    op.drop_column('users', 'role')

    # Rename the new column to the original name
    op.alter_column('users', 'role_new', new_column_name='role')


def downgrade():
    # Create a new temporary column
    op.add_column('users', sa.Column('role_new', sa.Enum('ADMIN', 'USER', 'INSTITUTION', name='role'), nullable=False))

    # Update the new column with the existing values
    op.execute("UPDATE users SET role_new = role")

    # Drop the old column
    op.drop_column('users', 'role')

    # Rename the new column to the original name
    op.alter_column('users', 'role_new', new_column_name='role')