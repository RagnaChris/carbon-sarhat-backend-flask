"""Check changes

Revision ID: d36121c1149b
Revises: 1bc581df1012
Create Date: 2023-06-09 19:19:34.130136

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd36121c1149b'
down_revision = '1bc581df1012'
branch_labels = None
depends_on = None


def upgrade():
    # Create a new temporary column
    op.add_column('users', sa.Column('role_new', sa.Enum('Admin', 'User', 'Institution', name='role'), nullable=False))

    # Update the new column with the existing values
    op.execute("UPDATE users SET role_new = role")

    # Drop the old column
    op.drop_column('users', 'role')

    # Rename the new column to the original name
    op.alter_column('users', 'role_new', new_column_name='role')


def downgrade():
    # Create a new temporary column
    op.add_column('users', sa.Column('role_new', sa.Enum('Admin', 'User', 'Institution', name='role'), nullable=False))

    # Update the new column with the existing values
    op.execute("UPDATE users SET role_new = role")

    # Drop the old column
    op.drop_column('users', 'role')

    # Rename the new column to the original name
    op.alter_column('users', 'role_new', new_column_name='role')