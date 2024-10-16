"""Add fields to SoldProduct model

Revision ID: 30c7ec425ef3
Revises: ac0d13dd9245
Create Date: 2024-10-11 22:28:58.291537

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '30c7ec425ef3'
down_revision = 'ac0d13dd9245'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('sold_product', schema=None) as batch_op:
        # Add a named constraint, for example:
        batch_op.create_unique_constraint('uq_sold_product_barcode', ['barcode'])  # Ensure you provide a name for the constraint

def downgrade():
    with op.batch_alter_table('sold_product', schema=None) as batch_op:
        # Ensure the same named constraint is removed in downgrade
        batch_op.drop_constraint('uq_sold_product_barcode', type_='unique')

    # ### end Alembic commands ###
