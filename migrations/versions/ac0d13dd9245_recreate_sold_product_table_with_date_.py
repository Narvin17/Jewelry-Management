"""Recreate sold_product table with date_sold

Revision ID: ac0d13dd9245
Revises: c98d221ef58d
Create Date: 2024-10-11 22:12:17.599225

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ac0d13dd9245'
down_revision = 'c98d221ef58d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('sold_product',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.Column('date_sold', sa.DateTime(), nullable=False),
    sa.Column('quantity_sold', sa.Integer(), nullable=False),
    sa.Column('total_price', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['product_id'], ['inventory.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('sold_product')
    # ### end Alembic commands ###
