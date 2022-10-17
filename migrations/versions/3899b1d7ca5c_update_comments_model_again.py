"""update comments model again

Revision ID: 3899b1d7ca5c
Revises: acb0eb8ffbe6
Create Date: 2022-07-05 13:04:41.517985

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3899b1d7ca5c'
down_revision = 'acb0eb8ffbe6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('comments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('text', sa.String(length=200), nullable=False),
    sa.Column('date_added', sa.DateTime(), nullable=True),
    sa.Column('username', sa.Integer(), nullable=True),
    sa.Column('post_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['post_id'], ['posts.id'], ),
    sa.ForeignKeyConstraint(['username'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_foreign_key(None, 'posts', 'users', ['poster_id'], ['id'])
    op.drop_column('posts', 'author')
    op.create_unique_constraint(None, 'users', ['username'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.add_column('posts', sa.Column('author', sa.VARCHAR(length=255), nullable=True))
    op.drop_constraint(None, 'posts', type_='foreignkey')
    op.drop_table('comments')
    # ### end Alembic commands ###
