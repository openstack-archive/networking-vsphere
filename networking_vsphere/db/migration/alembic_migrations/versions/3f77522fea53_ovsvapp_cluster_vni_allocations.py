# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Table for ovsvapp cluster vni allocations.

Revision ID: 3f77522fea53
Revises: start_ovsvapp_migration
Create Date: 2015-03-25 02:40:53.207016
"""

# revision identifiers, used by Alembic.
revision = '3f77522fea53'
down_revision = 'start_ovsvapp_migration'

from alembic import op
import sqlalchemy as sa


def downgrade():
    op.drop_table('ovsvapp_cluster_vni_allocations')


def upgrade():
    op.create_table('ovsvapp_cluster_vni_allocations',
                    sa.Column('vcenter_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('cluster_id', sa.String(length=255),
                              nullable=False),
                    sa.Column('lvid', sa.Integer(), nullable=False,
                              autoincrement=False),
                    sa.Column('network_id', sa.String(length=36)),
                    sa.Column('allocated', sa.Boolean(),
                              server_default=sa.sql.false(), nullable=False),
                    sa.Column('network_port_count', sa.Integer(),
                              server_default='0', nullable=False),
                    sa.PrimaryKeyConstraint('vcenter_id', 'cluster_id',
                                            'lvid')
                    )
