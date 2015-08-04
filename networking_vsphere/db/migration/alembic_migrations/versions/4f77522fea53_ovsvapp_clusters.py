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

"""Table for ovsvapp managed clusters.

Revision ID: 4f77522fea53
Revises: 3f77522fea53
Create Date: 2015-08-04 02:40:53.207016
"""

# revision identifiers, used by Alembic.
revision = '4f77522fea53'
down_revision = '3f77522fea53'

from alembic import op
import sqlalchemy as sa


def downgrade():
    op.drop_table('ovsvapp_clusters')


def upgrade():
    op.create_table('ovsvapp_clusters',
                    sa.Column('vcenter_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('cluster_id', sa.String(length=255),
                              nullable=False),
                    sa.Column('being_mitigated', sa.Boolean(),
                              server_default=sa.sql.false(), nullable=False),
                    sa.Column('threshold_reached', sa.Boolean(),
                              server_default=sa.sql.false(), nullable=False),
                    sa.PrimaryKeyConstraint('vcenter_id', 'cluster_id')
                    )
