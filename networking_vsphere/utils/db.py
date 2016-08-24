# Copyright 2016 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from neutron.db import agents_db
from neutron.db import api as db_api

from networking_vsphere.common import constants


def get_agent_by_host(agent_host):
    """Return a L2 agent on the host."""
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        query = session.query(agents_db.Agent)
        agent = query.filter(
            agents_db.Agent.host == agent_host,
            agents_db.Agent.agent_type == constants.AGENT_TYPE_DVS,
            agents_db.Agent.admin_state_up.is_(True)).first()
        if agent and agent.is_active:
            return agent
    return None
