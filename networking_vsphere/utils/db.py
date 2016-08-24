from neutron.db import agents_db
from neutron.db import api as db_api

from networking_vsphere.common import constants

def get_agent_by_host(agent_host):
    """Return a L2 agent on the host."""
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        query = session.query(agents_db.Agent)
        agent = query.filter(agents_db.Agent.host == agent_host,
            agents_db.Agent.agent_type ==  constants.AGENT_TYPE_DVS,
            agents_db.Agent.admin_state_up == True).first()
        if agent and agent.is_active:
            return agent
    return None
