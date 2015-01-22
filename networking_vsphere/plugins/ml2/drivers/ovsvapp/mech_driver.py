# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
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

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2.drivers import mech_agent

from networking_vsphere.common import constants
from networking_vsphere.plugins.ml2.drivers.ovsvapp import rpc

LOG = log.getLogger(__name__)


class OVSvAppAgentMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using OVSvApp Agent.

    The OVSvAppAgentMechanismDriver integrates the ml2 plugin with the
    OVSvApp Agent. Port binding with this driver requires the
    OVSvApp Agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """
    # TODO(romilg): Move this mech_driver to Neutron eventually.

    def __init__(self):
        super(OVSvAppAgentMechanismDriver, self).__init__(
            constants.AGENT_TYPE_OVSVAPP,
            portbindings.VIF_TYPE_OTHER,
            {portbindings.CAP_PORT_FILTER: True})
        self._start_rpc_listeners()

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [p_constants.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('bridge_mappings', {})

    def _start_rpc_listeners(self):
        self.notifier = rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self.endpoints = [rpc.OVSvAppServerRpcCallback(self.notifier)]
        self.topic = constants.OVSVAPP
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()
