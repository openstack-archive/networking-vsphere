# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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

import socket
import sys

from oslo.config import cfg
from oslo import messaging

from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as neutron_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.openvswitch.agent import ovs_neutron_agent as ovs_agent

from networking_vsphere.agent import agent
from networking_vsphere.common import constants as ovsvapp_const

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class OVSvAppL2Agent(agent.Agent, ovs_agent.OVSNeutronAgent,
                     sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    """OVSvApp L2 Agent."""

    def __init__(self):
        agent.Agent.__init__(self)
        neutron_config.init(sys.argv[1:])
        neutron_config.setup_logging()
        self.hostname = socket.getfqdn()
        self.bridge_mappings = CONF.OVSVAPP.bridge_mappings
        self.tunnel_types = []
        self.agent_state = {
            'binary': 'ovsvapp-agent',
            'host': self.hostname,
            'topic': topics.AGENT,
            'configurations': {'bridge_mappings': self.bridge_mappings,
                               'tunnel_types': self.tunnel_types},
            'agent_type': ovsvapp_const.AGENT_TYPE_OVSVAPP,
            'start_flag': True}

        self.setup_rpc()
        self.setup_report_states()

    def start(self):
        LOG.info(_("Starting OVSvApp L2 Agent"))
        self.set_node_state(True)

    def stop(self):
        LOG.info(_("Stopping OVSvApp L2 Agent"))
        self.set_node_state(False)
        if self.connection:
            self.connection.close()

    def _report_state(self):

        """Reporting agent state to neutron server."""

        try:
            if self.agent_state.get("start_flag"):
                LOG.info(_("OVSvApp Agent reporting state %s"),
                         self.agent_state)
            self.state_rpc.report_state(self.context, self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Heartbeat failure - Failed reporting state!"))

    def setup_report_states(self):

        """Method to send heartbeats to the neutron server."""

        report_interval = CONF.OVSVAPP.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)
        else:
            LOG.warn(_("Report interval is not initialized."
                       "Unable to send heartbeats to Neutron Server"))

    def setup_rpc(self):
        # Ensure that the control exchange is set correctly
        self.agent_id = "ovsvapp-agent %s" % self.hostname
        self.topic = topics.AGENT
        self.plugin_rpc = RpcPluginApi()
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.ovsvapp_rpc = OVSvAppPluginApi(ovsvapp_const.OVSVAPP)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [
            [topics.PORT, topics.UPDATE],
            [ovsvapp_const.DEVICE, topics.CREATE],
            [ovsvapp_const.DEVICE, topics.UPDATE],
            [topics.SECURITY_GROUP, topics.UPDATE]
        ]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        LOG.debug("Finished Setup RPC")


class RpcPluginApi(agent_rpc.PluginApi,
                   sg_rpc.SecurityGroupServerRpcApi):

    def __init__(self):
        super(RpcPluginApi, self).__init__(topic=topics.PLUGIN)


class OVSvAppPluginApi(object):

    def __init__(self, topic):
        target = messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_ports_for_device(self, context, device, agent_id):
        cctxt = self.client.prepare()
        LOG.info(_(" RPC get_ports_for_device is called for device_id: %s"),
                 device['id'])
        return cctxt.call(context, 'get_ports_for_device', device=device,
                          agent_id=agent_id)

    def update_port_binding(self, context, agent_id, port_id, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_port_binding', agent_id=agent_id,
                          port_id=port_id, host=host)