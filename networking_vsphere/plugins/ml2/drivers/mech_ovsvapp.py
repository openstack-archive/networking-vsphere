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

from oslo import messaging

from neutron.common import constants as q_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
import time

LOG = log.getLogger(__name__)

AGENT_TYPE_OVSVAPP = "OVSvApp L2 Agent"
OVSVAPP = 'ovsvapp'
DEVICE = 'device'


class OVSvAppAgentMechanismDriver(
        mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using OVSvApp Agent.

    The OVSvAppAgentMechanismDriver integrates the ml2 plugin with the
    OVSvApp Agent. Port binding with this driver requires the
    OVSvApp Agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """
    def __init__(self):
        super(OVSvAppAgentMechanismDriver, self).__init__(
            AGENT_TYPE_OVSVAPP,
            portbindings.VIF_TYPE_OTHER,
            {portbindings.CAP_PORT_FILTER: True})
        self._start_rpc_listeners()

    def check_segment_for_agent(self, segment, agent):
        LOG.debug("Checking segment: %(segment)s ", {'segment': segment})
        if segment[api.NETWORK_TYPE] in ['vlan', 'vxlan']:
            return True
        else:
            return False

    def _start_rpc_listeners(self):
        self.notifier = OVSvAppAgentNotifyAPI(topics.AGENT)
        self.endpoints = [OVSvAppServerRpcCallback(self.notifier)]
        self.topic = OVSVAPP
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()


class OVSvAppServerRpcCallback(object):

    """Plugin side of the OVSvApp rpc.

    This class contains extra rpc callbacks to be served for use by the
    OVSvApp Agent.
    """
    target = messaging.Target(version='1.0')

    def __init__(self, notifier=None):
        super(OVSvAppServerRpcCallback, self).__init__()
        self.notifier = notifier

    @property
    def plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_devices_info(self, devices, plugin):
        return dict(
            (port['id'], port)
            for port in self.plugin.get_ports_from_devices(devices)
            if port and not port['device_owner'].startswith('network:')
        )

    def get_ports_for_device(self, rpc_context, **kwargs):
        """RPC for getting port info.

        This method provides information about the network and port for
        a given device_id.
        """
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        device_id = device['id']
        LOG.debug("Device %(device_id)s details requested by agent "
                  "%(agent_id)s",
                  {'device_id': device_id, 'agent_id': agent_id})
        if not device_id:
            return False
        try_count = 3
        try:
            while try_count > 0:
                ports = self.plugin.get_ports(rpc_context,
                                              filters={'device_id':
                                                       [device_id]})
                device_ports = []
                sg_port_ids = set()
                for port in ports:
                    network = self.plugin.get_network(rpc_context,
                                                      port['network_id'])
                    port.update(
                        {'network_type': network['provider:network_type'],
                         'segmentation_id':
                         network['provider:segmentation_id'],
                         'physical_network':
                         network['provider:physical_network']})

                    new_status = (q_const.PORT_STATUS_BUILD
                                  if port['admin_state_up']
                                  else q_const.PORT_STATUS_DOWN)
                    if port['status'] != new_status:
                        port['status'] = new_status

                    if 'security_groups' in port:
                        sg_port_ids.add(port['id'])

                    device_ports.append(port)
                if not device_ports:
                    try_count -= 1
                    LOG.debug("Port details could not be retrieved for "
                              "device %s ..retrying", device_id)
                    time.sleep(3)
                else:
                    LOG.debug("Device details returned by controller:"
                              " %s", device_ports)
                    # Get the SG rules for the security enabled ports
                    sg_payload = {}
                    if sg_port_ids:
                        ports = self._get_devices_info(sg_port_ids,
                                                       self.plugin)
                        sg_rules = self.plugin.security_group_rules_for_ports(
                            rpc_context, ports)
                        sg_payload[device_id] = sg_rules
                    self.notifier.device_create(rpc_context, device,
                                                device_ports, sg_payload)
                    return True
        except Exception:
            LOG.exception(_("Failed to retrieve port details for "
                            "device %s") % device_id)
        LOG.debug("Failed to retrieve ports for device %s", device_id)
        return False

    def update_port_binding(self, rpc_context, **kwargs):
        agent_id = kwargs.get('agent_id')
        port_id = kwargs.get('port_id')
        host = kwargs.get('host')
        LOG.debug("Port %(port_id)s update_port_binding() invoked by agent "
                  "%(agent_id)s for host %(host)s",
                  {'port_id': port_id, 'agent_id': agent_id, 'host': host})
        port = {'port': {portbindings.HOST_ID: host}}
        updated_port = self.plugin.update_port(rpc_context, port_id, port)
        return updated_port


class OVSvAppAgentNotifyAPI(object):

    """Agent side of the OVSvApp rpc API.

    """

    def __init__(self, topic=topics.AGENT):
        target = messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        self.topic = topic

    def _get_device_topic(self, action):
        return topics.get_topic_name(self.topic,
                                     DEVICE,
                                     action)

    def device_create(self, context, device, ports, sg_rules):
        cctxt = self.client.prepare(
            topic=self._get_device_topic(topics.CREATE), fanout=True)
        cctxt.cast(context, 'device_create', device=device, ports=ports,
                   sg_rules=sg_rules)

    def device_update(self, context, device_data):
        cctxt = self.client.prepare(
            topic=self._get_device_topic(topics.UPDATE), fanout=True)
        cctxt.cast(context, 'device_update', device_data=device_data)