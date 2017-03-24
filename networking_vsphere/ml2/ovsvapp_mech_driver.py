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

import eventlet
eventlet.monkey_patch()
import netaddr
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils

from neutron.common import constants as common_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as neutron_context
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent

from networking_vsphere._i18n import _LE, _LI
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.db import ovsvapp_db
from networking_vsphere.ml2 import ovsvapp_rpc
from networking_vsphere.monitor import ovsvapp_monitor

LOG = log.getLogger(__name__)


class OVSvAppAgentMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using OVSvApp Agent.

    The OVSvAppAgentMechanismDriver integrates the ml2 plugin with the
    OVSvApp Agent. Port binding with this driver requires the
    OVSvApp Agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """
    def __init__(self):
        super(OVSvAppAgentMechanismDriver, self).__init__(
            ovsvapp_const.AGENT_TYPE_OVSVAPP,
            portbindings.VIF_TYPE_OTHER,
            {portbindings.CAP_PORT_FILTER: True})
        self.context = neutron_context.get_admin_context()
        self._start_rpc_listeners()
        self._plugin = None
        self._pool = None
        self.supported_network_types = [p_const.TYPE_VLAN, p_const.TYPE_VXLAN]
        LOG.info(_LI("Successfully initialized OVSvApp Mechanism driver."))
        if cfg.CONF.OVSVAPP.enable_ovsvapp_monitor:
            self._start_ovsvapp_monitor()

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [p_const.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('bridge_mappings', {})

    @property
    def plugin(self):
        if self._plugin is None:
            self._plugin = manager.NeutronManager.get_plugin()
        return self._plugin

    @property
    def threadpool(self):
        if self._pool is None:
            self._pool = eventlet.GreenPool(2)
        return self._pool

    def _start_rpc_listeners(self):
        self.notifier = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self.ovsvapp_sg_server_rpc = (
            ovsvapp_rpc.OVSvAppSecurityGroupServerRpcMixin())
        self.endpoints = [ovsvapp_rpc.OVSvAppServerRpcCallback(
                          self.notifier, self.ovsvapp_sg_server_rpc),
                          ovsvapp_rpc.OVSvAppSecurityGroupServerRpcCallback(
                          self.ovsvapp_sg_server_rpc)]
        self.topic = ovsvapp_const.OVSVAPP
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def _start_ovsvapp_monitor(self):
        self.ovsvapp_monitor = ovsvapp_monitor.AgentMonitor()
        self.ovsvapp_monitor.initialize_thread(self.notifier)

    def _get_ovsvapp_agent_from_cluster(self, context, cluster_id):
        chosen_agent = None
        agents = self.plugin.get_agents(
            context,
            filters={'agent_type': [ovsvapp_const.AGENT_TYPE_OVSVAPP]})
        chosen_agent = agents[0]
        recent_time = chosen_agent['heartbeat_timestamp']
        agents = agents[1:]
        for agent in agents:
            agent_cluster_id = agent['configurations'].get('cluster_id')
            if cluster_id != agent_cluster_id:
                continue
            delta = timeutils.delta_seconds(recent_time,
                                            agent['heartbeat_timestamp'])
            if delta > 0:
                recent_time = agent['heartbeat_timestamp']
                chosen_agent = agent
        return chosen_agent

    def _notify_agent(self, network_info):
        host = None
        cluster_id = network_info['cluster_id']
        if 'host' in network_info:
            host = network_info['host']
        else:
            agent = self._get_ovsvapp_agent_from_cluster(self.context,
                                                         cluster_id)
            LOG.debug("Agent chosen for notification: %s.", agent)
            if agent and 'host' in agent:
                host = agent['host']
            else:
                LOG.error(_LE("Failed to find OVSvApp Agent with host "
                              "%(host)s while releasing network allocations "
                              "for %(cluster)s in vCenter %(vcenter)s."),
                          {'host': host,
                           'vcenter': network_info['vcenter_id'],
                           'cluster': cluster_id})
                return
        try:
            LOG.info(_LI("Initiating device_delete RPC for network "
                         "%(network)s to OVSvApp agent on host %(host)s."),
                     {'host': host, 'network': network_info})
            self.notifier.device_delete(self.context, network_info, host,
                                        cluster_id)
        except Exception:
            LOG.exception(_LE("Failed to notify agent to delete port group."))

    def _check_and_fire_provider_update(self, port):
        if port['device_owner'] == common_const.DEVICE_OWNER_DHCP:
            self.notifier.enhanced_sg_provider_updated(self.context,
                                                       port['network_id'])
        # For IPv6, provider rule need to be updated in case router
        # interface is created or updated after VM port is created.
        elif port['device_owner'] == common_const.DEVICE_OWNER_ROUTER_INTF:
            if any(netaddr.IPAddress(fixed_ip['ip_address']).version == 6
                   for fixed_ip in port['fixed_ips']):
                self.notifier.enhanced_sg_provider_updated(self.context,
                                                           port['network_id'])

    def create_port_postcommit(self, context):
        port = context.current
        self._check_and_fire_provider_update(port)

    def update_port_postcommit(self, context):
        pass

    def delete_port_postcommit(self, context):
        """Delete port non-database commit event."""
        port = context.current
        if port and port['device_owner'].startswith('compute'):
            segment = context.top_bound_segment
            if (segment and
                    segment[api.NETWORK_TYPE] in self.supported_network_types):
                LOG.debug("OVSvApp Mech driver - delete_port_postcommit for "
                          "port: %s with network_type as %s.",
                          port['id'], segment[api.NETWORK_TYPE])
                vni = segment[api.SEGMENTATION_ID]
                network_type = segment[api.NETWORK_TYPE]
                host = port[portbindings.HOST_ID]
                agent = None
                vcenter = None
                cluster = None
                net_info = None
                agents = self.plugin.get_agents(
                    self.context,
                    filters={'agent_type': [ovsvapp_const.AGENT_TYPE_OVSVAPP],
                             'host': [host]})
                if agents:
                    agent = agents[0]
                    vcenter = agent['configurations']['vcenter_id']
                    cluster = agent['configurations']['cluster_id']
                    net_info = {'vcenter_id': vcenter,
                                'cluster_id': cluster,
                                'network_id': port['network_id'],
                                'segmentation_id': vni,
                                'network_type': network_type,
                                'host': host}
                else:
                    LOG.debug("Not a valid ESX port: %s.", port['id'])
                    return
                try:
                    lvid = ovsvapp_db.check_to_reclaim_local_vlan(net_info)
                    if lvid >= 1:
                        net_info.update({'lvid': lvid})
                        LOG.debug("Spawning thread for releasing network "
                                  "VNI allocations for %s.", net_info)
                        self.threadpool.spawn_n(self._notify_agent, net_info)
                        LOG.info(_LI("Spawned a thread for releasing network "
                                     "vni allocations for network: %s."),
                                 net_info)
                except Exception:
                    LOG.exception(_LE("Failed to check for reclaiming "
                                      "local vlan."))
        else:
            self._check_and_fire_provider_update(port)

    def delete_network_postcommit(self, context):
        network = context.current
        segments = context.network_segments
        vxlan_segments = []
        if segments:
            for segment in segments:
                if segment[api.NETWORK_TYPE] in self.supported_network_types:
                    vxlan_segments.append(segment)
        if not vxlan_segments:
            return
        try:
            stale_entries = ovsvapp_db.get_stale_local_vlans_for_network(
                network['id'])
            if stale_entries:
                for (vcenter, cluster, lvid) in stale_entries:
                    network_info = {'vcenter_id': vcenter,
                                    'cluster_id': cluster,
                                    'lvid': lvid,
                                    'network_id': network['id']}
                    if len(vxlan_segments) == 1:
                        seg_id = vxlan_segments[0][api.SEGMENTATION_ID]
                        net_type = vxlan_segments[0][api.NETWORK_TYPE]
                        network_info.update({'segmentation_id': seg_id,
                                             'network_type': net_type})
                    LOG.debug("Spawning thread for releasing network "
                              "VNI allocations for %s.", network_info)
                    self.threadpool.spawn_n(self._notify_agent, network_info)
                    LOG.info(_LI("Spawned a thread for releasing network "
                                 "vni allocations for network: %s."),
                             network_info)
        except Exception:
            LOG.exception(_LE("Failed checking stale local vlan allocations."))
