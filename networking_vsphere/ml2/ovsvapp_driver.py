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
from oslo_log import log
from oslo_utils import timeutils

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as neutron_context
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api

from networking_vsphere.common import constants
from networking_vsphere.db import ovsvapp_db
from networking_vsphere.ml2 import ovsvapp_rpc

LOG = log.getLogger(__name__)


class OVSvAppAgentDriver(object):
    """OVSvApp Python Driver for Neutron.

    This code is the backend implementation for the OVSvApp ML2
    MechanismDriver for OpenStack Neutron.
    """

    def initialize(self):
        self.networks_to_release = []
        self.force_release_networks = []
        self.context = neutron_context.get_admin_context()
        self._start_rpc_listeners()
        self._plugin = None
        self._pool = None
        self._start_vni_allocation_release_thread()

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

    def _start_vni_allocation_release_thread(self):
        try:
            monitor_interval = 300
            release_thread = loopingcall.FixedIntervalLoopingCall(
                self.release_stale_network_allocations)
            release_thread.start(interval=monitor_interval)
            LOG.debug("Successfully initialized VNI allocation "
                      "release thread with loop interval %s.",
                      monitor_interval)
        except Exception:
            LOG.exception(_("Cannot initialize VNI allocation release "
                            "thread.."))

    def _start_rpc_listeners(self):
        self.notifier = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self.endpoints = [ovsvapp_rpc.OVSvAppServerRpcCallback(self.notifier)]
        self.topic = constants.OVSVAPP
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def _get_ovsvapp_agent_from_cluster(self, context, cluster_id):
        chosen_agent = None
        agents = self.plugin.get_agents(
            context,
            filters={'agent_type': [constants.AGENT_TYPE_OVSVAPP]})
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

    def _notify_agent_and_update_db(self, network_info):
        host = None
        skip_release = True
        if 'host' in network_info:
            host = network_info['host']
            status = True
        else:
            cluster = network_info['cluster_id']
            agent = self._get_ovsvapp_agent_from_cluster(self.context,
                                                         cluster)
            if agent and 'host' in agent:
                host = agent['host']
            else:
                LOG.error(_("Failed to find OVSvApp Agent with host "
                            "%(host)s while releasing network allocations "
                            "for %(cluster)s in vCenter %(vcenter)s."),
                          {'host': host,
                           'vcenter': network_info['vcenter_id'],
                           'cluster': cluster})
                return
            status = ovsvapp_db.check_to_reclaim_local_vlan(network_info,
                                                            False)
            skip_release = False
        success = False
        try:
            if status:
                success = self.notifier.device_delete(self.context,
                                                      network_info,
                                                      host)
            if (not skip_release) and success:
                ovsvapp_db.release_local_vlan(network_info)
        except Exception:
            LOG.exception(_("Failed to delete the port group/release "
                            "local vlan."))
            # Add the network back for processing??

    def _is_device_owner_compute(self, port):
        return port['device_owner'].startswith('compute')

    def release_stale_network_allocations(self):
        try:
            LOG.debug('Trying to delete the stale VNI allocations.')
            ovsvapp_db.release_stale_allocations()
        except Exception:
            LOG.exception(_('Exception occurred while deleting the '
                            'stale VNI allocations.'))

    def delete_port_postcommit(self, context):
        """Delete port non-database commit event."""
        port = context.current
        if port and port['device_owner'].startswith('compute'):
            segment = context.bound_segment
            if segment and segment[api.NETWORK_TYPE] == p_const.TYPE_VXLAN:
                host = port[portbindings.HOST_ID]
                vcenter = None
                cluster = None
                agents = self.plugin.get_agents(
                    self.context,
                    filters={'agent_type': [constants.AGENT_TYPE_OVSVAPP],
                             'host': [host]})
                agent = agents[0]
                vcenter = agent['configurations']['vcenter']
                cluster = agent['configurations']['cluster_id']
                net_info = {'vcenter_id': vcenter,
                            'cluster_id': cluster,
                            'network_id': port['network_id'],
                            'host': host}
                try:
                    status = ovsvapp_db.check_to_reclaim_local_vlan(net_info)
                    if status:
                        LOG.debug("Spawning thread for releasing network "
                                  "VNI allocations for %s.", net_info)
                        self.threadpool.spawn_n(
                            self._notify_agent_and_update_db, net_info)
                except Exception:
                    LOG.exception(_("Failed to check for reclaiming "
                                    "local vlan."))

    def delete_network_postcommit(self, context):
        try:
            network = context.current
            stale_entries = ovsvapp_db.get_stale_local_vlans_for_network(
                network['id'])
            if stale_entries:
                for (vcenter, cluster) in stale_entries:
                    network_info = {'vcenter_id': vcenter,
                                    'cluster_id': cluster,
                                    'network_id': network['id']}
                    LOG.debug("Spawning thread for releasing network "
                              "VNI allocations for %s.", network_info)
                    self.threadpool.spawn_n(self._notify_agent_and_update_db,
                                            network_info)
        except Exception:
            LOG.exception(_("Failed to check for stale "
                            "local vlan allocations."))
