# Copyright 2015 Mirantis, Inc.
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

import itertools
import signal
import sys
import time

from neutron.agent.common import polling
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import constants as n_const
from neutron.common import topics
from neutron.common import utils
from neutron import context
from neutron.plugins.common import constants
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall

from networking_vsphere._i18n import _, _LE, _LI
from networking_vsphere.agent.firewalls import dvs_securitygroup_rpc as dvs_rpc
from networking_vsphere.common import constants as dvs_const
from networking_vsphere.common import dvs_agent_rpc_api
from networking_vsphere.common import exceptions
from networking_vsphere.utils import dvs_util

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('DVS_AGENT',
                      'networking_vsphere.common.vmware_conf')


class DVSPluginApi(agent_rpc.PluginApi):
    pass


class DVSAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
               dvs_agent_rpc_api.ExtendAPI):

    target = oslo_messaging.Target(version='1.2')

    def __init__(self, vsphere_hostname, vsphere_login, vsphere_password,
                 bridge_mappings, polling_interval, quitting_rpc_timeout=None):
        super(DVSAgent, self).__init__()

        self.agent_state = {
            'binary': 'neutron-dvs-agent',
            'host': cfg.CONF.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'vsphere_hostname': vsphere_hostname,
                               'log_agent_heartbeats':
                                   cfg.CONF.DVS_AGENT.log_agent_heartbeats},
            'agent_type': 'DVS agent',
            'start_flag': True}

        self.setup_rpc()
        report_interval = cfg.CONF.DVS_AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

        self.polling_interval = polling_interval
        # Security group agent support
        self.sg_agent = dvs_rpc.DVSSecurityGroupRpc(
            self.context, self.sg_plugin_rpc, defer_refresh_firewall=True)
        self.run_daemon_loop = True
        self.iter_num = 0
        self.fullsync = True
        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

        self.quitting_rpc_timeout = quitting_rpc_timeout
        self.network_map = dvs_util.create_network_map_from_config(
            cfg.CONF.ML2_VMWARE)
        self.updated_ports = set()
        self.deleted_ports = set()
        self.known_ports = set()
        self.added_ports = set()
        self.booked_ports = set()

    @dvs_util.wrap_retry
    def create_network_precommit(self, current, segment):
        try:
            dvs = self._lookup_dvs_for_context(segment)
        except (exceptions.NoDVSForPhysicalNetwork,
                exceptions.NotSupportedNetworkType) as e:
            LOG.info(_LI('Network %(id)s not created. Reason: %(reason)s') % {
                'id': current['id'],
                'reason': e.message})
        except exceptions.InvalidNetwork:
            pass
        else:
            dvs.create_network(current, segment)

    @dvs_util.wrap_retry
    def delete_network_postcommit(self, current, segment):
        try:
            dvs = self._lookup_dvs_for_context(segment)
        except (exceptions.NoDVSForPhysicalNetwork,
                exceptions.NotSupportedNetworkType) as e:
            LOG.info(_LI('Network %(id)s not deleted. Reason: %(reason)s') % {
                'id': current['id'],
                'reason': e.message})
        except exceptions.InvalidNetwork:
            pass
        else:
            dvs.delete_network(current)

    @dvs_util.wrap_retry
    def update_network_precommit(self, current, segment, original):
        try:
            dvs = self._lookup_dvs_for_context(segment)
        except (exceptions.NoDVSForPhysicalNetwork,
                exceptions.NotSupportedNetworkType) as e:
            LOG.info(_LI('Network %(id)s not updated. Reason: %(reason)s') % {
                'id': current['id'],
                'reason': e.message})
        except exceptions.InvalidNetwork:
            pass
        else:
            dvs.update_network(current, original)

    @dvs_util.wrap_retry
    def book_port(self, current, network_segments, network_current):
        physnet = network_current['provider:physical_network']
        dvs = None
        dvs_segment = None
        for segment in network_segments:
            if segment['physical_network'] == physnet:
                dvs = self._lookup_dvs_for_context(segment)
                dvs_segment = segment
        if dvs:
            port = dvs.book_port(network_current, current['id'], dvs_segment)
            self.booked_ports.add(current['id'])
            return port
        return None

    @dvs_util.wrap_retry
    def update_port_postcommit(self, current, original, segment):
        try:
            dvs = self._lookup_dvs_for_context(segment)
            if current['id'] in self.booked_ports:
                self.added_ports.add(current['id'])
                self.booked_ports.discard(current['id'])
        except exceptions.NotSupportedNetworkType as e:
            LOG.info(_LI('Port %(id)s not updated. Reason: %(reason)s') % {
                'id': current['id'],
                'reason': e.message})
        except exceptions.NoDVSForPhysicalNetwork:
            raise exceptions.InvalidSystemState(details=_(
                'Port %(port_id)s belong to VMWare VM, but there is '
                'no mapping from network to DVS.') % {'port_id': current['id']}
            )
        else:
            self._update_admin_state_up(dvs, original, current)
            # TODO(SlOPS): update security groups on girect call

    @dvs_util.wrap_retry
    def delete_port_postcommit(self, current, original, segment):
        try:
            dvs = self._lookup_dvs_for_context(segment)
        except exceptions.NotSupportedNetworkType as e:
            LOG.info(_LI('Port %(id)s not deleted. Reason: %(reason)s') % {
                'id': current['id'],
                'reason': e.message})
        except exceptions.NoDVSForPhysicalNetwork:
            raise exceptions.InvalidSystemState(details=_(
                'Port %(port_id)s belong to VMWare VM, but there is '
                'no mapping from network to DVS.') % {'port_id': current['id']}
            )
        else:
            # TODO(SlOPS): update security groups on girect call
            dvs.release_port(current)

    def _lookup_dvs_for_context(self, segment):
        if segment['network_type'] == constants.TYPE_VLAN:
            physical_network = segment['physical_network']
            try:
                return self.network_map[physical_network]
            except KeyError:
                LOG.debug('No dvs mapped for physical '
                          'network: %s' % physical_network)
                raise exceptions.NoDVSForPhysicalNetwork(
                    physical_network=physical_network)
        else:
            raise exceptions.NotSupportedNetworkType(
                network_type=segment['network_type'])

    def _update_admin_state_up(self, dvs, original, current):
        try:
            original_admin_state_up = original['admin_state_up']
        except KeyError:
            pass
        else:
            current_admin_state_up = current['admin_state_up']
            perform = current_admin_state_up != original_admin_state_up
            if perform:
                dvs.switch_port_blocked_state(current)

    def _report_state(self):
        try:
            agent_status = self.state_rpc.report_state(self.context,
                                                       self.agent_state,
                                                       True)
            if agent_status == n_const.AGENT_REVIVED:
                LOG.info(_LI('Agent has just revived. Do a full sync.'))
                self.fullsync = True
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def setup_rpc(self):
        self.agent_id = 'dvs-agent-%s' % cfg.CONF.host
        self.topic = topics.AGENT
        self.plugin_rpc = DVSPluginApi(topics.PLUGIN)
        # self.agentside_rpc = ServerAPI()
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [dvs_const.DVS, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False

    @dvs_util.wrap_retry
    def _clean_up_vsphere_extra_ports(self, connected_ports):
        LOG.debug("Cleanup vsphere extra ports...")
        vsphere_not_connected_ports_maps = {}
        for phys_net, dvs in self.network_map.items():
            all_dvs_ports = set([p.config.name for p in dvs.get_ports(False)])
            not_connected_dvs_ports = all_dvs_ports - connected_ports
            vsphere_not_connected_ports_maps.update(
                {port_id: phys_net for port_id in not_connected_dvs_ports})

        if not vsphere_not_connected_ports_maps:
            return

        devices_details_list = (
            self.plugin_rpc.get_devices_details_list_and_failed_devices(
                self.context,
                vsphere_not_connected_ports_maps.keys(),
                self.agent_id,
                cfg.CONF.host))
        neutron_ports = set([
            p['port_id'] for p in itertools.chain(
                devices_details_list['devices'],
                devices_details_list['failed_devices']) if p.get('port_id')
        ])

        for port_id, phys_net in vsphere_not_connected_ports_maps.items():
            if port_id not in neutron_ports:
                dvs = self.network_map[phys_net]
                dvs.release_port({'id': port_id})

    def daemon_loop(self):
        with polling.get_polling_manager() as pm:
            self.rpc_loop(polling_manager=pm)

    def rpc_loop(self, polling_manager=None):
        if not polling_manager:
            polling_manager = polling.get_polling_manager(
                minimize_polling=False)
        while self.run_daemon_loop:
            start = time.time()
            port_stats = {'regular': {'added': 0,
                                      'updated': 0,
                                      'removed': 0}}
            if self.fullsync:
                LOG.info(_LI("Agent out of sync with plugin!"))
                connected_ports = self._get_dvs_ports()
                self.added_ports = connected_ports - self.known_ports
                self._clean_up_vsphere_extra_ports(connected_ports)
                self.fullsync = False
                polling_manager.force_polling()
            if self._agent_has_updates(polling_manager):
                LOG.debug("Agent rpc_loop - update")
                self.process_ports()
                port_stats['regular']['added'] = len(self.added_ports)
                port_stats['regular']['updated'] = len(self.updated_ports)
                port_stats['regular']['removed'] = len(self.deleted_ports)
                polling_manager.polling_completed()
            self.loop_count_and_wait(start)

    def _agent_has_updates(self, polling_manager):
        return (polling_manager.is_polling_required or
                self.sg_agent.firewall_refresh_needed() or
                self.updated_ports or self.deleted_ports)

    def loop_count_and_wait(self, start_time):
        # sleep till end of polling interval
        elapsed = time.time() - start_time
        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d "
                  "completed. Elapsed:%(elapsed).3f",
                  {'iter_num': self.iter_num,
                   'elapsed': elapsed})
        if elapsed < self.polling_interval:
            time.sleep(self.polling_interval - elapsed)
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
        self.iter_num = self.iter_num + 1

    def process_ports(self):
        LOG.debug("Process ports")
        if self.deleted_ports:
            deleted_ports = self.deleted_ports.copy()
            self.deleted_ports = self.deleted_ports - deleted_ports
            self.sg_agent.remove_devices_filter(deleted_ports)
        if self.added_ports:
            possible_ports = self.added_ports
            self.added_ports = set()
        else:
            possible_ports = set()
        self.sg_agent.setup_port_filters(possible_ports,
                                         self.updated_ports)
        self.known_ports |= possible_ports

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        self.updated_ports.add(port['id'])
        LOG.debug("port_update message processed for port %s", port['id'])

    def port_delete(self, context, **kwargs):
        port_id = kwargs.get('port_id')
        if port_id in self.known_ports:
            self.deleted_ports.add(port_id)
            self.known_ports.discard(port_id)
        if port_id in self.added_ports:
            self.added_ports.discard(port_id)
        LOG.debug("port_delete message processed for port %s", port_id)

    def _get_dvs_ports(self):
        ports = set()
        dvs_list = self.network_map.values()
        for dvs in dvs_list:
            LOG.debug("Take port ids for dvs %s", dvs)
            ports.update(dvs._get_ports_ids())
        return ports


def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = utils.parse_mappings(config.ML2_VMWARE.network_maps)
    except ValueError as e:
        raise ValueError(_("Parsing network_maps failed: %s.") % e)

    kwargs = dict(
        vsphere_hostname=config.ML2_VMWARE.vsphere_hostname,
        vsphere_login=config.ML2_VMWARE.vsphere_login,
        vsphere_password=config.ML2_VMWARE.vsphere_password,
        bridge_mappings=bridge_mappings,
        polling_interval=config.DVS_AGENT.polling_interval,
        quitting_rpc_timeout=config.DVS_AGENT.quitting_rpc_timeout,
    )
    return kwargs


def main():

    # cfg.CONF.register_opts(ip_lib.OPTS)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    utils.log_opt_values(LOG)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_LE('%s Agent terminated!'), e)
        sys.exit(1)

    try:
        agent = DVSAgent(**agent_config)
    except RuntimeError as e:
        LOG.error(_LE("%s Agent terminated!"), e)
        sys.exit(1)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()

if __name__ == "__main__":
    main()
