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
#    under the License.from oslo.config import cfg.

import eventlet
eventlet.monkey_patch()
from oslo_config import cfg
from oslo_log import log
from oslo_service import loopingcall
from oslo_utils import timeutils

import random
import requests

from neutron import context as neutron_context
from neutron.db import agents_db
from neutron.db import common_db_mixin
from neutron import manager

from networking_vsphere._i18n import _, _LE, _LI, _LW
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.db import ovsvapp_db

LOG = log.getLogger(__name__)

DEFAULT_MONITOR_INTERVAL = 10

# OVSvApp Fault Management config read from neutron.conf.
OVSVAPP_MONITOR_OPTS = [
    cfg.BoolOpt('enable_ovsvapp_monitor', default=False,
                help=_('To monitor the OVSvApp Agents.'))
]

cfg.CONF.register_opts(OVSVAPP_MONITOR_OPTS, "OVSVAPP")


class AgentMonitor(agents_db.AgentDbMixin, common_db_mixin.CommonDbMixin):
    """OVSvApp agent monitor class.

    Represents agent_monitor class which maintains active and inactive
    agents and reschedules its resources.
    """
    active_agents = []
    inactive_agents = []
    agents = {}
    context = None
    notifier = None
    plugin = None
    agent_ext_support = None
    _pool = None

    @property
    def threadpool(self):
        if self._pool is None:
            self._pool = eventlet.GreenPool(2)
        return self._pool

    def initialize_thread(self, notifier):
        """Initialization of agent monitor thread."""
        try:
            self.notifier = notifier
            monitor_interval = DEFAULT_MONITOR_INTERVAL
            api_worker_count = cfg.CONF.api_workers
            if api_worker_count and api_worker_count > 4:
                monitor_interval = 4 * api_worker_count
            monitor_thread = loopingcall.FixedIntervalLoopingCall(
                self.monitor_agent_state)
            monitor_thread.start(interval=monitor_interval)
            LOG.debug("Successfully initialized agent monitor "
                      "thread with loop interval: %s.", monitor_interval)
        except Exception:
            LOG.exception(_LE("Cannot initialize agent monitor thread.."))

    def _update_agent_admin_state(self, context, id, agt):
        agent_data = agt['agent']
        with context.session.begin(subtransactions=True):
            agent = self._get_agent(context, id)
            if agent['admin_state_up'] != agent_data['admin_state_up']:
                agent.update(agent_data)
                return True
        return False

    def update_agent_state(self, agent_id, status):
        agent_state = {'agent': {'admin_state_up': status}}
        return self._update_agent_admin_state(self.context,
                                              agent_id,
                                              agent_state)

    def _get_eligible_ovsvapp_agent(self, cluster_id, vcenter_id):
        cluster_agents = []
        agents = self.plugin.get_agents(
            self.context,
            filters={'agent_type': [ovsvapp_const.AGENT_TYPE_OVSVAPP]})
        for agent in agents:
            agent_cluster_id = agent['configurations'].get('cluster_id')
            agent_vcenter_id = agent['configurations'].get('vcenter_id')
            if (cluster_id != agent_cluster_id) or (
                vcenter_id != agent_vcenter_id):
                continue
            cluster_agents.append(agent)
        if not cluster_agents:
            return
        _agent = random.choice(cluster_agents)
        recent_time = _agent['heartbeat_timestamp']
        if not timeutils.is_older_than(recent_time,
                                       cfg.CONF.agent_down_time):
            return _agent
        cluster_agents.remove(_agent)
        for agent in cluster_agents:
            delta = timeutils.delta_seconds(recent_time,
                                            agent['heartbeat_timestamp'])
            if delta > 0:
                if not timeutils.is_older_than(agent['heartbeat_timestamp'],
                                               cfg.CONF.agent_down_time):
                    return agent

    def process_ovsvapp_agent(self, agent):
        """Inform the OVSvApp agent.

        To set the other host into maintenance or shutdown mode.
        """
        try:
            LOG.info(_LI("Processing the OVSvApp agent to set the other host "
                         "into maintenance or shutdown mode %s."), agent)
            device_data = {}
            agent_config = agent['configurations']
            source_host = agent_config.get('esx_host_name')
            chosen_agent = self._get_eligible_ovsvapp_agent(
                agent_config['cluster_id'], agent_config['vcenter_id'])
            if chosen_agent and (chosen_agent['id'] in self.active_agents):
                cluster_id = chosen_agent['configurations'].get('cluster_id')
                device_data['assigned_agent_host'] = chosen_agent['host']
                device_data['esx_host_name'] = source_host
                device_data['ovsvapp_agent'] = '-'.join(
                    ['ovsvapp', source_host.replace('.', '-')])
                LOG.info(_LI("Invoking device_update RPC with"
                             "target host %s."),
                         chosen_agent['host'])
                self.notifier.device_update(self.context,
                                            device_data, cluster_id)
            else:
                ovsvapp_db.set_cluster_threshold(agent_config['vcenter_id'],
                                                 agent_config['cluster_id'])
                LOG.info(_LI("No eligible OVSvApp agents found for "
                             "processing. Reverting DB status for the agent."))
                self.update_agent_state(agent['id'], True)
        except Exception:
            agent_config = agent['configurations']
            ovsvapp_db.set_cluster_threshold(agent_config['vcenter_id'],
                                             agent_config['cluster_id'])
            LOG.exception(_LE("Unable to inform the OVSvApp agent for "
                              "Host - maintenance or shutdown operation."))

    def _check_datapath_health(self, monitoring_ip):
        if monitoring_ip:
            url = 'http://%s:8080/status.json' % monitoring_ip
            try:
                response = requests.get(url, timeout=5)
                if response:
                    LOG.debug("HTTP response from OVSvApp agent@ %(ip)s is "
                              "%(res)s", {'res': response,
                                          'ip': monitoring_ip})
                    status = response.json()
                    LOG.info(_LI("ovs status is %(st)s from agent@ %(ip)s")
                             % {'st': status, 'ip': monitoring_ip})
                    return (status.get('ovs') == "OK")
            except Exception:
                LOG.exception(_LE("Failed to get OVS status. Will continue "
                                  "with mitigation."))
                return False

    def check_ovsvapp_data_path(self, agent):
        agent_config = agent['configurations']
        # Check if the Data path is alright.
        monitoring_ip = agent_config.get('monitoring_ip')
        datapath_health = self._check_datapath_health(monitoring_ip)
        if datapath_health:
            LOG.info(_LI("Data path looks to be OK on %s. "
                         "Skipping mitigation."), agent['host'])
            LOG.warning(_LW("Issues encountered in receiving "
                            "heartbeats from OVSvApp Agent on "
                            "host %s."), agent['host'])
        else:
            LOG.warning(_LW("Data path seems to be broken already on %s."
                            "Will continue with mitigation."), agent['host'])
        return datapath_health

    def _check_plugin_ext_support(self, extension):
        """Helper Method.

        To check if plugin supports Agent Management Extension.
        """
        try:
            if self.plugin:
                return extension in self.plugin.supported_extension_aliases
        except Exception:
            LOG.exception(_LE("%s extension is not supported."), extension)
        return False

    def get_plugin_and_initialize(self):
        """Initializes plugin and populates list of all agents."""
        try:
            self.context = neutron_context.get_admin_context()
            self.plugin = manager.NeutronManager.get_plugin()
            if not self.plugin:
                return False
            self.agent_ext_support = self._check_plugin_ext_support('agent')
        except Exception:
            LOG.warning(_LW("Failed initialization of agent monitor.."))
            return False
        return True

    def monitor_agent_state(self):
        """Thread to monitor agent state.

        Represents a thread which maintains list of active
        and inactive agents based on the heartbeat recorded.
        """
        # Do nothing until plugin is initialized.
        if not self.plugin:
            status = self.get_plugin_and_initialize()
            if not status:
                LOG.warning(_LW("Plugin not defined...returning!"))
                return
        if not self.agent_ext_support:
            LOG.warning(_LW("Agent extension is not loaded by plugin."))
            return
        try:
            self.agents = self.plugin.get_agents(
                self.context,
                filters={'agent_type': [ovsvapp_const.AGENT_TYPE_OVSVAPP]})
        except Exception:
            LOG.exception(_LE("Unable to get agent list."))
            return
        for agent in self.agents:
            agent_time_stamp = agent['heartbeat_timestamp']
            agent_id = agent['id']
            status = timeutils.is_older_than(agent_time_stamp,
                                             cfg.CONF.agent_down_time * 2)
            LOG.debug("For ovsvapp_agent %(agent)s agent_state %(state)s.",
                      {'agent': agent, 'state': status})
            try:
                agent_config = agent['configurations']
                if not status:
                    if agent_id not in self.active_agents:
                        self.active_agents.append(agent_id)
                        self.update_agent_state(agent_id, True)
                    if agent_id in self.inactive_agents:
                        LOG.info(_LI("Removing agent: %s from inactive "
                                     "agent list."), agent_id)
                        self.inactive_agents.remove(agent_id)
                        ovsvapp_db.reset_cluster_threshold(
                            agent_config['vcenter_id'],
                            agent_config['cluster_id']
                        )
                else:
                    if not agent['admin_state_up']:
                        # This agent is already handled in earlier run or by
                        # another Neutron server. Just update the cache and
                        # proceed further.
                        if agent_id not in self.inactive_agents:
                            LOG.info(_LI("Moving agent: %s from active to "
                                         "inactive."), agent_id)
                            self.inactive_agents.append(agent_id)
                        if agent_id in self.active_agents:
                            self.active_agents.remove(agent_id)
                        continue
                    if self.update_agent_state(agent_id, False):
                        # Got the ownership for mitigating this agent.
                        if agent_id in self.active_agents:
                            self.active_agents.remove(agent_id)
                        if self.check_ovsvapp_data_path(agent):
                            continue
                        cluster_status = (
                            ovsvapp_db.update_and_get_cluster_lock(
                                agent_config['vcenter_id'],
                                agent_config['cluster_id']))
                        if cluster_status == ovsvapp_db.SUCCESS:
                            # Got the cluster lock for mitigating this agent.
                            self.threadpool.spawn_n(self.process_ovsvapp_agent,
                                                    agent)
                            LOG.info(_LI("Spawned a thread for processing "
                                         "OVSvApp Agent %s."), agent['id'])
                            if agent_id not in self.inactive_agents:
                                LOG.info(_LI("Moving agent: %s from active to "
                                             "inactive."), agent_id)
                                self.inactive_agents.append(agent_id)
                        elif cluster_status == ovsvapp_db.RETRY:
                            self.update_agent_state(agent['id'], True)
                            LOG.debug("Will retry the agent %s in the next "
                                      "iteration.", agent['id'])
                        elif cluster_status == ovsvapp_db.GIVE_UP:
                            self.update_agent_state(agent['id'], True)
                            LOG.debug("Threshold already reached. Will retry "
                                      "the agent %s in the next run",
                                      agent['id'])
            except Exception:
                LOG.exception(_LE("Exception occurred in"
                                  "monitor_agent_state."))
