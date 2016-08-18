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

from oslo_config import cfg

from networking_vsphere._i18n import _
from neutron.agent.common import config

DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_UPLINK_MAPPINGS = []
DEFAULT_VLAN_RANGES = []
DEFAULT_TUNNEL_RANGES = []
DEFAULT_TUNNEL_TYPES = []

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.IntOpt('quitting_rpc_timeout', default=10,
               help=_("Set new timeout in seconds for new rpc calls after "
                      "agent receives SIGTERM. If value is set to 0, rpc "
                      "timeout won't be changed")),
    cfg.BoolOpt('log_agent_heartbeats', default=False,
               help=_("Log agent heartbeats")),
    cfg.IntOpt('report_interval',
               default=30,
               help='Seconds between nodes reporting state to server.'),
]

vmware_opts = [
    cfg.FloatOpt(
        'task_poll_interval',
        default=2,
        help=_('The interval of task polling in seconds.')),
    cfg.IntOpt(
        'api_retry_count',
        default=10,
        help=_('number of times an API must be retried upon '
               'session/connection related errors')),
    cfg.IntOpt(
        'connections_pool_size',
        default=100,
        help=_('number of vsphere connections pool '
               'must be higher for intensive operations')),
    cfg.StrOpt('vsphere_login', default='administrator',
               help=_("Vsphere login.")),
    cfg.ListOpt('network_maps',
               default=DEFAULT_BRIDGE_MAPPINGS,
               help=_("List of <physical_network>:<bridge>.")),
    cfg.ListOpt('uplink_maps',
               default=DEFAULT_UPLINK_MAPPINGS,
               help=_("List of <physical_network>:<active uplinks>:"
                      "<failover uplinks>."
                      "Use semicolon between uplink names")),
    cfg.StrOpt('vsphere_hostname', default='vsphere',
               help=_("Vsphere host name or IP.")),
    cfg.StrOpt('vsphere_password', default='',
               help=_("Vsphere password.")),
    cfg.StrOpt('cluster_name',
               help=_("compute_cluster_name."))
]

dvs_opts = [
    cfg.BoolOpt('clean_on_restart',
                default=True,
                help=_("Run DVS cleaning procedure on agent restart.")),
    cfg.BoolOpt('precreate_networks',
                default=False,
                help=_("Precreate networks on DVS.")),
    cfg.IntOpt('init_pg_ports_count',
               default=4,
               help=_("Initial ports size for networks on DVS.")),
    cfg.FloatOpt('cache_pool_interval',
                 default=0.1,
                 help=_("The interval of task polling for "
                        "DVS cache in seconds.")),
    cfg.IntOpt('cache_free_ports_size',
               default=20,
               help=_("The number of free ports of network to store in "
                      "DVS cache."))
]

cfg.CONF.register_opts(dvs_opts, "DVS")

cfg.CONF.register_opts(agent_opts, "DVS_AGENT")
cfg.CONF.register_opts(vmware_opts, "ML2_VMWARE")
config.register_agent_state_opts_helper(cfg.CONF)
CONF = cfg.CONF
