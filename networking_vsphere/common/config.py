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

import shutil

from oslo.config import cfg

from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const


LOG = logging.getLogger(__name__)

agent_opts = [
    cfg.StrOpt('agent_driver',
               help=_("OVSvApp Agent implementation"),
               default=_("networking_vsphere.agent.ovsvapp_agent"
                         ".OVSvAppL2Agent")),
    cfg.StrOpt('network_manager',
               help=_("DriverManager implementation for "
                      "NetworkDriver"),
               default=_("networking_vsphere.drivers.manager."
                         "VcenterManager")),
    cfg.StrOpt('firewall_driver',
               help=_("DriverManager implementation for "
                      "OVS based Firewall"),
               default=_("networking_sphere.drivers.ovs_firewall."
                         "OVSFirewallDriver"))
]

DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_TUNNEL_TYPES = []

OVSVAPP_OPTS = [
    cfg.StrOpt('tenant_network_type', default='vlan',
               help=_('Network type for tenant networks - vlan, vxlan')),
    cfg.StrOpt('integration_bridge', default="default",
               help=_('Integration Bridge')),
    cfg.ListOpt('bridge_mappings', default=DEFAULT_BRIDGE_MAPPINGS,
                help=_('Bridge mappings')),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_('Tunnel Bridge')),
    cfg.StrOpt('local_ip', default='',
               help=_('Local IP address of VXLAN tunnel endpoints')),
]

OVSVAPPAGENT_OPTS = [
    cfg.IntOpt('report_interval', default=4,
               help=_('Seconds between nodes reporting state to server')),
    cfg.IntOpt('polling_interval', default=2,
               help=_('The number of seconds the agent will wait between '
                      'polling for local device changes')),
    cfg.IntOpt('veth_mtu', default=1500,
               help=_('MTU size of veth interfaces')),
    cfg.ListOpt('tunnel_types', default=DEFAULT_TUNNEL_TYPES,
                help=_("Network types supported by the agent - vxlan")),
    cfg.IntOpt('vxlan_udp_port', default=p_const.VXLAN_UDP_PORT,
               help=_("The UDP port to use for VXLAN tunnels.")),
    cfg.IntOpt('dont_fragment', default=True,
               help=_("Dont fragment")),
    cfg.BoolOpt('agent_maintenance', default=False,
                help=_('Turn on this flag during agent updates to help '
                       'prevent datapath outage')),
]

VMWARE_OPTS = [
    cfg.StrOpt('esx_hostname', default="default",
               help=_('ESX host name where this OVSvApp is hosted')),
    cfg.BoolOpt('esx_maintenance_mode', default=True,
                help=_('Set host into maintenance mode')),
    cfg.BoolOpt('cert_check', default=False,
                help=_('Enable SSL certificate check for vCenter')),
    cfg.StrOpt('cert_path', default='/etc/ssl/certs/certs.pem',
               help=_('Certificate chain path containing cacert of vCenters')),
]

SECURITYGROUP_OPTS = [
    cfg.StrOpt('security_bridge',
               default=None,
               help=_("<security_bridge>:<phy_interface>")),
    cfg.BoolOpt('defer_apply',
                default=True,
                help=_('Enable defer_apply on security bridge')),
]

cfg.CONF.register_opts(agent_opts, "OVSVAPPAGENT")
cfg.CONF.register_opts(OVSVAPP_OPTS, "OVSVAPP")
cfg.CONF.register_opts(OVSVAPPAGENT_OPTS, "OVSVAPPAGENT")
cfg.CONF.register_opts(VMWARE_OPTS, "VMWARE")
cfg.CONF.register_opts(SECURITYGROUP_OPTS, "SECURITYGROUP")
CONF = cfg.CONF


def parse(args):
    cfg.CONF(args=args, project='neutron',
             default_config_files=["/etc/neutron/plugins/ovsvapp/"
                                   "ovsvapp.ini"])


def remove_config_file(temp_dir):
    shutil.rmtree(temp_dir)
