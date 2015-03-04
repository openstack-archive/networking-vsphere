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
#    under the License.

from oslo_config import cfg

# vCenter server and ESX host related config read from ovsvapp_agent.ini
VMWARE_OPTS = [
    cfg.StrOpt('vcenter_ip',
               help=_("vCenter server IP"),
               default=None),
    cfg.StrOpt('vcenter_username',
               help=_("vCenter server user name"),
               default=None),
    cfg.StrOpt('vcenter_password',
               help=_("vCenter server password"),
               default=None),
    cfg.BoolOpt('cert_check', default=False,
                help=_('Enable SSL certificate check for vCenter')),
    cfg.StrOpt('cert_path', default='/etc/ssl/certs/certs.pem',
               help=_('Certificate chain path containing cacert of vCenters')),
    cfg.IntOpt('https_port',
               help=_('Customized https_port for vCenter communication'),
               default=443),
    cfg.StrOpt('wsdl_location',
               help=_("vCenter server wsdl location"),
               default=None),
    cfg.StrOpt('vcenter_api_retry_count',
               help=_("Number of retries while connecting to vcenter server"),
               default=5),
    cfg.StrOpt('esx_hostname', default="default",
               help=_('ESX host name where this OVSvApp is hosted')),
    cfg.BoolOpt('esx_maintenance_mode', default=True,
                help=_('Set host into maintenance mode')),
    cfg.MultiStrOpt('cluster_dvs_mapping',
                    help=_("vCenter cluster to DVS mapping"),
                    default=[])
]

# OVSvApp Agent related config read from ovsvapp_agent.ini and neutron.conf
OVSVAPP_OPTS = [
    cfg.StrOpt('tenant_network_type', default='vlan',
               help=_('Network type for tenant networks - vlan')),
    cfg.StrOpt('integration_bridge', default="br-int",
               help=_('Integration Bridge')),
    cfg.ListOpt('bridge_mappings', default=[],
                help=_('Bridge mappings')),
    cfg.StrOpt('agent_driver',
               help=_("OVSvApp Agent implementation"),
               default=_("networking_vsphere.agent.ovsvapp_agent"
                         ".OVSvAppL2Agent")),
    cfg.StrOpt('network_manager',
               help=_("DriverManager implementation for "
                      "NetworkDriver"),
               default=_("networking_vsphere.drivers.manager."
                         "VcenterManager")),
    cfg.IntOpt('report_interval', default=4,
               help=_('Seconds between nodes reporting state to server')),
    cfg.IntOpt('polling_interval', default=2,
               help=_('The number of seconds the agent will wait between '
                      'polling for local device changes')),
    cfg.IntOpt('veth_mtu', default=1500,
               help=_('MTU size of veth interfaces')),
    cfg.BoolOpt('agent_maintenance', default=False,
                help=_('Turn on this flag during agent updates to help '
                       'prevent datapath outage'))
]

# OVSvApp Security Group related config read from ovsvapp_agent.ini
SECURITYGROUP_OPTS = [
    cfg.StrOpt('security_bridge_mapping',
               default='br-sec',
               help=_("<security_bridge>:<phy_interface>")),
    cfg.BoolOpt('defer_apply',
                default=True,
                help=_('Enable defer_apply on security bridge')),
    cfg.StrOpt('ovsvapp_firewall_driver',
               help=_("DriverManager implementation for "
                      "OVS based Firewall"),
               default=_("networking_sphere.drivers.ovs_firewall."
                         "OVSFirewallDriver"))
]


def register_options():
    cfg.CONF.register_opts(VMWARE_OPTS, "VMWARE")
    cfg.CONF.register_opts(OVSVAPP_OPTS, "OVSVAPP")
    cfg.CONF.register_opts(SECURITYGROUP_OPTS, "SECURITYGROUP")