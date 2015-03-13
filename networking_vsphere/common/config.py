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

# vCenter server and ESX host related config read from ovsvapp_agent.ini.
VMWARE_OPTS = [
    cfg.StrOpt('vcenter_ip',
               default=None,
               help='vCenter server IP'),
    cfg.StrOpt('vcenter_username',
               default=None,
               help='vCenter server user name'),
    cfg.StrOpt('vcenter_password',
               default=None,
               help='vCenter server password'),
    cfg.BoolOpt('cert_check',
                default=False,
                help='Enable SSL certificate check for vCenter'),
    cfg.StrOpt('cert_path',
               default='/etc/ssl/certs/certs.pem',
               help='Certificate chain path containing cacert of vCenters'),
    cfg.IntOpt('https_port',
               default=443,
               help='Customized https_port for vCenter communication'),
    cfg.StrOpt('wsdl_location',
               default=None,
               help='vCenter server wsdl location'),
    cfg.StrOpt('vcenter_api_retry_count',
               default=5,
               help='Number of retries while connecting to vcenter server'),
    cfg.StrOpt('esx_hostname',
               default=None,
               help='ESX host name where this OVSvApp is hosted'),
    cfg.BoolOpt('esx_maintenance_mode',
                default=True,
                help='Set host into maintenance mode'),
    cfg.MultiStrOpt('cluster_dvs_mapping',
                    default=[],
                    help='vCenter cluster to DVS mapping')
]

# OVSvApp Agent related config read from ovsvapp_agent.ini and neutron.conf.
OVSVAPP_OPTS = [
    cfg.StrOpt('tenant_network_type',
               default='vlan',
               help='Network type for tenant networks - vlan'),
    cfg.StrOpt('integration_bridge',
               default="br-int",
               help='Integration Bridge'),
    cfg.ListOpt('bridge_mappings',
                default=[],
                help='Bridge mappings'),
    cfg.StrOpt('agent_driver',
               default='networking_vsphere.agent.ovsvapp_agent'
                       '.OVSvAppL2Agent',
               help='OVSvApp Agent implementation'),
    cfg.StrOpt('network_manager',
               default='networking_vsphere.drivers.manager.'
                       'VcenterManager',
               help='Driver Manager implementation for '
                    'NetworkDriver'),
    cfg.IntOpt('report_interval',
               default=4,
               help='Seconds between nodes reporting state to server'),
    cfg.IntOpt('polling_interval',
               default=2,
               help='The number of seconds the agent will wait between '
                    'polling for local device changes'),
    cfg.IntOpt('veth_mtu',
               default=1500,
               help='MTU size of veth interfaces'),
    cfg.BoolOpt('agent_maintenance',
                default=False,
                help='Turn on this flag during agent updates to help '
                     'prevent datapath outage')
]

# OVSvApp Security Group related config read from ovsvapp_agent.ini.
SECURITYGROUP_OPTS = [
    cfg.StrOpt('security_bridge_mapping',
               default='br-sec',
               help='<security_bridge>:<phy_interface>'),
    cfg.BoolOpt('defer_apply',
                default=True,
                help='Enable defer_apply on security bridge'),
    cfg.StrOpt('ovsvapp_firewall_driver',
               default='networking_vsphere.drivers.ovs_firewall.'
                       'OVSFirewallDriver',
               help='DriverManager implementation for '
                    'OVS based Firewall')
]


def register_options():
    cfg.CONF.register_opts(VMWARE_OPTS, "VMWARE")
    cfg.CONF.register_opts(OVSVAPP_OPTS, "OVSVAPP")
    cfg.CONF.register_opts(SECURITYGROUP_OPTS, "SECURITYGROUP")