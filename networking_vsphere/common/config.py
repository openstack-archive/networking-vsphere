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

vmware_opts = [
    cfg.StrOpt('esx_hostname', default="default",
               help=_('ESX host name where this OVSvApp is hosted')),
]

cfg.CONF.register_opts(agent_opts, "OVSVAPPAGENT")
cfg.CONF.register_opts(vmware_opts, "VMWARE")


def parse(args):
    cfg.CONF(args=args, project='neutron',
             default_config_files=["/etc/neutron/plugins/ovsvapp/"
                                   "ovsvapp.ini"])


def remove_config_file(temp_dir):
    shutil.rmtree(temp_dir)
