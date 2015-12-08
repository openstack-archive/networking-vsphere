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

# vCenter related config information to login
VCENTER_OPTS = [
    cfg.StrOpt('vcenter_ip',
               help="The vCenter ip address "),
    cfg.StrOpt('trunk_dvswitch_name',
               help="The trunk dvswitch name "),
    cfg.StrOpt('vcenter_username',
               help="Username to login to vCenter "),
    cfg.StrOpt('vcenter_password',
               help="Password to login to vCenter ",
               secret=True),
    cfg.StrOpt('tenant_network_type',
               default="vlan",
               help="tenant network type is vlan or vxlan"),
    cfg.StrOpt('controller_ip',
               help="The controller ip under test"),
    cfg.StrOpt('cluster_in_use',
               help="The Cluster in use for the test"),
    cfg.StrOpt('vapp_username',
               help="Username to login to OVSvApp "),
    cfg.StrOpt('vapp_password',
               help="Password to login to OVSvApp",
               secret=True),
    cfg.StrOpt('bridge_interface_trunk',
               help="Bridge interface of trunk dvs"),
    cfg.StrOpt('neutron_database_name',
               help="Neutron database name as in mysql table")
]


def register_options():
    cfg.CONF.register_opts(VCENTER_OPTS, "VCENTER")
