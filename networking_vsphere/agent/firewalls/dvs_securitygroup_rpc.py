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
from threading import Timer
from oslo_log import log as logging

from networking_vsphere._i18n import _LI
from networking_vsphere.utils.rpc_translator import update_rules
from neutron.agent import securitygroups_rpc


LOG = logging.getLogger(__name__)


class DVSSecurityGroupRpc(securitygroups_rpc.SecurityGroupAgentRpc):

    def __init__(self, context, plugin_rpc,
                 defer_refresh_firewall=False):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self._devices_to_update = set()
        self.init_firewall(defer_refresh_firewall)

    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Preparing filters for devices %s"), device_ids)

        if self.use_enhanced_rpc:
            devices_info = self.plugin_rpc.security_group_info_for_devices(
                self.context, list(device_ids))
            devices = update_rules(devices_info)
        else:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, list(device_ids))
        self.firewall.prepare_port_filter(devices.values())

    def remove_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Remove device filter for %r"), device_ids)
        self.firewall.remove_port_filter(device_ids)

    def _refresh_ports(self):
        device_ids = self._devices_to_update
        self._devices_to_update = self._devices_to_update - device_ids
        if not device_ids:
            return
        if self.use_enhanced_rpc:
            devices_info = self.plugin_rpc.security_group_info_for_devices(
                self.context, device_ids)
            devices = update_rules(devices_info)
        else:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, device_ids)
        self.firewall.update_port_filter(devices.values())

    def refresh_firewall(self, device_ids=None):
        LOG.info(_LI("Refresh firewall rules"))
        self._devices_to_update |= device_ids
        if device_ids:
            Timer(2, self._refresh_ports).start()
