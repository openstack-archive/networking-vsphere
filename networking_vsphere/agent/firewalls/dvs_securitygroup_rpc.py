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
from oslo_log import log as logging

from neutron.agent import securitygroups_rpc
from neutron.i18n import _LI

LOG = logging.getLogger(__name__)


class DVSSecurityGroupRpc(securitygroups_rpc.SecurityGroupAgentRpc):

    @property
    def use_enhanced_rpc(self):
        if self._use_enhanced_rpc is None:
            self._use_enhanced_rpc = False
        return self._use_enhanced_rpc

    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Preparing filters for devices %s"), device_ids)

        devices = self.plugin_rpc.security_group_rules_for_devices(
            self.context, list(device_ids))

        self.firewall.prepare_port_filter(devices.values())

    def remove_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Remove device filter for %r"), device_ids)
        self.firewall.remove_port_filter(device_ids)

    def refresh_firewall(self, device_ids=None):
        LOG.info(_LI("Refresh firewall rules"))
        if not device_ids:
            device_ids = self.firewall.ports.keys()
            if not device_ids:
                LOG.info(_LI("No ports here to refresh firewall"))
                return
        devices = self.plugin_rpc.security_group_rules_for_devices(
            self.context, device_ids)

        self.firewall.update_port_filter(devices.values())
