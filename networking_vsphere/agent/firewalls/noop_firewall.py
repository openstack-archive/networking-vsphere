# Copyright 2012, Nachi Ueno, NTT MCL, Inc., 2016 Mirantis, Inc.
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

from networking_vsphere._i18n import _LI
from neutron.agent import firewall
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NoopvCenterFirewallDriver(firewall.FirewallDriver):

    def prepare_port_filter(self, port):
        LOG.debug("prepare_port_filter called")

    def apply_port_filter(self, port):
        LOG.debug("apply_port_filter called")

    def update_port_filter(self, port):
        LOG.debug("update_port_filter called")

    def remove_port_filter(self, port):
        LOG.debug("remove_port_filter called")

    def filter_defer_apply_on(self):
        LOG.debug("filter_defer_apply_on called")

    def filter_defer_apply_off(self):
        LOG.debug("filter_defer_apply_off called")

    @property
    def ports(self):
        LOG.debug("ports called")
        return {}

    def update_security_group_members(self, sg_id, ips):
        LOG.debug("update_security_group_members called")

    def update_security_group_rules(self, sg_id, rules):
        LOG.debug("update_security_group_rules called")

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        LOG.debug("security_group_updated called")

    def update_security_group_rules_and_members(self, security_groups,
                                                security_group_member_ips):
        LOG.debug("update_security_group_rules_and_members called")

    def stop_all(self):
        LOG.info(_LI("stop noop firewall engine called"))
