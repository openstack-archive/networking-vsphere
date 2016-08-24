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
import mock
import uuid

from neutron.tests import base

from networking_vsphere.agent.firewalls import vcenter_firewall

FAKE_PREFIX = {'IPv4': '10.0.0.0/24',
               'IPv6': 'fe80::/48'}
FAKE_IP = {'IPv4': '10.0.0.1',
           'IPv6': 'fe80::1'}

FAKE_SG_RULE_IPV4_PORT = {'ethertype': 'IPv4', 'direction': 'ingress',
                          'port_range_min': 20, 'port_range_max': 20,
                          'protocol': 'tcp'}

FAKE_SG_RULE_IPV6 = {'ethertype': 'IPv6', 'direction': 'egress'}

FAKE_SG_RULE_IPV4_WITH_REMOTE = {'ethertype': 'IPv4', 'direction': 'ingress',
                                 'remote_group_id': '12345'}


class TestDVSFirewallDriver(base.BaseTestCase):

    @mock.patch('networking_vsphere.agent.firewalls.'
                'vcenter_firewall.firewall_main')
    def setUp(self, firewall_staff_mock):
        super(TestDVSFirewallDriver, self).setUp()
        self.dvs = mock.Mock()
        self.use_patch(
            'networking_vsphere.utils.dvs_util.create_network_map_from_config',
            return_value={'physnet1': self.dvs})
        self.firewall = vcenter_firewall.DVSFirewallDriver()
        self.sg_rules = [FAKE_SG_RULE_IPV6, FAKE_SG_RULE_IPV4_WITH_REMOTE]
        self.firewall.sg_rules = {'1234': self.sg_rules}
        self.port = self._fake_port('1234', self.sg_rules)
        self.firewall.dvs_port_map = {self.dvs: set([self.port['id']])}
        self.firewall.dvs_ports = {self.port['device']: self.port}

    def use_patch(self, *args, **kwargs):
        patch = mock.patch(*args, **kwargs)
        self.addCleanup(patch.stop)
        return patch.start()

    def _fake_port(self, sg_id, sg_rules, id=uuid.uuid4(),
                   network_id=uuid.uuid4()):
        return {'id': id,
                'device': 'tapfake_dev',
                'security_groups': [sg_id],
                'security_group_rules': sg_rules,
                'network_id': network_id,
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'fixed_ips': [FAKE_IP['IPv4'], FAKE_IP['IPv6']],
                'binding:vif_details': {'dvs_port_key': '333'}}

    def test_remove_port_filter(self):
        port = self._fake_port('12345', [FAKE_SG_RULE_IPV4_PORT,
                                         FAKE_SG_RULE_IPV6])
        self.firewall.dvs_ports[port['id']] = port
        self.firewall.remove_port_filter([port['id']])
        self.assertNotIn(port['id'], self.firewall.dvs_port_map.values())

    def test__apply_sg_rules_for_port(self):
        self.firewall._apply_sg_rules_for_port([self.port])
