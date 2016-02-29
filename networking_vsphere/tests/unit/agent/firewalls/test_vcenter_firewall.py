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
from networking_vsphere.utils import security_group_utils as sg_utils

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

    def setUp(self):
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

    def _fake_port(self, sg_id, sg_rules, id=uuid.uuid4()):
        return {'id': id,
                'device': 'tapfake_dev',
                'security_groups': [sg_id],
                'security_group_rules': sg_rules,
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'fixed_ips': [FAKE_IP['IPv4'], FAKE_IP['IPv6']],
                'binding:vif_details': {'dvs_port_key': '333'}}

    def test_prepare_port_filter(self):
        port = self._fake_port('12345', [FAKE_SG_RULE_IPV4_PORT,
                                         FAKE_SG_RULE_IPV6])
        with mock.patch.object(self.firewall, '_get_dvs_for_port_id',
                               return_value=self.dvs), \
            mock.patch.object(sg_utils, 'update_port_rules') as update_port:
                self.firewall.prepare_port_filter([port])
                update_port.assert_called_once_with(self.dvs, [port])
                self.assertEqual(
                    {port['device']: port}, self.firewall.dvs_ports)

    def test_remove_port_filter(self):
        port = self._fake_port('12345', [FAKE_SG_RULE_IPV4_PORT,
                                         FAKE_SG_RULE_IPV6])
        self.firewall.dvs_ports[port['id']] = port
        with mock.patch.object(self.firewall, '_get_dvs_for_port_id',
                               return_value=self.dvs), \
                mock.patch.object(sg_utils,
                                  'update_port_rules') as update_port:
            self.firewall.remove_port_filter([port['id']])
            update_port.assert_called_once_with(self.dvs, [port])
            self.assertNotIn(port['id'], self.firewall.dvs_port_map.values())

    def test__apply_sg_rules_for_port(self):
        with mock.patch.object(sg_utils, 'update_port_rules') as update_port:
            self.firewall._apply_sg_rules_for_port([self.port])
            update_port.assert_called_once_with(self.dvs, [self.port])

    def test__get_dvs_for_port_id(self):
        dvs = self.firewall._get_dvs_for_port_id(self.port['id'])
        self.assertEqual(self.dvs, dvs)

    def test__get_dvs_for_port_id_new_dvs(self):
        port = self._fake_port('1234', self.sg_rules, id=uuid.uuid4())
        new_dvs = mock.Mock()
        with mock.patch('networking_vsphere.utils.dvs_util.create_port_map',
                        return_value={new_dvs: [port['id']]}):
            dvs = self.firewall._get_dvs_for_port_id(port['id'])
            self.assertEqual(new_dvs, dvs)
            self.assertDictSupersetOf({new_dvs: set([port['id']])},
                                      self.firewall.dvs_port_map)

    def test__remove_sg_from_dvs_port(self):
        port = self._fake_port('4567', [FAKE_SG_RULE_IPV6], id=uuid.uuid4())
        with mock.patch.object(self.firewall, '_get_dvs_for_port_id',
                               return_value=self.dvs), \
                mock.patch.object(sg_utils,
                                  'update_port_rules') as update_port:
            self.firewall._remove_sg_from_dvs_port(port)
            update_port.assert_called_once_with(self.dvs, [port])
            self.assertEqual([], port['security_group_rules'])
