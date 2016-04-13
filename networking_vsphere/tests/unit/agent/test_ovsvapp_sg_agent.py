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

import mock
from oslo_config import cfg
from oslo_utils import uuidutils

from networking_vsphere.agent import ovsvapp_sg_agent as sg_agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.drivers import ovs_firewall
from networking_vsphere.tests import base

cfg.CONF.import_group('AGENT', 'neutron.plugins.ml2.drivers.openvswitch.agent.'
                      'common.config')

fake_port = {'security_group_source_groups': 'abc',
             'mac_address': '00:11:22:33:44:55',
             'network_id': "netid",
             'id': "123",
             'security_groups': "abc",
             'segmentation_id': "100",
             'sg_normal_rules': [],
             'security_group_rules': [
                 {"direction": "ingress",
                  "protocol": "tcp",
                  "port_range_min": 2001,
                  "port_range_max": 2009,
                  "source_port_range_min": 67,
                  "source_port_range_max": 77,
                  "ethertype": "IPv4",
                  "source_ip_prefix": "150.1.1.0/22",
                  "dest_ip_prefix": "170.1.1.0/22"}]}


class FakeFirewall(ovs_firewall.OVSFirewallDriver):
    def __init__(self):
        self.filtered_ports = {}


class TestOVSvAppSecurityGroupAgent(base.TestCase):

    @mock.patch('networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver.'
                'check_ovs_firewall_restart')
    @mock.patch('networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver.'
                'setup_base_flows')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.create')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.set_secure_mode')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.get_port_ofport')
    def setUp(self, mock_get_port_ofport, mock_set_secure_mode,
              mock_create_ovs_bridge, mock_setup_base_flows,
              mock_check_ovs_firewall_restart):
        super(TestOVSvAppSecurityGroupAgent, self).setUp()
        self.context = mock.Mock()
        cfg.CONF.set_override('security_bridge_mapping',
                              "fake_sec_br:fake_if", 'SECURITYGROUP')
        mock_get_port_ofport.return_value = 5
        self.ovsvapp_sg_rpc = sg_agent.OVSvAppSecurityGroupServerRpcApi(
            ovsvapp_const.OVSVAPP)
        self.agent = sg_agent.OVSvAppSecurityGroupAgent(
            self.context, self.ovsvapp_sg_rpc, True)
        self.agent.firewall = FakeFirewall()
        self.agent.defer_refresh_firewall = True
        self.agent.devices_to_refilter = set()
        self.agent.global_refresh_firewall = False
        self.agent._use_enhanced_rpc = None
        self.LOG = sg_agent.LOG

    def test_use_enhanced_rpc(self):
        expected = False
        _use_enhanced_rpc = self.agent.use_enhanced_rpc
        self.assertEqual(expected, _use_enhanced_rpc)

    def test_sg_provider_updated(self):
        ports_dict = {'123': {'id': '123',
                              'network_id': 'net_1',
                              'device': '123'},
                      '124': {'id': '124',
                              'network_id': 'net_2',
                              'device': '124'},
                      '125': {'id': '125',
                              'network_id': 'net_1',
                              'device': '125'}}
        self.agent.firewall.filtered_ports = ports_dict
        self.agent.devices_to_refilter = set()
        self.agent.firewall.provider_port_cache = set(['123', '124', '125'])
        self.agent.sg_provider_updated('net_1')
        self.assertEqual(set(['124']), self.agent.firewall.provider_port_cache)
        self.assertEqual(ports_dict, self.agent.firewall.filtered_ports)
        self.assertEqual(set(['123', '125']), self.agent.devices_to_refilter)

    def test_add_devices_to_filter(self):
        with mock.patch.object(self.agent.firewall,
                               'add_ports_to_filter') as mock_add:
            self.agent.add_devices_to_filter(['213421adsfs-123412asdfas',
                                              '213421adsfs-123412asdfas'])
            mock_add.assert_called_with(['213421adsfs-123412asdfas',
                                         '213421adsfs-123412asdfas'])

    def test_add_devices_to_filter_empty_input(self):
        with mock.patch.object(self.agent.firewall,
                               'add_ports_to_filter') as mock_add:
            self.agent.add_devices_to_filter([])
            self.assertFalse(mock_add.called)

    def test_ovsvapp_sg_update(self):
        ports = {"123": fake_port['security_group_rules']}
        self.agent.firewall.filtered_ports["123"] = fake_port
        with mock.patch.object(self.agent.firewall,
                               'prepare_port_filter') as mock_prepare:
            self.agent.ovsvapp_sg_update(ports)
            self.assertTrue(mock_prepare.called)
            mock_prepare.assert_called_with(ports["123"])

    def test_ovsvapp_sg_update_multiple_ports(self):
        ports = {"123": fake_port['security_group_rules'],
                 "456": fake_port['security_group_rules']}
        self.agent.firewall.filtered_ports["123"] = fake_port
        self.agent.firewall.filtered_ports["456"] = fake_port
        with mock.patch.object(self.agent.firewall,
                               'prepare_port_filter') as mock_prepare:
            self.agent.ovsvapp_sg_update(ports)
            self.assertTrue(mock_prepare.called)
            mock_prepare.assert_called_with(ports["123"])
            mock_prepare.assert_called_with(ports["456"])

    def test_ovsvapp_sg_update_invalid_port(self):
        ports = {"123": fake_port['security_group_rules']}
        self.agent.firewall.filtered_ports = {}
        with mock.patch.object(self.agent.firewall,
                               'prepare_port_filter') as mock_prepare:
            self.agent.ovsvapp_sg_update(ports)
            self.assertFalse(mock_prepare.called)

    def test_remove_devices_filter(self):
        with mock.patch.object(self.agent.firewall,
                               'clean_port_filters') as mock_clean:
            self.agent.remove_devices_filter("123")
            self.assertTrue(mock_clean.called)
            mock_clean.assert_called_with(["123"], True)

    def _get_fake_portids(self, count):
        ports = []
        i = 0
        while i < count:
            ports.append(uuidutils.generate_uuid())
            i += 1
        return ports

    def _get_fake_ports(self, ids):
        ports = {}
        for id in ids:
            port = {'id': id, 'security_group_rules': mock.MagicMock()}
            ports[id] = port
        return ports

    def test_fetch_and_apply_rules_for_prepare(self):
        port_ids = self._get_fake_portids(2)
        ret_val = self._get_fake_ports(port_ids)
        port_info = {'member_ips': mock.MagicMock(),
                     'ports': ret_val}
        with mock.patch.object(self.agent.ovsvapp_sg_rpc,
                               'security_group_info_for_esx_devices',
                               return_value=port_info) as mock_ovsvapp_sg_rpc, \
                mock.patch.object(self.agent, 'expand_sg_rules',
                                  return_value=ret_val
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.agent.firewall,
                                  'prepare_port_filter') as mock_prep, \
                mock.patch.object(self.agent.firewall,
                                  'update_port_filter') as mock_update:
            self.agent._fetch_and_apply_rules(set(port_ids))
            self.assertEqual(1, mock_ovsvapp_sg_rpc.call_count)
            self.assertEqual(2, mock_expand_sg_rules.call_count)
            self.assertEqual(2, mock_prep.call_count)
            self.assertFalse(mock_update.called)

    def test_fetch_and_apply_rules_for_refresh(self):
        port_ids = self._get_fake_portids(2)
        ret_val = self._get_fake_ports(port_ids)
        port_info = {'member_ips': mock.MagicMock(),
                     'ports': ret_val}
        with mock.patch.object(self.agent.ovsvapp_sg_rpc,
                               'security_group_info_for_esx_devices',
                               return_value=port_info) as mock_ovsvapp_sg_rpc, \
                mock.patch.object(self.agent, 'expand_sg_rules',
                                  return_value=ret_val
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.agent.firewall,
                                  'prepare_port_filter') as mock_prep, \
                mock.patch.object(self.agent.firewall,
                                  'update_port_filter') as mock_update:
            self.agent._fetch_and_apply_rules(set(port_ids), True)
            self.assertEqual(1, mock_ovsvapp_sg_rpc.call_count)
            self.assertEqual(2, mock_expand_sg_rules.call_count)
            self.assertEqual(2, mock_update.call_count)
            self.assertFalse(mock_prep.called)

    def test_process_port_set(self):
        port_ids = self._get_fake_portids(25)
        with mock.patch.object(self.agent.t_pool, 'spawn_n') as mock_spawn:
            self.agent._process_port_set(set(port_ids))
            self.assertEqual(3, mock_spawn.call_count)

    def test_prepare_firewall(self):
        port_ids = self._get_fake_portids(25)
        with mock.patch.object(self.agent, '_process_port_set'
                               ) as mock_process:
            self.agent.prepare_firewall(set(port_ids))
            mock_process.assert_called_with(set(port_ids))

    def test_refresh_firewall(self):
        port_ids = self._get_fake_portids(30)
        with mock.patch.object(self.agent, '_process_port_set'
                               ) as mock_process:
            self.agent.refresh_firewall(set(port_ids))
            mock_process.assert_called_with(set(port_ids), True)

    def test_refresh_firewall_no_input(self):
        port_ids = self._get_fake_portids(10)
        ports_data = self._get_fake_ports(port_ids)
        self.agent.firewall.filtered_ports = ports_data
        with mock.patch.object(self.agent, '_process_port_set'
                               ) as mock_process:
            self.agent.refresh_firewall()
            mock_process.assert_called_with(set(port_ids), True)

    def test_refresh_firewall_no_input_firewall_empty(self):
        self.agent.firewall.filtered_ports = {}
        with mock.patch.object(self.agent, '_process_port_set'
                               ) as mock_process:
            self.agent.refresh_firewall()
            self.assertFalse(mock_process.called)

    def test_refresh_port_filters_case1(self):
        # Global refresh firewall is false devices_to_refilter has few ports
        # This case is where we need to update filters only the own ports
        own_host_ports = self._get_fake_portids(3)
        other_host_ports = self._get_fake_portids(6)
        self.agent.devices_to_refilter = set(own_host_ports)
        self.agent.global_refresh_firewall = False
        with mock.patch.object(self.agent.firewall, 'clean_port_filters'
                               ) as mock_clean, \
                mock.patch.object(self.agent, 'refresh_firewall'
                                  ) as mock_refresh, \
                mock.patch.object(self.agent, 'prepare_firewall'
                                  ) as mock_prepare:
            self.agent.refresh_port_filters(set(own_host_ports),
                                            set(other_host_ports))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        mock_clean.assert_called_with(set([]))
        self.assertTrue(mock_refresh.called)
        self.assertFalse(mock_prepare.called)

    def test_refresh_port_filters_case2(self):
        # Global refresh firewall is false devices_to_refilter has few ports
        # This case is where we need to update filters only the other ports
        own_host_ports = self._get_fake_portids(3)
        other_host_ports = self._get_fake_portids(6)
        self.agent.devices_to_refilter = set(other_host_ports)
        self.agent.global_refresh_firewall = False
        with mock.patch.object(self.agent.firewall, 'clean_port_filters'
                               ) as mock_clean, \
                mock.patch.object(self.agent, 'refresh_firewall'
                                  ) as mock_refresh, \
                mock.patch.object(self.agent, 'prepare_firewall'
                                  ) as mock_prepare:
            self.agent.refresh_port_filters(set(own_host_ports),
                                            set(other_host_ports))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        mock_clean.assert_called_with(set(other_host_ports))
        self.assertFalse(mock_refresh.called)
        self.assertTrue(mock_prepare.called)

    def test_refresh_port_filters_case3(self):
        # Global refresh firewall is false devices_to_refilter has few ports
        # This case is where we need to update filters for both own host and
        # other host ports
        own_host_ports = self._get_fake_portids(3)
        other_host_ports = self._get_fake_portids(6)
        ports_to_filter = [own_host_ports[2], other_host_ports[3],
                           other_host_ports[4]]
        self.agent.devices_to_refilter = set(ports_to_filter)
        self.agent.global_refresh_firewall = False
        with mock.patch.object(self.agent.firewall, 'clean_port_filters'
                               ) as mock_clean, \
                mock.patch.object(self.agent, 'refresh_firewall'
                                  ) as mock_refresh, \
                mock.patch.object(self.agent, 'prepare_firewall'
                                  ) as mock_prepare:
            self.agent.refresh_port_filters(set(own_host_ports),
                                            set(other_host_ports))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        mock_clean.assert_called_with(set([other_host_ports[3],
                                           other_host_ports[4]]))
        self.assertTrue(mock_refresh.called)
        self.assertTrue(mock_prepare.called)

    def test_refresh_port_filters_case4(self):
        # Global refresh firewall is True devices_to_refilter has no ports
        own_host_ports = self._get_fake_portids(3)
        other_host_ports = self._get_fake_portids(6)
        self.agent.devices_to_refilter = set([])
        self.agent.global_refresh_firewall = True
        with mock.patch.object(self.agent.firewall, 'clean_port_filters'
                               ) as mock_clean, \
                mock.patch.object(self.agent, 'refresh_firewall'
                                  ) as mock_refresh, \
                mock.patch.object(self.agent, 'prepare_firewall'
                                  ) as mock_prepare:
            self.agent.refresh_port_filters(set(own_host_ports),
                                            set(other_host_ports))
        self.assertFalse(self.agent.global_refresh_firewall)
        mock_clean.assert_called_with(set(other_host_ports))
        self.assertTrue(mock_refresh.called)
        self.assertFalse(mock_prepare.called)

    def test_refresh_port_filters_case5(self):
        # Global refresh firewall is True devices_to_refilter has few ports
        # global_refresh_firewall should get priority over devices_to_refilter
        own_host_ports = self._get_fake_portids(3)
        other_host_ports = self._get_fake_portids(6)
        self.agent.devices_to_refilter = set(own_host_ports)
        self.agent.global_refresh_firewall = True
        with mock.patch.object(self.agent.firewall, 'clean_port_filters'
                               ) as mock_clean, \
                mock.patch.object(self.agent, 'refresh_firewall'
                                  ) as mock_refresh, \
                mock.patch.object(self.agent, 'prepare_firewall'
                                  ) as mock_prepare:
            self.agent.refresh_port_filters(set(own_host_ports),
                                            set(other_host_ports))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        mock_clean.assert_called_with(set(other_host_ports))
        self.assertTrue(mock_refresh.called)
        self.assertFalse(mock_prepare.called)
