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

import contextlib

import mock
from oslo_config import cfg

from neutron.agent import securitygroups_rpc
from neutron.openstack.common import uuidutils

from networking_vsphere.agent import ovsvapp_sg_agent
from networking_vsphere.tests import base

cfg.CONF.import_group('AGENT', 'neutron.plugins.openvswitch.common.config')

fake_port = {'security_group_source_groups': 'abc',
             'mac_address': '00:11:22:33:44:55',
             'network_id': "netid",
             'id': "123",
             'security_groups': "abc",
             'segmentation_id': "100",
             "security_group_rules": [
                 {"direction": "ingress",
                  "protocol": "tcp",
                  "port_range_min": 2001,
                  "port_range_max": 2009,
                  "source_port_range_min": 67,
                  "source_port_range_max": 77,
                  "ethertype": "IPv4",
                  "source_ip_prefix": "150.1.1.0/22",
                  "dest_ip_prefix": "170.1.1.0/22"}]}


class FakePlugin(securitygroups_rpc.SecurityGroupServerRpcApi):
    def __init__(self, topic):
        self.topic = topic


class TestOVSVAppSecurityGroupAgent(base.TestCase):

    def setUp(self):
        self.context = mock.Mock()
        self.plugin = FakePlugin('fake_topic')
        cfg.CONF.set_default(
            'firewall_driver',
            'networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver',
            group='SECURITYGROUP')
        cfg.CONF.set_override('security_bridge_mapping',
                              "br-fake:fake_if", 'SECURITYGROUP')
        super(TestOVSVAppSecurityGroupAgent, self).setUp()
        with contextlib.nested(
                mock.patch('networking_vsphere.drivers.'
                           'ovs_firewall.OVSFirewallDriver.'
                           'setup_base_flows'),
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'create'),
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'set_secure_mode'),
                mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                           'get_port_ofport',
                           return_value=5)):
            self.agent = ovsvapp_sg_agent.OVSVAppSecurityGroupAgent(
                self.context, self.plugin, True)
        self.LOG = ovsvapp_sg_agent.LOG

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

    def test_remove_device_filters(self):
        with mock.patch.object(self.agent.firewall,
                               'clean_port_filters') as mock_clean:
            self.agent.remove_device_filters("123")
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
            port = {'id': id, 'security_group_rules': mock.Mock()}
            ports[id] = port
        return ports

    def test_prepare_firewall(self):
        port_ids = self._get_fake_portids(2)
        ret_val = self._get_fake_ports(port_ids)
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              'security_group_rules_for_devices',
                              return_value=ret_val),
            mock.patch.object(self.agent.firewall,
                              'prepare_port_filter')
        ) as (plugin_rpc, mock_prep):
            self.agent.prepare_firewall(set(port_ids))
            self.assertEqual(1, plugin_rpc.call_count)
            self.assertEqual(2, mock_prep.call_count)

    def test_prepare_firewall_many_ports(self):
        # Since we batch the ports before firing RPC to the neutron server
        # the number of RPCs should be lower. To be specific, we should be
        # firing one RPC call for every 10 ports.
        port_ids = self._get_fake_portids(25)
        ret_val = self._get_fake_ports(port_ids)
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              'security_group_rules_for_devices',
                              return_value=ret_val),
            mock.patch.object(self.agent.firewall,
                              'prepare_port_filter')
        ) as (plugin_rpc, mock_prep):
            self.agent.prepare_firewall(set(port_ids))
            self.assertEqual(3, plugin_rpc.call_count)
            self.assertEqual(25, mock_prep.call_count)

    def test_refresh_firewall_specific_ports(self):
        port_ids = self._get_fake_portids(2)
        ret_val = self._get_fake_ports(port_ids)
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              'security_group_rules_for_devices',
                              return_value=ret_val),
            mock.patch.object(self.agent.firewall,
                              'update_port_filter')
        ) as (plugin_rpc, mock_update):
            self.agent.refresh_firewall(set(port_ids))
            self.assertEqual(1, plugin_rpc.call_count)
            self.assertEqual(2, mock_update.call_count)

    def test_refresh_firewall_many_ports(self):
        # Since we batch the ports before firing RPC to the neutron server
        # the number of RPCs should be lower. To be specific, we should be
        # firing one RPC call for every 10 ports.
        port_ids = self._get_fake_portids(30)
        ret_val = self._get_fake_ports(port_ids)
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              'security_group_rules_for_devices',
                              return_value=ret_val),
            mock.patch.object(self.agent.firewall,
                              'update_port_filter')
        ) as (plugin_rpc, mock_update):
            self.agent.refresh_firewall(set(port_ids))
            self.assertEqual(3, plugin_rpc.call_count)
            self.assertEqual(30, mock_update.call_count)

    def test_refresh_firewall_no_input(self):
        port_ids = self._get_fake_portids(20)
        ret_val = self._get_fake_ports(port_ids)
        self.agent.firewall.filtered_ports = ret_val
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              'security_group_rules_for_devices',
                              return_value=ret_val),
            mock.patch.object(self.agent.firewall,
                              'update_port_filter')
        ) as (plugin_rpc, mock_update):
            self.agent.refresh_firewall()
            self.assertEqual(2, plugin_rpc.call_count)
            self.assertEqual(20, mock_update.call_count)

    def test_refresh_firewall_no_input_firewall_empty(self):
        port_ids = self._get_fake_portids(20)
        ret_val = self._get_fake_ports(port_ids)
        self.agent.firewall.filtered_ports = {}
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              'security_group_rules_for_devices',
                              return_value=ret_val),
            mock.patch.object(self.agent.firewall,
                              'update_port_filter')
        ) as (plugin_rpc, mock_update):
            self.agent.refresh_firewall()
            self.assertFalse(plugin_rpc.called)
            self.assertFalse(mock_update.called)

    def test_refresh_port_filters_case1(self):
        # Global refresh firewall is false devices_to_refilter has few ports
        # This case is where we need to update filters only the own ports
        own_host_ports = self._get_fake_portids(3)
        other_host_ports = self._get_fake_portids(6)
        self.agent.devices_to_refilter = set(own_host_ports)
        self.agent.global_refresh_firewall = False
        with contextlib.nested(
            mock.patch.object(self.agent.firewall, 'clean_port_filters'),
            mock.patch.object(self.agent, 'refresh_firewall'),
            mock.patch.object(self.agent, 'prepare_firewall')
        ) as (mock_clean, mock_refresh, mock_prepare):
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
        with contextlib.nested(
            mock.patch.object(self.agent.firewall, 'clean_port_filters'),
            mock.patch.object(self.agent, 'refresh_firewall'),
            mock.patch.object(self.agent, 'prepare_firewall')
        ) as (mock_clean, mock_refresh, mock_prepare):
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
        with contextlib.nested(
            mock.patch.object(self.agent.firewall, 'clean_port_filters'),
            mock.patch.object(self.agent, 'refresh_firewall'),
            mock.patch.object(self.agent, 'prepare_firewall')
        ) as (mock_clean, mock_refresh, mock_prepare):
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
        with contextlib.nested(
            mock.patch.object(self.agent.firewall, 'clean_port_filters'),
            mock.patch.object(self.agent, 'refresh_firewall'),
            mock.patch.object(self.agent, 'prepare_firewall')
        ) as (mock_clean, mock_refresh, mock_prepare):
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
        with contextlib.nested(
            mock.patch.object(self.agent.firewall, 'clean_port_filters'),
            mock.patch.object(self.agent, 'refresh_firewall'),
            mock.patch.object(self.agent, 'prepare_firewall')
        ) as (mock_clean, mock_refresh, mock_prepare):
            self.agent.refresh_port_filters(set(own_host_ports),
                                            set(other_host_ports))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        mock_clean.assert_called_with(set(other_host_ports))
        self.assertTrue(mock_refresh.called)
        self.assertFalse(mock_prepare.called)
