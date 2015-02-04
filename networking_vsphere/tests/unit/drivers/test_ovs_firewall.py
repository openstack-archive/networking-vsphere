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

import copy

import mock
from oslo.config import cfg

import contextlib
from neutron.agent.common import config
from neutron.agent.linux import ovs_lib as ovslib
from neutron.common import constants
from neutron.tests import base

from networking_vsphere.drivers import ovs_firewall as ovs_fw


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
                  "source_port_range_max": 68,
                  "ethertype": "IPv4",
                  "source_ip_prefix": "150.1.1.0/22",
                  "dest_ip_prefix": "170.1.1.0/22"}]}


class TestOVSFirewallDriver(base.BaseTestCase):
    def setUp(self):
        super(TestOVSFirewallDriver, self).setUp()
        config.register_root_helper(cfg.CONF)
        cfg.CONF.set_override('security_bridge_mapping',
                              "br-fake:fake_if", 'SECURITYGROUP')
        with contextlib.nested(
            # mock.patch('networking_vsphere.agent.portCache'),
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
            self.ovs_firewall = ovs_fw.OVSFirewallDriver()
            self.ovs_firewall.sg_br = mock.Mock()
            self.mock_br = ovslib.DeferredOVSBridge(self.ovs_firewall.sg_br)
            self.LOG = ovs_fw.LOG

    def test_get_compact_port(self):
        compact_port = {'security_group_source_groups': 'abc',
                        'mac_address': '00:11:22:33:44:55',
                        'network_id': "netid",
                        'id': "123",
                        'device': "123",
                        'security_groups': "abc",
                        'segmentation_id': "100"}
        res = self.ovs_firewall._get_compact_port(fake_port)
        self.assertEqual(res, compact_port)

    def test_add_ovs_flow(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (deferred_fn, mock_add_flow):
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal")
            mock_add_flow.assert_called_with(priority=0, actions='normal',
                                             table=1)

    def test_add_ovs_flow_with_protocol(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (deferred_fn, mock_add_flow):
            # rule with protocol
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal",
                                            protocol="arp")
            mock_add_flow.assert_called_with(table=1, priority=0,
                                             proto="arp", actions="normal")

    def test_add_ovs_flow_with_dest_mac(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (deferred_fn, mock_add_flow):
            # rule with dl_dest
            dest_mac = "01:00:00:00:00:00"
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal",
                                            dl_dest=dest_mac)
            mock_add_flow.assert_called_with(table=1, priority=0,
                                             dl_dst=dest_mac,
                                             actions="normal")

    def test_add_ovs_flow_with_tcpflag(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (deferred_fn, mock_add_flow):
            # rule with tcp_flags
            t_flag = "+rst"
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal",
                                            tcp_flag=t_flag)
            mock_add_flow.assert_called_with(table=1, priority=0,
                                             proto=constants.PROTO_NAME_TCP,
                                             tcp_flags=t_flag,
                                             actions="normal")

    def test_add_ovs_flow_with_icmptype(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (deferred_fn, mock_add_flow):
            # rule with icmp_req_type
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal",
                                            icmp_req_type=11)
            mock_add_flow.assert_called_with(table=1, priority=0,
                                             proto=constants.PROTO_NAME_ICMP,
                                             icmp_type=11, actions="normal")

    def test_add_ports_to_filter(self):
        self.ovs_firewall.filtered_ports = {}
        self.ovs_firewall.add_ports_to_filter([fake_port])
        res_port = {'security_group_source_groups': 'abc',
                    'mac_address': '00:11:22:33:44:55',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        self.assertIsNotNone(self.ovs_firewall.filtered_ports)
        ret_port = self.ovs_firewall.filtered_ports["123"]
        self.assertEqual(ret_port, res_port)

    def test_setup_aap_flows(self):
        port_with_app = copy.deepcopy(fake_port)
        key = "allowed_address_pairs"
        port_with_app[key] = [{'ip_address': '10.0.0.2',
                               'mac_address': 'aa:bb:cc:dd:ee:aa'},
                              {'ip_address': '10.0.0.3',
                               'mac_address': 'aa:bb:cc:dd:ee:ab'}]
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                              return_value=100),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (get_vlan, deferred_fn, mock_add_flow):
            self.ovs_firewall._setup_aap_flows(self.mock_br, port_with_app)
            self.assertEqual(mock_add_flow.call_count, 2)

    def test_setup_aap_flows_invalid_call(self):
        port_with_app = copy.deepcopy(fake_port)
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                              return_value=100),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (get_vlan, deferred_fn, mock_add_flow):
            self.ovs_firewall._setup_aap_flows(self.mock_br, port_with_app)
            self.assertFalse(mock_add_flow.called)

#     def test_get_net_prefix_len(self):
#         ip_addr = "150.1.1.0/22"
#         length = self.ovs_firewall._get_net_prefix_len(ip_addr)
#         self.assertNotEqual(length, 0)
#
#         ip_addr = None
#         length = self.ovs_firewall._get_net_prefix_len(ip_addr)
#         self.assertEqual(length, 0)

    def test_get_protocol(self):
        proto = self.ovs_firewall._get_protocol("IPv4", None)
        self.assertEqual(proto, ['ip'])

        proto = self.ovs_firewall._get_protocol("IPv6", None)
        self.assertEqual(proto, ['ipv6'])

        proto = self.ovs_firewall._get_protocol("IPv6", 'icmp')
        self.assertEqual(proto, ['icmp6'])

        proto = self.ovs_firewall._get_protocol("IPv4", 'icmp')
        self.assertEqual(proto, ['icmp'])

        proto = self.ovs_firewall._get_protocol("IPv4", 'udp')
        self.assertEqual(proto, ['udp'])

        proto = self.ovs_firewall._get_protocol("IPv6", 'tcp')
        self.assertEqual(proto, ['tcp'])

        proto = self.ovs_firewall._get_protocol("IPv6", 'unknown')
        self.assertEqual(proto, ['ipv6', 'unknown'])

    def test_add_flow_with_range(self):
        flow = {"priority": 1}
        res_flow = {"priority": 1,
                    "tp_dst": 1,
                    "tp_src": 1}
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (deferred_fn, mock_add_flow):
            self.ovs_firewall._add_flow_with_range(self.mock_br, flow,
                                                   1, 2, 1, 2)
            mock_add_flow.called_with(res_flow)
            self.assertEqual(mock_add_flow.call_count, 4)

    def test_add_flow_with_multiple_range(self):
        flow = {"priority": 1}
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (deferred_fn, mock_add_flow):
            self.ovs_firewall._add_flow_with_range(self.mock_br, flow,
                                                   1, 3, 1, 2)
            self.assertEqual(mock_add_flow.call_count, 6)

    def test_add_flows_call_no_vlan(self):
        port_with_app = copy.deepcopy(fake_port)
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                              return_value=None),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow'),
            mock.patch.object(self.LOG, 'warn'),
        ) as (get_vlan, deferred_fn, mock_add_flow, warning_log):
            self.ovs_firewall._add_flows(self.mock_br, port_with_app)
            self.assertFalse(mock_add_flow.called)
            self.assertTrue(warning_log.called)

    def test_add_flows_call_tcp(self):
        port = copy.deepcopy(fake_port)
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                              return_value=100),
            mock.patch.object(self.ovs_firewall, '_get_protocol',
                              return_value=['tcp']),
            mock.patch.object(self.ovs_firewall, '_add_flow_with_range'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (get_vlan, get_proto, add_range_flows,
              deferred_fn, mock_add_flow):
            self.ovs_firewall._add_flows(self.mock_br, port)
            self.assertTrue(get_vlan.called)
            self.assertTrue(get_proto.called)
            self.assertTrue(add_range_flows.called)

    def test_add_flows_call_normal(self):
        port = copy.deepcopy(fake_port)
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                              return_value=100),
            mock.patch.object(self.ovs_firewall, '_get_protocol',
                              return_value=['ip']),
            mock.patch.object(self.ovs_firewall, '_add_flow_with_range'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'add_flow')
        ) as (get_vlan, get_proto, add_range_flows,
              deferred_fn, mock_add_flow):
            self.ovs_firewall._add_flows(self.mock_br, port)
            self.assertTrue(get_vlan.called)
            self.assertTrue(get_proto.called)
            self.assertFalse(add_range_flows.called)
            self.assertTrue(mock_add_flow.called)

    def test_prepare_port_filter(self):
        res_port = {'security_group_source_groups': 'abc',
                    'mac_address': '00:11:22:33:44:55',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.ovs_firewall, '_setup_aap_flows'),
            mock.patch.object(self.ovs_firewall, '_add_flows'),
            mock.patch.object(self.mock_br, 'add_flow'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
        ) as (get_lock_fn, deferred_fn, aap_flow_fn, add_flow_fn,
              mock_add_flow, rls_lock_fn):
            self.ovs_firewall.prepare_port_filter(fake_port)
            self.assertTrue(get_lock_fn.called)
            aap_flow_fn.assertCalledWith(self.mock_br, fake_port)
            add_flow_fn.assertCalledWith(self.mock_br, fake_port)
            self.assertTrue(rls_lock_fn.called)
            ret_port = self.ovs_firewall.filtered_ports['123']
            self.assertEqual(ret_port, res_port)

    def test_prepare_port_filter_exception(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.ovs_firewall, '_setup_aap_flows',
                              side_effect=Exception()),
            mock.patch.object(self.ovs_firewall, '_add_flows'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.LOG, 'exception')
        ) as (get_lock_fn, deferred_fn, aap_flow_fn, add_flow_fn,
              rls_lock_fn, exception_log):
            self.ovs_firewall.prepare_port_filter(fake_port)
            self.assertTrue(get_lock_fn.called)
            aap_flow_fn.assertCalledWith(self.mock_br, fake_port)
            self.assertFalse(add_flow_fn.called)
            self.assertTrue(exception_log.called)
            self.assertTrue(rls_lock_fn.called)

    def test_remove_flows(self):
        res_port = {'security_group_source_groups': 'abc',
                    'mac_address': '00:11:22:33:44:55',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        self.ovs_firewall.filtered_ports["123"] = res_port
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                              return_value=100),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'delete_flows')
        ) as (get_vlan, deferred_fn, mock_del_flows):
            self.ovs_firewall._remove_flows(self.mock_br, "123")
            self.assertTrue(get_vlan.called)
            self.assertEqual(mock_del_flows.call_count, 5)

    def test_remove_flows_invalid_port(self):
        res_port = {'security_group_source_groups': 'abc',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        self.ovs_firewall.filtered_ports["123"] = res_port
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                              return_value=100),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.mock_br, 'delete_flows'),
            mock.patch.object(self.LOG, 'debug')
        ) as (get_vlan, deferred_fn, mock_del_flows, debug_log):
            self.ovs_firewall._remove_flows(self.mock_br, "123")
            self.assertTrue(get_vlan.called)
            self.assertEqual(mock_del_flows.call_count, 1)
            self.assertTrue(debug_log.call_count, 2)

    def test_clean_port_filters(self):
        res_port = {'security_group_source_groups': 'abc',
                    'mac_address': '00:11:22:33:44:55',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        self.ovs_firewall.filtered_ports["123"] = res_port
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, '_remove_flows'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall, 'remove_lock')
        ) as (deferred_fn, get_lock_fn,
              mock_rem_flow, rls_lock_fn, remove_lock_fn):
            self.ovs_firewall.clean_port_filters(["123"])
            self.assertTrue(get_lock_fn.called)
            mock_rem_flow.assertCalledWith(self.mock_br, "123")
            self.assertTrue(rls_lock_fn.called)
            self.assertIn("123", self.ovs_firewall.filtered_ports)
            self.assertFalse(remove_lock_fn.called)

    def test_clean_port_filters_remove_port(self):
        res_port = {'security_group_source_groups': 'abc',
                    'mac_address': '00:11:22:33:44:55',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        self.ovs_firewall.filtered_ports["123"] = res_port
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, '_remove_flows'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall, 'remove_lock')
        ) as (deferred_fn, get_lock_fn,
              mock_rem_flow, rls_lock_fn, remove_lock_fn):
            self.ovs_firewall.clean_port_filters(["123"], True)
            self.assertTrue(get_lock_fn.called)
            mock_rem_flow.assertCalledWith(self.mock_br, "123")
            self.assertTrue(rls_lock_fn.called)
            self.assertNotIn("123", self.ovs_firewall.filtered_ports)
            self.assertTrue(remove_lock_fn.called)

    def test_clean_port_filters_exception(self):
        res_port = {'security_group_source_groups': 'abc',
                    'mac_address': '00:11:22:33:44:55',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        self.ovs_firewall.filtered_ports["123"] = res_port
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, '_remove_flows',
                              side_effect=Exception()),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall, 'remove_lock'),
            mock.patch.object(self.LOG, 'exception')
        ) as (deferred_fn, get_lock_fn, rem_flow_fn,
              rls_lock_fn, remove_lock_fn, exception_log):
            self.ovs_firewall.clean_port_filters(["123"])
            self.assertTrue(get_lock_fn.called)
            rem_flow_fn.assertCalledWith(self.mock_br, "123")
            self.assertFalse(remove_lock_fn.called)
            self.assertTrue(exception_log.called)
            self.assertTrue(rls_lock_fn.called)

    def test_update_port_filters(self):
        res_port = {'security_group_source_groups': 'abc',
                    'mac_address': '00:11:22:33:44:55',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        self.ovs_firewall.filtered_ports["123"] = res_port
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, '_remove_flows'),
            mock.patch.object(self.ovs_firewall, '_setup_aap_flows'),
            mock.patch.object(self.ovs_firewall, '_add_flows'),
            mock.patch.object(self.ovs_firewall, 'release_lock')
        ) as (deferred_fn, get_lock_fn, mock_rem_flow,
              aap_flow_fn, add_flow_fn, rls_lock_fn):
            self.ovs_firewall.update_port_filter(fake_port)
            self.assertTrue(get_lock_fn.called)
            mock_rem_flow.assertCalledWith(self.mock_br, "123")
            aap_flow_fn.assertCalledWith(self.mock_br, fake_port)
            add_flow_fn.assertCalledWith(self.mock_br, fake_port)
            self.assertTrue(rls_lock_fn.called)
            self.assertIn("123", self.ovs_firewall.filtered_ports)

    def test_update_port_filters_exception(self):
        res_port = {'security_group_source_groups': 'abc',
                    'mac_address': '00:11:22:33:44:55',
                    'network_id': "netid",
                    'id': "123",
                    'security_groups': "abc",
                    'segmentation_id': "100",
                    'device': "123"}
        self.ovs_firewall.filtered_ports["123"] = res_port
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=self.mock_br),
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, '_remove_flows',
                              side_effect=Exception()),
            mock.patch.object(self.ovs_firewall, '_add_flows'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.LOG, 'exception')
        ) as (deferred_fn, get_lock_fn, mock_rem_flow,
              aap_flow_fn, rls_lock_fn, exception_log):
            self.ovs_firewall.update_port_filter(fake_port)
            self.assertTrue(get_lock_fn.called)
            mock_rem_flow.assertCalledWith(self.mock_br, "123")
            self.assertFalse(aap_flow_fn.called)
            self.assertTrue(rls_lock_fn.called)
            self.assertIn("123", self.ovs_firewall.filtered_ports)
            self.assertTrue(exception_log.called)
