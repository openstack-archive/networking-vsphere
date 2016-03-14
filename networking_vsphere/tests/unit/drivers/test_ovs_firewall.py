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
from oslo_config import cfg

from neutron.agent.common import config
from neutron.agent.common import ovs_lib
from neutron.common import constants

from networking_vsphere.drivers import ovs_firewall as ovs_fw
from networking_vsphere.tests import base

fake_port = {'security_group_source_groups': 'abc',
             'mac_address': '00:11:22:33:44:55',
             'network_id': "netid",
             'id': "123",
             'security_groups': "abc",
             'lvid': "100",
             'sg_provider_rules': [],
             'security_group_rules': [
                 {"direction": "ingress",
                  "protocol": "tcp",
                  "port_range_min": 2001,
                  "port_range_max": 2009,
                  "source_port_range_min": 67,
                  "source_port_range_max": 68,
                  "ethertype": "IPv4",
                  "source_ip_prefix": "150.1.1.0/22",
                  "dest_ip_prefix": "170.1.1.0/22"}]}

fake_res_port = {'security_group_source_groups': 'abc',
                 'mac_address': '00:11:22:33:44:55',
                 'network_id': "netid",
                 'id': "123",
                 'security_groups': "abc",
                 'lvid': "100",
                 'device': "123"}

cookie = ("0x%x" % (hash("123") & 0xffffffffffffffff))


class TestOVSFirewallDriver(base.TestCase):

    @mock.patch('networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver.'
                'check_ovs_firewall_restart')
    @mock.patch('networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver.'
                'setup_base_flows')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.create')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.set_secure_mode')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.get_port_ofport')
    def setUp(self, mock_get_port_ofport, mock_set_secure_mode,
              mock_create_ovs_bridge, mock_setup_base_flows,
              mock_check_ovs_firewall_restart,):
        super(TestOVSFirewallDriver, self).setUp()
        config.register_root_helper(cfg.CONF)
        cfg.CONF.set_override('security_bridge_mapping',
                              "fake_sec_br:fake_if", 'SECURITYGROUP')
        mock_get_port_ofport.return_value = 5
        self.ovs_firewall = ovs_fw.OVSFirewallDriver()
        self.ovs_firewall.sg_br = mock.Mock()
        self.mock_br = ovs_lib.DeferredOVSBridge(self.ovs_firewall.sg_br)
        self.LOG = ovs_fw.LOG

    def test_get_compact_port(self):
        compact_port = {'security_group_source_groups': 'abc',
                        'mac_address': '00:11:22:33:44:55',
                        'network_id': "netid",
                        'id': "123",
                        'device': "123",
                        'security_groups': "abc",
                        'lvid': "100"}
        res = self.ovs_firewall._get_compact_port(fake_port)
        self.assertEqual(compact_port, res)

    def test_remove_ports_from_provider_cache(self):
        self.ovs_firewall.provider_port_cache = set(['123', '124', '125'])
        self.ovs_firewall.remove_ports_from_provider_cache(['123', '125'])
        self.assertEqual(set(['124']), self.ovs_firewall.provider_port_cache)

        self.ovs_firewall.provider_port_cache = set(['123', '124', '125'])
        self.ovs_firewall.remove_ports_from_provider_cache(['121', '125'])
        self.assertEqual(set(['123', '124']),
                         self.ovs_firewall.provider_port_cache)

    def test_add_ovs_flow(self):
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal")
            mock_add_flow.assert_called_with(priority=0, actions='normal',
                                             table=1)

    def test_add_ovs_flow_with_protocol(self):
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            # rule with protocol
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal",
                                            protocol="arp")
            mock_add_flow.assert_called_with(table=1, priority=0,
                                             proto="arp", actions="normal")

    def test_add_ovs_flow_with_dest_mac(self):
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            # rule with dl_dest
            dest_mac = "01:00:00:00:00:00"
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal",
                                            dl_dest=dest_mac)
            mock_add_flow.assert_called_with(table=1, priority=0,
                                             dl_dst=dest_mac,
                                             actions="normal")

    def test_add_ovs_flow_with_tcpflag(self):
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            # rule with tcp_flags
            t_flag = "+rst"
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal",
                                            tcp_flag=t_flag)
            mock_add_flow.assert_called_with(table=1, priority=0,
                                             proto=constants.PROTO_NAME_TCP,
                                             tcp_flags=t_flag,
                                             actions="normal")

    def test_add_ovs_flow_with_icmptype(self):
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            # rule with icmp_req_type
            self.ovs_firewall._add_ovs_flow(self.mock_br, 0, 1, "normal",
                                            icmp_req_type=11)
            mock_add_flow.assert_called_with(table=1, priority=0,
                                             proto=constants.PROTO_NAME_ICMP,
                                             icmp_type=11, actions="normal")

    def test_add_ports_to_filter(self):
        self.ovs_firewall.filtered_ports = {}
        self.ovs_firewall.add_ports_to_filter([fake_port])
        self.assertIsNotNone(self.ovs_firewall.filtered_ports)
        ret_port = self.ovs_firewall.filtered_ports["123"]
        self.assertEqual(fake_res_port, ret_port)

    def test_setup_aap_flows(self):
        port_with_app = copy.deepcopy(fake_port)
        key = "allowed_address_pairs"
        port_with_app[key] = [{'ip_address': '10.0.0.2',
                               'mac_address': 'aa:bb:cc:dd:ee:aa'},
                              {'ip_address': '10.0.0.3',
                               'mac_address': 'aa:bb:cc:dd:ee:ab'}]
        with mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                               return_value=100), \
                mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                                  return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            self.ovs_firewall._setup_aap_flows(self.mock_br, port_with_app)
            self.assertEqual(2, mock_add_flow.call_count)

    def test_setup_aap_flows_invalid_call(self):
        port_with_app = copy.deepcopy(fake_port)
        with mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                               return_value=100), \
                mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                                  return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            self.ovs_firewall._setup_aap_flows(self.mock_br, port_with_app)
            self.assertFalse(mock_add_flow.called)

    def test_get_net_prefix_len(self):
        ip_addr = "150.1.1.0/22"
        length = self.ovs_firewall._get_net_prefix_len(ip_addr)
        self.assertNotEqual(0, length)

        ip_addr = None
        length = self.ovs_firewall._get_net_prefix_len(ip_addr)
        self.assertEqual(0, length)

    def test_get_protocol(self):
        proto = self.ovs_firewall._get_protocol("IPv4", None)
        self.assertEqual(['ip'], proto)

        proto = self.ovs_firewall._get_protocol("IPv6", None)
        self.assertEqual(['ipv6'], proto)

        proto = self.ovs_firewall._get_protocol("IPv6", 'icmp')
        self.assertEqual(['icmp6'], proto)

        proto = self.ovs_firewall._get_protocol("IPv4", 'icmp')
        self.assertEqual(['icmp'], proto)

        proto = self.ovs_firewall._get_protocol("IPv4", 'udp')
        self.assertEqual(['udp'], proto)

        proto = self.ovs_firewall._get_protocol("IPv6", 'tcp')
        self.assertEqual(['tcp'], proto)

        proto = self.ovs_firewall._get_protocol("IPv6", 'unknown')
        self.assertEqual(['ipv6', 'unknown'], proto)

    def test_add_flow_with_range(self):
        flow = {"priority": 1}
        res_flow = {"priority": 1,
                    "tp_dst": 1,
                    "tp_src": 1}
        port = fake_port
        direction = "fake_direction"
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_add_flows_to_sec_br'
                                  ) as mock_add_flows_sec_br:
            self.ovs_firewall._add_flow_with_range(self.mock_br, port, flow,
                                                   direction, 1, 2, 1, 2)
            mock_add_flows_sec_br.called_with(res_flow)
            self.assertEqual(4, mock_add_flows_sec_br.call_count)

    def test_add_flow_with_multiple_range(self):
        flow = {"priority": 1}
        port = fake_port
        direction = "fake_direction"
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_add_flows_to_sec_br'
                                  ) as mock_add_flows_sec_br:
            self.ovs_firewall._add_flow_with_range(self.mock_br, port, flow,
                                                   direction, 1, 3, 1, 2)
            self.assertEqual(6, mock_add_flows_sec_br.call_count)

    def test_add_flow_with_range_all_ports(self):
        flow = {"priority": 1}
        port = fake_port
        direction = "fake_direction"
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_add_flows_to_sec_br'
                                  ) as mock_add_flows_sec_br:
            self.ovs_firewall._add_flow_with_range(self.mock_br, port,
                                                   flow, direction, 1, 65535)
            self.assertEqual(1, mock_add_flows_sec_br.call_count)

    def test_add_flow_with_range_some_ports(self):
        flow = {"priority": 1}
        port = fake_port
        direction = "fake_direction"
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_add_flows_to_sec_br'
                                  ) as mock_add_flows_sec_br:
            self.ovs_firewall._add_flow_with_range(self.mock_br, port,
                                                   flow, direction, 1, 100)
            self.assertEqual(100, mock_add_flows_sec_br.call_count)

    def test_add_flows_to_sec_br_ingress_direction(self):
        flows = {}
        port = fake_port
        direction = "ingress"
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            self.ovs_firewall._add_flows_to_sec_br(self.mock_br, port,
                                                   flows, direction)
            self.assertTrue(mock_add_flow.called)
            self.assertEqual(1, mock_add_flow.call_count)

    def test_add_flows_to_sec_br_egress_direction(self):
        flows = {}
        port = fake_port
        flows['dl_src'] = '01:02:03:04:05:06'
        flows['proto'] = 'ip'
        flows['dl_vlan'] = 25
        port['fixed_ips'] = [u'70.0.0.5']
        direction = "egress"
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            self.ovs_firewall._add_flows_to_sec_br(self.mock_br, port,
                                                   flows, direction)
            self.assertTrue(mock_add_flow.called)
            self.assertEqual(2, mock_add_flow.call_count)

    def test_add_flows_to_sec_br_egress_direction_multiple_fixed_ips(self):
        flows = {}
        port = fake_port
        flows['dl_src'] = '01:02:03:04:05:06'
        flows['proto'] = 'ip'
        flows['dl_vlan'] = 25
        port['fixed_ips'] = [u'70.0.0.5', u'80.0.0.6']
        direction = "egress"
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            self.ovs_firewall._add_flows_to_sec_br(self.mock_br, port,
                                                   flows, direction)
            self.assertTrue(mock_add_flow.called)
            self.assertEqual(4, mock_add_flow.call_count)

    def test_add_flows_call_no_vlan(self):
        port_with_app = copy.deepcopy(fake_port)
        with mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                               return_value=None), \
                mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                                  return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow,\
                mock.patch.object(self.LOG, 'error') as mock_error_log:
            self.ovs_firewall._add_flows(self.mock_br, port_with_app, cookie)
            self.assertFalse(mock_add_flow.called)
            self.assertTrue(mock_error_log.called)

    def test_add_flows_call_tcp(self):
        port = copy.deepcopy(fake_port)
        with mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                               return_value=100) as mock_get_vlan, \
                mock.patch.object(self.ovs_firewall, '_get_protocol',
                                  return_value=['tcp']) as mock_get_proto, \
                mock.patch.object(self.ovs_firewall, '_add_flow_with_range'
                                  ) as mock_add_range_flows, \
                mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                                  return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow'):
            self.ovs_firewall._add_flows(self.mock_br, port, cookie)
            self.assertTrue(mock_get_vlan.called)
            self.assertTrue(mock_get_proto.called)
            self.assertTrue(mock_add_range_flows.called)

    def test_add_flows_call_normal(self):
        port = copy.deepcopy(fake_port)
        with mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                               return_value=100) as mock_get_vlan, \
                mock.patch.object(self.ovs_firewall, '_get_protocol',
                                  return_value=['ip']) as mock_get_proto, \
                mock.patch.object(self.ovs_firewall, '_add_flow_with_range'
                                  ) as mock_add_range_flows, \
                mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                                  return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'add_flow') as mock_add_flow:
            self.ovs_firewall._add_flows(self.mock_br, port, cookie)
            self.assertTrue(mock_get_vlan.called)
            self.assertTrue(mock_get_proto.called)
            self.assertFalse(mock_add_range_flows.called)
            self.assertTrue(mock_add_flow.called)

    def test_prepare_port_filter(self):
        self.ovs_firewall.provider_port_cache = set()
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_setup_aap_flows'
                                  ) as mock_aap_flow_fn, \
                mock.patch.object(self.ovs_firewall, '_add_flows'
                                  ) as mock_add_flow_fn, \
                mock.patch.object(self.mock_br, 'add_flow'):
            self.ovs_firewall.prepare_port_filter(fake_port)
            mock_aap_flow_fn.assert_called_with(self.mock_br, fake_port)
            mock_add_flow_fn.assert_called_with(self.mock_br, fake_port,
                                                cookie)
            self.assertEqual(2, mock_add_flow_fn.call_count)
            ret_port = self.ovs_firewall.filtered_ports['123']
            self.assertEqual(fake_res_port, ret_port)
            self.assertEqual(set(['123']),
                             self.ovs_firewall.provider_port_cache)

    def test_prepare_port_filter_exception(self):
        self.ovs_firewall.provider_port_cache = set()
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_setup_aap_flows',
                                  side_effect=Exception()
                                  ) as mock_aap_flow_fn, \
                mock.patch.object(self.ovs_firewall, '_add_flows'
                                  ) as mock_add_flow_fn, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_exception_log:
            self.ovs_firewall.prepare_port_filter(fake_port)
            mock_aap_flow_fn.assert_called_with(self.mock_br, fake_port)
            self.assertFalse(mock_add_flow_fn.called)
            self.assertTrue(mock_exception_log.called)
            self.assertEqual(set(), self.ovs_firewall.provider_port_cache)

    def test_remove_only_tenant_flows(self):
        self.ovs_firewall.filtered_ports["123"] = fake_res_port
        with mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                               return_value=100) as mock_get_vlan, \
                mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                                  return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'delete_flows'
                                  ) as mock_del_flows:
            self.ovs_firewall._remove_flows(self.mock_br, "123")
            self.assertTrue(mock_get_vlan.called)
            self.assertEqual(4, mock_del_flows.call_count)

    def test_remove_all_flows(self):
        self.ovs_firewall.filtered_ports["123"] = fake_res_port
        with mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                               return_value=100) as mock_get_vlan, \
                mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                                  return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'delete_flows'
                                  ) as mock_del_flows:
            self.ovs_firewall._remove_flows(self.mock_br, "123", True)
            self.assertTrue(mock_get_vlan.called)
            self.assertEqual(7, mock_del_flows.call_count)

    def test_remove_flows_invalid_port(self):
        res_port = copy.deepcopy(fake_res_port)
        res_port.pop('mac_address')
        self.ovs_firewall.filtered_ports["123"] = res_port
        with mock.patch.object(self.ovs_firewall, '_get_port_vlan',
                               return_value=100) as mock_get_vlan, \
                mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                                  return_value=self.mock_br), \
                mock.patch.object(self.mock_br, 'delete_flows'
                                  ) as mock_del_flows, \
                mock.patch.object(self.LOG, 'debug') as mock_debug_log:
            self.ovs_firewall._remove_flows(self.mock_br, "123")
            self.assertTrue(mock_get_vlan.called)
            self.assertEqual(1, mock_del_flows.call_count)
            self.assertEqual(2, mock_debug_log.call_count)

    def test_clean_port_filters(self):
        self.ovs_firewall.filtered_ports["123"] = fake_res_port
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_remove_flows'
                                  ) as mock_rem_flow:
            self.ovs_firewall.clean_port_filters(["123"])
            mock_rem_flow.assert_called_with(self.mock_br, "123")
            self.assertIn("123", self.ovs_firewall.filtered_ports)

    def test_clean_port_filters_remove_port(self):
        self.ovs_firewall.filtered_ports["123"] = fake_res_port
        self.ovs_firewall.provider_port_cache = set(['123'])
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_remove_flows'
                                  ) as mock_rem_flow:
            self.ovs_firewall.clean_port_filters(["123"], True)
            mock_rem_flow.assert_called_with(self.mock_br, "123", True)
            self.assertNotIn("123", self.ovs_firewall.filtered_ports)
            self.assertNotIn("123", self.ovs_firewall.provider_port_cache)

    def test_clean_port_filters_exception(self):
        self.ovs_firewall.filtered_ports["123"] = fake_res_port
        self.ovs_firewall.provider_port_cache = set(['123'])
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_remove_flows',
                                  side_effect=Exception()
                                  ) as mock_rem_flow, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_exception_log:
            self.ovs_firewall.clean_port_filters(["123"], True)
            mock_rem_flow.assert_called_with(self.mock_br, "123", True)
            self.assertTrue(mock_exception_log.called)
            self.assertIn("123", self.ovs_firewall.provider_port_cache)
            self.assertIn("123", self.ovs_firewall.filtered_ports)

    def test_normal_update_port_filters(self):
        self.ovs_firewall.filtered_ports["123"] = fake_res_port
        self.ovs_firewall.provider_port_cache = set(['123'])
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_remove_flows'
                                  ) as mock_rem_flow, \
                mock.patch.object(self.ovs_firewall, '_setup_aap_flows'
                                  ) as mock_aap_flow_fn, \
                mock.patch.object(self.ovs_firewall, '_add_flows'
                                  ) as mock_add_flow_fn:
            self.ovs_firewall.update_port_filter(fake_port)
            mock_rem_flow.assert_called_with(self.mock_br, "123")
            mock_aap_flow_fn.assert_called_with(self.mock_br, fake_port)
            mock_add_flow_fn.assert_called_with(self.mock_br, fake_port,
                                                cookie)
            self.assertEqual(1, mock_add_flow_fn.call_count)
            self.assertIn("123", self.ovs_firewall.filtered_ports)

    def test_update_port_filters_for_provider_update(self):
        self.ovs_firewall.filtered_ports["123"] = fake_res_port
        self.ovs_firewall.provider_port_cache = set()
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_remove_flows'
                                  ) as mock_rem_flow, \
                mock.patch.object(self.ovs_firewall, '_setup_aap_flows'
                                  ) as mock_aap_flow_fn, \
                mock.patch.object(self.ovs_firewall, '_add_flows'
                                  ) as mock_add_flow_fn:
            self.ovs_firewall.update_port_filter(fake_port)
            mock_rem_flow.assert_called_with(self.mock_br, "123", True)
            mock_aap_flow_fn.assert_called_with(self.mock_br, fake_port)
            mock_add_flow_fn.assert_called_with(self.mock_br, fake_port,
                                                cookie)
            self.assertEqual(2, mock_add_flow_fn.call_count)
            self.assertIn("123", self.ovs_firewall.filtered_ports)
            self.assertIn("123", self.ovs_firewall.provider_port_cache)

    def test_update_port_filters_exception(self):
        self.ovs_firewall.filtered_ports["123"] = fake_res_port
        self.ovs_firewall.provider_port_cache = set(['123'])
        with mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                               return_value=self.mock_br), \
                mock.patch.object(self.ovs_firewall, '_remove_flows',
                                  side_effect=Exception()) as mock_rem_flow, \
                mock.patch.object(self.ovs_firewall, '_add_flows'
                                  ) as mock_add_flow_fn, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_exception_log:
            self.ovs_firewall.update_port_filter(fake_port)
            mock_rem_flow.assert_called_with(self.mock_br, "123")
            self.assertFalse(mock_add_flow_fn.called)
            self.assertIn("123", self.ovs_firewall.filtered_ports)
            self.assertTrue(mock_exception_log.called)

    def test_ovs_firewall_restart_with_canary_flow(self):

        flow = "cookie=0x0, duration=4633.482s, table=23, n_packets=0" + \
               "n_bytes=0, idle_age=4633, priority=0 actions=drop"
        with mock.patch.object(self.ovs_firewall.sg_br,
                               "dump_flows_for_table",
                               return_value=flow) as mock_dump_flow:
            canary_flow = self.ovs_firewall.check_ovs_firewall_restart()
            self.assertTrue(mock_dump_flow.called)
            self.assertTrue(canary_flow)

    def test_ovs_firewall_restart_without_canary_flow(self):

        flow = ""
        with mock.patch.object(self.ovs_firewall.sg_br,
                               "dump_flows_for_table",
                               return_value=flow) as mock_dump_flow:
            canary_flow = self.ovs_firewall.check_ovs_firewall_restart()
            self.assertTrue(mock_dump_flow.called)
            self.assertFalse(canary_flow)
