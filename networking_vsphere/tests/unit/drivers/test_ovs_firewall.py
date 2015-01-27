# Copyright (c) 2012 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#F
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import contextlib
import mock
from neutron.common import constants
from neutron.plugins.ovsvapp.drivers import ovs_firewall as ovs_fw
from neutron.tests import base
from oslo.config import cfg
import threading

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


class TestOVSFirewallDriver(base.BaseTestCase):
    def setUp(self):
        super(TestOVSFirewallDriver, self).setUp()
        cfg.CONF.set_override('security_bridge',
                              "br-fake:fake_if", 'SECURITYGROUP')
        with contextlib.nested(
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'get_port_ofport'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.__init__'),
            mock.patch('neutron.plugins.ovsvapp.agent.portCache'),
            mock.patch('neutron.plugins.ovsvapp.drivers.ovs_firewall.'
                       'OVSFirewallDriver.setup_base_flows')
                  ):
            self.ovs_firewall = ovs_fw.OVSFirewallDriver()
            self.ovs_firewall.sg_br = mock.Mock()

    def test_add_ovs_flow(self):
        mock_add_flow = mock.patch('neutron.agent.linux.ovs_lib.'
                                   'DeferredOVSBridge.add_flow')
        mock_br = mock.patch('neutron.agent.linux.ovs_lib.'
                             'DeferredOVSBridge')
        #simple rule
        self.ovs_firewall._add_ovs_flow(mock_br, 0, 1, "normal")
        mock_add_flow.assert_called_with(table=1, priority=0,
                                         actions="normal")
        #rule with protocol
        self.ovs_firewall._add_ovs_flow(mock_br, 0, 1, "normal",
                                        protocol="arp")
        mock_add_flow.assert_called_with(table=1, priority=0,
                                         proto="arp",actions="normal")
        #rule with dl_dest
        dest_mac = "01:00:00:00:00:00"
        self.ovs_firewall._add_ovs_flow(mock_br, 0, 1, "normal",
                                        dl_dest=dest_mac)
        mock_add_flow.assert_called_with(table=1, priority=0,
                                         dl_dst=dest_mac, actions="normal")
        #rule with tcp_flags
        t_flag = "+rst"
        self.ovs_firewall._add_ovs_flow(mock_br, 0, 1, "normal",
                                        tcp_flag=t_flag)
        mock_add_flow.assert_called_with(table=1, priority=0,
                                         proto=constants.PROTO_NAME_TCP,
                                         tcp_flags=t_flag,actions="normal")
        #rule with icmp_req_type
        self.ovs_firewall._add_ovs_flow(mock_br, 0, 1, "normal",
                                        icmp_req_type=11)
        mock_add_flow.assert_called_with(table=1, priority=0,
                                         proto=constants.PROTO_NAME_ICMP,
                                         icmp_type=11,actions="normal")

    def test_get_compact_port(self):
        compact_port = {'security_group_source_groups': 'abc',
                        'mac_address': '00:11:22:33:44:55',
                        'network_id': "netid",
                        'id': "123",
                        'security_groups': "abc",
                        'segmentation_id': "100"}
        res = self.ovs_firewall._get_compact_port(fake_port)
        self.assertEqual(res, compact_port)

    def test_setup_base_flows(self):
        mock_add_flow = mock.patch('neutron.agent.linux.ovs_lib.'
                                   'DeferredOVSBridge.add_flow')
        mock_br = mock.patch('neutron.agent.linux.ovs_lib.'
                             'DeferredOVSBridge')
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              return_value=mock_br),
            mock.patch.object(self.ovs_firewall.sg_br, 'do_action_flows'),
            mock.patch.object(self.ovs_firewall, '_add_ovs_flows'),
            mock.patch.object(self.ovs_firewall, '_setup_learning_flows')
        ) as (deferred_fn, do_action_flows_fn, add_ovs_flow_fn,
              setup_learn_flows_fn):
            self.ovs_firewall.setup_base_flows()
            self.assertTrue(mock_add_flow.called)
            self.assertTrue(deferred_fn.called)
            self.assertEqual(add_ovs_flow_fn.call_count, 8)
            self.assertTrue(setup_learn_flows_fn.called)
            setup_learn_flows_fn.assert_called_with(mock_br)
