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
from oslo.config import cfg

import contextlib
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
