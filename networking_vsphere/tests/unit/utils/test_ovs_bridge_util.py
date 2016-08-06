# Copyright (c) 2016 Hewlett-Packard Development Company, L.P.
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

from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants as ovs_const  # noqa

from networking_vsphere.tests import base
from networking_vsphere.utils import ovs_bridge_util as ovsvapp_br

FAKE_LVID = 10
FAKE_SEG_ID = 2000
FAKE_MAC_ADDRESS = "11:22:33:44:55:66"
FAKE_SEC_OFPORT = 2
FAKE_INT_OFPORT = 3
FAKE_TUN_OFPORT = 4
FAKE_PHY_OFPORT = 5
FAKE_ETH_OFPORT = 6


class TestOVSvAppIntegrationBridge(base.TestCase):

    @mock.patch('neutron.agent.ovsdb.api.'
                'API.get')
    def setUp(self, mock_ovsdb_api):
        super(TestOVSvAppIntegrationBridge, self).setUp()
        self.int_br = ovsvapp_br.OVSvAppIntegrationBridge("br-int")

    def test_provision_local_vlan_vlan(self):
        with mock.patch.object(self.int_br, "add_flow") as mock_add_flow:
            self.int_br.provision_local_vlan(p_const.TYPE_VLAN,
                                             FAKE_LVID,
                                             FAKE_SEG_ID,
                                             FAKE_SEC_OFPORT,
                                             FAKE_INT_OFPORT,
                                             FAKE_TUN_OFPORT)
            self.assertTrue(mock_add_flow.called)
            self.assertEqual(mock_add_flow.call_count, 2)
            mock_add_flow.assert_any_call(priority=4,
                                          in_port=FAKE_SEC_OFPORT,
                                          dl_vlan=FAKE_LVID,
                                          actions="output:%s"
                                          % FAKE_INT_OFPORT)

    def test_provision_local_vlan_vxlan(self):
        with mock.patch.object(self.int_br, "add_flow") as mock_add_flow:
            self.int_br.provision_local_vlan(p_const.TYPE_VXLAN,
                                             FAKE_LVID,
                                             FAKE_SEG_ID,
                                             FAKE_SEC_OFPORT,
                                             FAKE_INT_OFPORT,
                                             FAKE_TUN_OFPORT)
            self.assertTrue(mock_add_flow.called)
            self.assertEqual(mock_add_flow.call_count, 1)
            mock_add_flow.assert_called_once_with(priority=4,
                                                  in_port=FAKE_SEC_OFPORT,
                                                  dl_vlan=FAKE_LVID,
                                                  actions="output:%s"
                                                  % FAKE_TUN_OFPORT)

    def test_reclaim_local_vlan_vlan(self):
        with mock.patch.object(self.int_br, "delete_flows") as mock_del_flow:
            self.int_br.reclaim_local_vlan(p_const.TYPE_VLAN,
                                           FAKE_SEG_ID,
                                           FAKE_LVID,
                                           FAKE_INT_OFPORT,
                                           FAKE_SEC_OFPORT)
            self.assertTrue(mock_del_flow.called)
            self.assertEqual(mock_del_flow.call_count, 2)
            mock_del_flow.assert_any_call(dl_vlan=FAKE_SEG_ID,
                                          in_port=FAKE_INT_OFPORT)

    def test_reclaim_local_vlan_vxlan(self):
        with mock.patch.object(self.int_br, "delete_flows") as mock_del_flow:
            self.int_br.reclaim_local_vlan(p_const.TYPE_VXLAN,
                                           FAKE_SEG_ID,
                                           FAKE_LVID,
                                           FAKE_INT_OFPORT,
                                           FAKE_SEC_OFPORT)
            self.assertTrue(mock_del_flow.called)
            mock_del_flow.assert_called_once_with(dl_vlan=FAKE_LVID,
                                                  in_port=FAKE_SEC_OFPORT)


class TestOVSvAppPhysicalBridge(base.TestCase):

    @mock.patch('neutron.agent.ovsdb.api.'
                'API.get')
    def setUp(self, mock_ovsdb_api):
        super(TestOVSvAppPhysicalBridge, self).setUp()
        self.br = ovsvapp_br.OVSvAppPhysicalBridge("br-phy")

    def test_provision_local_vlan(self):
        with mock.patch.object(self.br, "add_flow") as mock_add_flow:
            self.br.provision_local_vlan(FAKE_LVID,
                                         FAKE_SEG_ID,
                                         FAKE_PHY_OFPORT,
                                         FAKE_ETH_OFPORT)
            self.assertTrue(mock_add_flow.called)
            mock_add_flow.assert_called_once_with(
                priority=4,
                in_port=FAKE_PHY_OFPORT,
                dl_vlan=FAKE_LVID,
                actions="mod_vlan_vid:%s,output:%s"
                % (FAKE_SEG_ID, FAKE_ETH_OFPORT))

    def test_reclaim_local_vlan(self):
        with mock.patch.object(self.br, "delete_flows") as mock_delete_flow:
            self.br.reclaim_local_vlan(FAKE_LVID)
            self.assertTrue(mock_delete_flow.called)
            mock_delete_flow.assert_called_once_with(dl_vlan=FAKE_LVID)

    def test_add_drop_flows(self):
        with mock.patch.object(self.br, "add_flow") as mock_add_flow:
            self.br.add_drop_flows(FAKE_LVID,
                                   FAKE_MAC_ADDRESS,
                                   FAKE_ETH_OFPORT)
            self.assertTrue(mock_add_flow.called)
            mock_add_flow.assert_called_once_with(priority=4,
                                                  in_port=FAKE_ETH_OFPORT,
                                                  dl_vlan=FAKE_LVID,
                                                  dl_src=FAKE_MAC_ADDRESS,
                                                  actions="drop")

    def test_delete_drop_flows(self):
        with mock.patch.object(self.br, "delete_flows") as mock_delete_flow:
            self.br.delete_drop_flows(FAKE_MAC_ADDRESS, FAKE_LVID)
            self.assertTrue(mock_delete_flow.called)
            mock_delete_flow.assert_called_once_with(dl_vlan=FAKE_LVID,
                                                     dl_src=FAKE_MAC_ADDRESS)


class TestOVSvAppTunnelBridge(base.TestCase):

    @mock.patch('neutron.agent.ovsdb.api.'
                'API.get')
    def setUp(self, mock_ovsdb_api):
        super(TestOVSvAppTunnelBridge, self).setUp()
        self.tun_br = ovsvapp_br.OVSvAppTunnelBridge("br-tun")

    def test_provision_local_vlan(self):
        with mock.patch.object(self.tun_br, "add_flow") as mock_add_flow:
            self.tun_br.provision_local_vlan(FAKE_LVID,
                                             FAKE_SEG_ID,
                                             FAKE_TUN_OFPORT)
            self.assertEqual(mock_add_flow.call_count, 2)
            mock_add_flow.assert_called_with(
                table=ovs_const.TUN_TABLE[p_const.TYPE_VXLAN],
                priority=1,
                tun_id=FAKE_SEG_ID,
                actions="mod_vlan_vid:%s,resubmit(,%s)" %
                (FAKE_LVID, ovs_const.LEARN_FROM_TUN))

    def test_reclaim_local_vlan(self):
        with mock.patch.object(self.tun_br, "delete_flows") as mock_del_flow:
            self.tun_br.reclaim_local_vlan(FAKE_SEG_ID, FAKE_LVID)
            self.assertTrue(mock_del_flow.called)
            self.assertEqual(mock_del_flow.call_count, 2)
            mock_del_flow.assert_any_call(dl_vlan=FAKE_LVID)
