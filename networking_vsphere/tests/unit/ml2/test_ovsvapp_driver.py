# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
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

from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base

from networking_vsphere.ml2 import ovsvapp_driver

network = {'id': 'net_id'}

net_info = {'vcenter_id': 'fake_vcenter',
            'cluster_id': 'fake_cluster',
            'network_id': 'net_id',
            'segmentation_id': 1234,
            'lvid': 1}

net_info_with_host = {'vcenter_id': 'fake_vcenter',
                      'cluster_id': 'fake_cluster',
                      'network_id': 'net_id',
                      'host': 'fake_host',
                      'segmentation_id': 1234,
                      'lvid': 1}

fake_agent = {'configurations': {'vcenter': 'fake_vcenter',
                                 'cluster_id': 'fake_cluster'},
              'host': 'fake_host'}

compute_port = {'id': 'fake_id',
                'device_owner': 'compute-nova',
                'network_id': 'net_id',
                portbindings.HOST_ID: 'fake_host'}

dhcp_port = {'id': 'fake_id',
             'device_owner': 'network_dhcp',
             'network_id': 'net_id',
             portbindings.HOST_ID: 'fake_host'}

vlan_segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN}

vxlan_segment = {api.NETWORK_TYPE: p_const.TYPE_VXLAN,
                 api.SEGMENTATION_ID: 1234}


class FakeContext():

    def __init__(self, current, bound_segment):
        self.current = current
        self.bound_segment = bound_segment

    @property
    def network_segments(self):
        return [self.bound_segment]


class FakePlugin():

    def get_agents(self):
        return


class OVSvAppAgentDriverTestCase(base.AgentMechanismBaseTestCase):

    def setUp(self):
        super(OVSvAppAgentDriverTestCase, self).setUp()
        self.driver = ovsvapp_driver.OVSvAppAgentDriver()
        self.driver.initialize()
        self.driver._plugin = FakePlugin()

    @mock.patch('networking_vsphere.db.ovsvapp_db.check_to_reclaim_local_vlan')
    @mock.patch('networking_vsphere.db.ovsvapp_db.release_local_vlan')
    def test_notify_agent_without_host(self, mock_release_local_vlan,
                                       mock_check_to_reclaim_local_vlan):
        mock_check_to_reclaim_local_vlan.return_value = 1
        with mock.patch.object(self.driver,
                               '_get_ovsvapp_agent_from_cluster',
                               return_value=fake_agent) as mock_get_agent, \
                mock.patch.object(self.driver.notifier,
                                  'device_delete', return_value=True
                                  ) as mock_device_delete_rpc:
            self.driver._notify_agent(net_info)
            self.assertTrue(mock_get_agent.called)
            self.assertFalse(mock_check_to_reclaim_local_vlan.called)
            self.assertTrue(mock_device_delete_rpc.called)
            self.assertFalse(mock_release_local_vlan.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.check_to_reclaim_local_vlan')
    @mock.patch('networking_vsphere.db.ovsvapp_db.release_local_vlan')
    def test_notify_agent_without_host_no_agent(self, mock_release_local_vlan,
                                                check_to_reclaim_local_vlan):
        with mock.patch.object(self.driver,
                               '_get_ovsvapp_agent_from_cluster',
                               return_value=None) as mock_get_agent:
            self.driver._notify_agent(net_info)
            self.assertTrue(mock_get_agent.called)
            self.assertFalse(check_to_reclaim_local_vlan.called)
            self.assertFalse(mock_release_local_vlan.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('networking_vsphere.db.ovsvapp_db.release_local_vlan')
    def test_notify_agent_without_host_rpc_failed(self,
                                                  mock_release_local_vlan,
                                                  mock_reclaim_local_vlan):
        with mock.patch.object(self.driver,
                               '_get_ovsvapp_agent_from_cluster',
                               return_value=fake_agent) as mock_get_agent, \
                mock.patch.object(self.driver.notifier, 'device_delete',
                                  return_value=False
                                  ) as mock_device_delete_rpc:
            mock_reclaim_local_vlan.return_value = 1
            self.driver._notify_agent(net_info)
            self.assertTrue(mock_get_agent.called)
            self.assertFalse(mock_reclaim_local_vlan.called)
            self.assertTrue(mock_device_delete_rpc.called)
            self.assertFalse(mock_release_local_vlan.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('networking_vsphere.db.ovsvapp_db.release_local_vlan')
    def test_notify_agent_with_host(self, mock_release_local_vlan,
                                    mock_check_to_reclaim_local_vlan):
        with mock.patch.object(self.driver.notifier,
                               'device_delete', return_value=True
                               ) as mock_device_delete_rpc:
            mock_check_to_reclaim_local_vlan.return_value = 1
            self.driver._notify_agent(net_info_with_host)
            self.assertFalse(mock_check_to_reclaim_local_vlan.called)
            self.assertTrue(mock_device_delete_rpc.called)
            self.assertFalse(mock_release_local_vlan.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_vlan_port(self, mock_spawn_thread,
                                              mock_reclaim_local_vlan):
        port_context = FakeContext(compute_port, vlan_segment)
        mock_reclaim_local_vlan.return_value = 1
        with mock.patch.object(self.driver._plugin, 'get_agents'
                               ) as mock_get_agents:
            self.driver.delete_port_postcommit(port_context)
            self.assertFalse(mock_get_agents.called)
            self.assertFalse(mock_reclaim_local_vlan.called)
            self.assertFalse(mock_spawn_thread.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_dhcp_port(self, mock_spawn_thread,
                                              mock_reclaim_local_vlan):
        port_context = FakeContext(dhcp_port, vlan_segment)
        mock_reclaim_local_vlan.return_value = 1
        with mock.patch.object(self.driver._plugin, 'get_agents',
                               return_value=[fake_agent]) as mock_get_agents:
            self.driver.delete_port_postcommit(port_context)
            self.assertFalse(mock_get_agents.called)
            self.assertFalse(mock_reclaim_local_vlan.called)
            self.assertFalse(mock_spawn_thread.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_vxlan_port_release_not_required(
            self, mock_spawn_thread, mock_check_to_reclaim_local_vlan):
        port_context = FakeContext(compute_port, vxlan_segment)
        mock_check_to_reclaim_local_vlan.return_value = -1
        with mock.patch.object(self.driver._plugin, 'get_agents',
                               return_value=[fake_agent]) as mock_get_agents:
            self.driver.delete_port_postcommit(port_context)
            self.assertTrue(mock_get_agents.called)
            self.assertTrue(mock_check_to_reclaim_local_vlan.called)
            self.assertFalse(mock_spawn_thread.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_vxlan_port_release_required(
            self, mock_spawn_thread, mock_check_to_reclaim_local_vlan):
        port_context = FakeContext(compute_port, vxlan_segment)
        mock_check_to_reclaim_local_vlan.return_value = True
        with mock.patch.object(self.driver._plugin, 'get_agents',
                               return_value=[fake_agent]) as mock_get_agents:
            self.driver.delete_port_postcommit(port_context)
            self.assertTrue(mock_get_agents.called)
            self.assertTrue(mock_check_to_reclaim_local_vlan.called)
            self.assertTrue(mock_spawn_thread.called)
            mock_spawn_thread.assert_called_with(
                self.driver._notify_agent, net_info_with_host)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'get_stale_local_vlans_for_network')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_network_postcommit_no_stale(self, mock_spawn_thread,
                                                mock_get_stale_entries):
        net_context = FakeContext(network, vxlan_segment)
        mock_get_stale_entries.return_value = []
        self.driver.delete_network_postcommit(net_context)
        self.assertTrue(mock_get_stale_entries.called)
        mock_get_stale_entries.assert_called_with('net_id')
        self.assertFalse(mock_spawn_thread.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'get_stale_local_vlans_for_network')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_network_postcommit(self, mock_spawn_thread,
                                       mock_get_stale_entries):
        net_context = FakeContext(network, vxlan_segment)
        ret_val = [('fake_vcenter', 'fake_cluster_1', 1),
                   ('fake_vcenter', 'fake_cluster', 1)]
        mock_get_stale_entries.return_value = ret_val
        self.driver.delete_network_postcommit(net_context)
        self.assertTrue(mock_get_stale_entries.called)
        mock_get_stale_entries.assert_called_with('net_id')
        self.assertTrue(mock_spawn_thread.called)
        self.assertEqual(2, mock_spawn_thread.call_count)
        mock_spawn_thread.assert_called_with(
            self.driver._notify_agent, net_info)
