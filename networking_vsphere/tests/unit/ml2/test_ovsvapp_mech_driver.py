# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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
#
# Unit test for OVSvApp Mechanism Driver.

import mock

from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base
# TODO(romilg): Revisit to minimize dependency on ML2 tests.

from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.ml2 import ovsvapp_mech_driver


network = {'id': 'net_id'}

net_info = {'vcenter_id': 'fake_vcenter',
            'cluster_id': 'fake_cluster',
            'network_id': 'net_id',
            'segmentation_id': 1234,
            'network_type': 'vxlan',
            'lvid': 1}

net_info_with_host = {'vcenter_id': 'fake_vcenter',
                      'cluster_id': 'fake_cluster',
                      'network_id': 'net_id',
                      'host': 'fake_host',
                      'segmentation_id': 1234,
                      'network_type': 'vxlan',
                      'lvid': 1}

fake_agent = {'configurations': {'vcenter_id': 'fake_vcenter',
                                 'cluster_id': 'fake_cluster'},
              'host': 'fake_host'}

compute_port = {'id': 'fake_id',
                'device_owner': 'compute:nova',
                'network_id': 'net_id',
                portbindings.HOST_ID: 'fake_host'}

dhcp_port = {'id': 'fake_id',
             'device_owner': 'network:dhcp',
             'network_id': 'net_id',
             portbindings.HOST_ID: 'fake_host'}

router_port_ipv4 = {'id': 'fake_id',
                    'device_owner': 'network:router_interface',
                    'network_id': 'net_id',
                    'fixed_ips': [{'ip_address': '10.10.10.1'}]}

router_port_ipv6 = {'id': 'fake_id',
                    'device_owner': 'network:router_interface',
                    'network_id': 'net_id',
                    'fixed_ips': [{'ip_address': 'FE80::0202:B3FF:FE1E:8329'}]}

vlan_segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                api.SEGMENTATION_ID: 1234}

vxlan_segment = {api.NETWORK_TYPE: p_const.TYPE_VXLAN,
                 api.SEGMENTATION_ID: 1234}


class FakeContext(object):

    def __init__(self, current, segment=None):
        self.current = current
        self.top_bound_segment = segment

    @property
    def network_segments(self):
        return [self.top_bound_segment]


class FakePlugin(object):

    def get_agents(self):
        return


class OVSvAppAgentMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OTHER
    CAP_PORT_FILTER = True
    AGENT_TYPE = ovsvapp_const.AGENT_TYPE_OVSVAPP

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}
    GOOD_TUNNEL_TYPES = ['vxlan']
    GOOD_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'tunnel_types': GOOD_TUNNEL_TYPES}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_bridge'}
    BAD_TUNNEL_TYPES = ['bad_tunnel_type']
    BAD_CONFIGS = {'bridge_mappings': BAD_MAPPINGS,
                   'tunnel_types': BAD_TUNNEL_TYPES}

    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS,
               'host': 'host'}]
    AGENTS_DEAD = [{'alive': False,
                    'configurations': GOOD_CONFIGS,
                    'host': 'dead_host'}]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS,
                   'host': 'bad_host_1'},
                  {'alive': True,
                   'configurations': BAD_CONFIGS,
                   'host': 'bad_host_2'}]

    def setUp(self):
        super(OVSvAppAgentMechanismBaseTestCase, self).setUp()
        self.driver = ovsvapp_mech_driver.OVSvAppAgentMechanismDriver()
        self.driver._plugin = FakePlugin()

    @mock.patch('networking_vsphere.db.ovsvapp_db.check_to_reclaim_local_vlan')
    @mock.patch('networking_vsphere.db.ovsvapp_db.release_local_vlan')
    def test_notify_agent_without_host(self, mock_release_local_vlan,
                                       mock_reclaim_local_vlan):
        mock_reclaim_local_vlan.return_value = 1
        with mock.patch.object(self.driver,
                               '_get_ovsvapp_agent_from_cluster',
                               return_value=fake_agent) as mock_get_agent, \
                mock.patch.object(self.driver.notifier,
                                  'device_delete', return_value=True
                                  ) as mock_device_delete_rpc:
            self.driver._notify_agent(net_info)
            self.assertTrue(mock_get_agent.called)
            self.assertFalse(mock_reclaim_local_vlan.called)
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
                                    mock_reclaim_local_vlan):
        with mock.patch.object(self.driver.notifier,
                               'device_delete', return_value=True
                               ) as mock_device_delete_rpc:
            mock_reclaim_local_vlan.return_value = 1
            self.driver._notify_agent(net_info_with_host)
            self.assertFalse(mock_reclaim_local_vlan.called)
            self.assertTrue(mock_device_delete_rpc.called)
            self.assertFalse(mock_release_local_vlan.called)

    def test_create_port_postcommit_dhcp_port(self):
        port_context = FakeContext(dhcp_port, vlan_segment)
        with mock.patch.object(self.driver.notifier,
                               'enhanced_sg_provider_updated'
                               ) as mock_sg_provider_updated_rpc:
            self.driver.create_port_postcommit(port_context)
            self.assertTrue(mock_sg_provider_updated_rpc.called)
            mock_sg_provider_updated_rpc.assert_called_with(
                self.driver.context, dhcp_port['network_id'])

    def test_create_port_postcommit_ipv6_router_port(self):
        port_context = FakeContext(router_port_ipv6)
        with mock.patch.object(self.driver.notifier,
                               'enhanced_sg_provider_updated'
                               ) as mock_sg_provider_updated_rpc:
            self.driver.create_port_postcommit(port_context)
            self.assertTrue(mock_sg_provider_updated_rpc.called)
            mock_sg_provider_updated_rpc.assert_called_with(
                self.driver.context, router_port_ipv6['network_id'])

    def test_create_port_postcommit_ipv4_router_port(self):
        port_context = FakeContext(router_port_ipv4)
        with mock.patch.object(self.driver.notifier,
                               'enhanced_sg_provider_updated'
                               ) as mock_sg_provider_updated_rpc:
            self.driver.create_port_postcommit(port_context)
            self.assertFalse(mock_sg_provider_updated_rpc.called)

    def test_create_port_postcommit_compute_port(self):
        port_context = FakeContext(compute_port, vlan_segment)
        with mock.patch.object(self.driver.notifier,
                               'enhanced_sg_provider_updated'
                               ) as mock_sg_provider_updated_rpc:
            self.driver.create_port_postcommit(port_context)
            self.assertFalse(mock_sg_provider_updated_rpc.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_vlan_port(self, mock_spawn_thread,
                                              mock_reclaim_local_vlan):
        port_context = FakeContext(compute_port, vlan_segment)
        mock_reclaim_local_vlan.return_value = 1
        with mock.patch.object(self.driver._plugin, 'get_agents'
                               ) as mock_get_agents, \
                mock.patch.object(self.driver.notifier,
                                  'enhanced_sg_provider_updated'
                                  ) as mock_sg_provider_updated_rpc:
            self.driver.delete_port_postcommit(port_context)
            self.assertTrue(mock_get_agents.called)
            self.assertTrue(mock_reclaim_local_vlan.called)
            self.assertTrue(mock_spawn_thread.called)
            self.assertFalse(mock_sg_provider_updated_rpc.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_dhcp_port(self, mock_spawn_thread,
                                              mock_reclaim_local_vlan):
        port_context = FakeContext(dhcp_port, vlan_segment)
        mock_reclaim_local_vlan.return_value = 1
        with mock.patch.object(self.driver._plugin, 'get_agents',
                               return_value=[fake_agent]) as mock_get_agents, \
                mock.patch.object(self.driver.notifier,
                                  'enhanced_sg_provider_updated'
                                  ) as mock_sg_provider_updated_rpc:
            self.driver.delete_port_postcommit(port_context)
            self.assertFalse(mock_get_agents.called)
            self.assertFalse(mock_reclaim_local_vlan.called)
            self.assertFalse(mock_spawn_thread.called)
            self.assertTrue(mock_sg_provider_updated_rpc.called)
            mock_sg_provider_updated_rpc.assert_called_with(
                self.driver.context, dhcp_port['network_id'])

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_vxlan_port_release_not_required(
            self, mock_spawn_thread, mock_reclaim_local_vlan):
        port_context = FakeContext(compute_port, vxlan_segment)
        mock_reclaim_local_vlan.return_value = -1
        with mock.patch.object(self.driver._plugin, 'get_agents',
                               return_value=[fake_agent]) as mock_get_agents:
            self.driver.delete_port_postcommit(port_context)
            self.assertTrue(mock_get_agents.called)
            self.assertTrue(mock_reclaim_local_vlan.called)
            self.assertFalse(mock_spawn_thread.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_vxlan_port_release_required(
            self, mock_spawn_thread, mock_reclaim_local_vlan):
        port_context = FakeContext(compute_port, vxlan_segment)
        mock_reclaim_local_vlan.return_value = True
        with mock.patch.object(self.driver._plugin, 'get_agents',
                               return_value=[fake_agent]) as mock_get_agents:
            self.driver.delete_port_postcommit(port_context)
            self.assertTrue(mock_get_agents.called)
            self.assertTrue(mock_reclaim_local_vlan.called)
            self.assertTrue(mock_spawn_thread.called)
            mock_spawn_thread.assert_called_with(
                self.driver._notify_agent, net_info_with_host)

    @mock.patch('networking_vsphere.db.ovsvapp_db.'
                'check_to_reclaim_local_vlan')
    @mock.patch('eventlet.GreenPool.spawn_n')
    def test_delete_port_postcommit_vxlan_invalid_port(
            self, mock_spawn_thread, mock_reclaim_local_vlan):
        port_context = FakeContext(compute_port, vxlan_segment)
        mock_reclaim_local_vlan.return_value = 1
        with mock.patch.object(self.driver._plugin, 'get_agents',
                               return_value=None) as mock_get_agents:
            self.driver.delete_port_postcommit(port_context)
            self.assertTrue(mock_get_agents.called)
            self.assertFalse(mock_reclaim_local_vlan.called)
            self.assertFalse(mock_spawn_thread.called)

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


class OVSvAppAgentMechanismGenericTestCase(
    OVSvAppAgentMechanismBaseTestCase,
    base.AgentMechanismGenericTestCase):
    pass


class OVSvAppAgentMechanismVlanTestCase(
    OVSvAppAgentMechanismBaseTestCase,
    base.AgentMechanismVlanTestCase):
    pass


class OVSvAppAgentMechanismVxlanTestCase(
    OVSvAppAgentMechanismBaseTestCase,
    base.AgentMechanismBaseTestCase):
    VXLAN_SEGMENTS = [{api.ID: 'unknown_segment_id',
                       api.NETWORK_TYPE: 'no_such_type'},
                      {api.ID: 'vxlan_segment_id',
                       api.NETWORK_TYPE: 'vxlan',
                       api.SEGMENTATION_ID: 1234}]

    def test_type_vxlan(self):
        context = base.FakePortContext(self.AGENT_TYPE,
                                       self.AGENTS,
                                       self.VXLAN_SEGMENTS)
        self.driver.bind_port(context)
        self._check_bound(context, self.VXLAN_SEGMENTS[1])

    def test_type_vxlan_bad(self):
        context = base.FakePortContext(self.AGENT_TYPE,
                                       self.AGENTS_BAD,
                                       self.VXLAN_SEGMENTS)
        self.driver.bind_port(context)
        self._check_unbound(context)
