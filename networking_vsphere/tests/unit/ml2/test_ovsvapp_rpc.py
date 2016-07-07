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

import collections

import mock
from oslo_config import cfg

from neutron.common import topics
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import rpc as plugin_rpc
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base
from neutron.tests.unit.plugins.ml2 import test_rpc

from networking_vsphere.agent import ovsvapp_agent
from networking_vsphere.agent import ovsvapp_sg_agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.ml2 import ovsvapp_rpc

from sqlalchemy.orm import exc as sa_exc

cfg.CONF.import_group('ml2', 'neutron.plugins.ml2.config')

FAKE_CLUSTER_ID = 'fake_cluster_id'
FAKE_VCENTER = 'fake_vcenter'
FAKE_HOST = 'fake_host'
FAKE_AGENT_ID = 'fake_agent_id'
FAKE_PORT_ID = 'fake_port_id'
FAKE_NETWORK_ID = "fake_network_id"
FAKE_SUBNET_ID = "fake_subnet_id"
FAKE_DEVICE_OWNER = "fake_device_owner"
FAKE_DEVICE_1 = 'fake_device_1'
FAKE_DEVICE_2 = 'fake_device_2'
FAKE_MAC_ADDRESS = 'fake_mac_address'
FAKE_IP_ADDRESS = 'fake_ip_address'
FAKE_SECURITY_GROUP = 'fake_grouop_id'


class TestFakePortContext(base.FakePortContext):
    VIF_TYPE = portbindings.VIF_TYPE_OTHER
    VIF_DETAILS = {portbindings.CAP_PORT_FILTER: True}
    AGENT_TYPE = ovsvapp_const.AGENT_TYPE_OVSVAPP

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}
    GOOD_TUNNEL_TYPES = ['vxlan']
    GOOD_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'tunnel_types': GOOD_TUNNEL_TYPES}
    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS}]

    def __init__(self, port, segments=None):
        agent_type = self.AGENT_TYPE
        agents = self.AGENTS
        vnic_type = portbindings.VNIC_NORMAL
        super(TestFakePortContext, self).__init__(agent_type,
                                                  agents,
                                                  segments,
                                                  vnic_type)
        if segments:
            self._bound_segment_id = segments[0].get(api.ID)
            self._bound_vif_type = 'other'
            self._bound_segment = segments[0]

        self._bound_segment = None
        self._port = port
        self._segments = segments

    @property
    def current(self):
        return self._port

    @property
    def status(self):
        return 'ACTIVE'

    @property
    def top_bound_segment(self):
        if self._segments:
            return self._expand_segment(self._bound_segment)


class OVSvAppServerRpcCallbackTest(test_rpc.RpcCallbacksTestCase):

    def setUp(self):
        super(OVSvAppServerRpcCallbackTest, self).setUp()
        self.ovsvapp_callbacks = ovsvapp_rpc.OVSvAppServerRpcCallback(
            mock.Mock(), mock.Mock())
        self.callbacks = plugin_rpc.RpcCallbacks(mock.Mock(), mock.Mock())
        self.plugin = self.manager.get_plugin()

    @mock.patch('networking_vsphere.ml2.ovsvapp_rpc.ovsvapp_db.get_local_vlan')
    def test_get_ports_for_device(self, ovsvapp_db):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'host': FAKE_HOST,
                  'device': {'id': 1,
                             'cluster_id': FAKE_CLUSTER_ID,
                             'vcenter': FAKE_VCENTER}}

        port = collections.defaultdict(lambda: 'fake')
        network = collections.defaultdict(lambda: 'fake')
        port['id'] = FAKE_PORT_ID
        port['status'] = 'DOWN'
        port['admin_state_up'] = True
        port['security_groups'] = ['fake-sg1', 'fake-sg2']

        ovsvapp_db.return_value = 1234
        with mock.patch.object(self.plugin,
                               'get_ports',
                               return_value=[port]), \
                mock.patch.object(self.plugin,
                                  'get_network',
                                  return_value=network), \
                mock.patch.object(self.ovsvapp_callbacks.notifier,
                                  'device_create') as mock_device_create, \
                mock.patch.object(ovsvapp_rpc.LOG, 'info'
                                  ) as mock_log_info, \
                mock.patch.object(self.plugin, 'get_ports_from_devices'
                                  ) as mock_get_ports_from_devices, \
                mock.patch.object(self.plugin, 'update_port_status'
                                  ) as mock_update_port_status, \
                mock.patch.object(self.ovsvapp_callbacks.sg_rpc,
                                  'security_group_info_for_esx_ports'
                                  ) as mock_sg_info_for_esx_ports, \
                mock.patch.object(self.ovsvapp_callbacks,
                                  'update_port_binding',
                                  return_value=[port]
                                  ) as mock_update_port_binding:
            self.assertTrue(self.ovsvapp_callbacks.get_ports_for_device(
                            'fake_context', **kwargs))
            self.assertTrue(mock_device_create.called)
            self.assertEqual(1, mock_log_info.call_count)
            mock_get_ports_from_devices.assert_called_with('fake_context',
                                                           set([FAKE_PORT_ID]))
            self.assertTrue(mock_update_port_status.called)
            self.assertTrue(mock_sg_info_for_esx_ports.called)
            self.assertTrue(mock_update_port_binding.called)

    @mock.patch.object(ovsvapp_rpc.LOG, 'debug')
    @mock.patch('networking_vsphere.ml2.ovsvapp_rpc.ovsvapp_db.get_local_vlan')
    def test_get_ports_for_device_no_security_groups(self, mock_log_debug,
                                                     ovsvapp_db):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'host': FAKE_HOST,
                  'device': {'id': 1,
                             'cluster_id': FAKE_CLUSTER_ID,
                             'vcenter': FAKE_VCENTER}}

        port = collections.defaultdict(lambda: 'fake')
        network = collections.defaultdict(lambda: 'fake')
        port['id'] = FAKE_PORT_ID
        port['status'] = 'DOWN'
        port['admin_state_up'] = True
        ovsvapp_db.return_value = 1234
        with mock.patch.object(self.plugin,
                               'get_ports',
                               return_value=[port]), \
                mock.patch.object(self.plugin,
                                  'get_network',
                                  return_value=network), \
                mock.patch.object(self.ovsvapp_callbacks.notifier,
                                  'device_create') as mock_device_create, \
                mock.patch.object(self.plugin, 'get_ports_from_devices'
                                  ) as mock_get_ports_from_devices, \
                mock.patch.object(self.plugin, 'update_port_status'
                                  ) as mock_update_port_status, \
                mock.patch.object(self.ovsvapp_callbacks,
                                  'update_port_binding',
                                  return_value=[port]
                                  ) as mock_update_port_binding:
            self.assertTrue(self.ovsvapp_callbacks.get_ports_for_device(
                            'fake_context', **kwargs))
            self.assertTrue(mock_device_create.called)
            self.assertEqual(1, mock_log_debug.call_count)
            self.assertFalse(mock_get_ports_from_devices.called)
            self.assertTrue(mock_update_port_status.called)
            self.assertTrue(mock_update_port_binding.called)

    @mock.patch.object(ovsvapp_rpc.LOG, 'info')
    @mock.patch.object(ovsvapp_rpc.LOG, 'exception')
    def test_get_ports_for_device_without_port(self, mock_log_exception,
                                               mock_log_info):
        self.plugin.get_ports.return_value = None
        self.assertFalse(self.ovsvapp_callbacks.get_ports_for_device(
                         'fake_context', agent_id=FAKE_AGENT_ID,
                         host=FAKE_HOST,
                         device={'id': 1,
                                 'cluster_id': FAKE_CLUSTER_ID,
                                 'vcenter': FAKE_VCENTER}))
        self.assertEqual(1, mock_log_info.call_count)
        self.assertTrue(mock_log_exception.called)

    def test_get_ports_for_device_without_device_id(self):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'host': FAKE_HOST,
                  'device': {'id': None,
                             'cluster_id': FAKE_CLUSTER_ID,
                             'vcenter': FAKE_VCENTER}}
        with mock.patch.object(ovsvapp_rpc.LOG, 'info') as log_info:
            self.assertFalse(self.ovsvapp_callbacks.get_ports_for_device(
                             'fake_context', **kwargs))
            self.assertTrue(log_info.called)

    def test_update_port_binding(self):
        kwargs = {'port_id': FAKE_PORT_ID, 'host': FAKE_HOST,
                  'agent_id': FAKE_AGENT_ID}
        port = {portbindings.HOST_ID: FAKE_HOST}
        self.plugin.update_port.return_value = port
        with mock.patch.object(ovsvapp_rpc.LOG, 'debug') as log_debug:
            updated_port = self.ovsvapp_callbacks.update_port_binding(
                'fake_context', **kwargs)
            self.assertEqual(port[portbindings.HOST_ID],
                             updated_port[portbindings.HOST_ID])
            self.assertTrue(log_debug.called)

    @mock.patch.object(ovsvapp_rpc.LOG, 'debug')
    def test_update_ports_binding(self, mock_log_debug):
        kwargs = {'ports': set([FAKE_PORT_ID]), 'host': FAKE_HOST,
                  'agent_id': FAKE_AGENT_ID}
        port = {portbindings.HOST_ID: FAKE_HOST,
                'id': FAKE_PORT_ID}
        self.plugin.update_port.return_value = port
        with mock.patch.object(self.plugin, 'port_bound_to_host',
                               return_value=False):
            status = self.ovsvapp_callbacks.update_ports_binding(
                'fake_context', **kwargs)
            self.assertIn("fake_port_id", status)
            self.assertTrue(mock_log_debug.called)

    @mock.patch.object(ovsvapp_rpc.LOG, 'debug')
    def test_update_ports_binding_no_host_change(self, mock_log_debug):
        kwargs = {'ports': set([FAKE_PORT_ID]), 'host': 'old_fake_host',
                  'agent_id': FAKE_AGENT_ID}
        port = {portbindings.HOST_ID: FAKE_HOST,
                'id': FAKE_PORT_ID}
        self.plugin.update_port.return_value = port
        with mock.patch.object(self.plugin, 'port_bound_to_host',
                               return_value=True):
            status = self.ovsvapp_callbacks.update_ports_binding(
                'fake_context', **kwargs)
            self.assertIn("fake_port_id", status)
            self.assertFalse(mock_log_debug.called)

    @mock.patch('networking_vsphere.ml2.ovsvapp_rpc.ovsvapp_db.get_local_vlan')
    @mock.patch('neutron.plugins.ml2.driver_context.PortContext')
    @mock.patch.object(ovsvapp_rpc.LOG, 'debug')
    def test_get_ports_details_list_all_ports_bound(self, mock_log_debug,
                                                    mock_port_ctxt,
                                                    mock_ovsvapp_db):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'port_ids': [FAKE_PORT_ID],
                  'vcenter_id': FAKE_VCENTER,
                  'cluster_id': FAKE_CLUSTER_ID}
        fake_port_db = mock.Mock()
        fake_port_dict = {'id': FAKE_PORT_ID,
                          'fixed_ips': [{'subnet_id': FAKE_SUBNET_ID,
                                         'ip_address': FAKE_IP_ADDRESS}],
                          'device_id': FAKE_DEVICE_1,
                          'device_owner': FAKE_DEVICE_OWNER,
                          'mac_address': FAKE_MAC_ADDRESS,
                          'admin_state_up': True,
                          'security_groups': [FAKE_SECURITY_GROUP],
                          'network_id': FAKE_NETWORK_ID}
        VLAN_SEGMENTS = [{api.ID: 'vlan_segment_id',
                          api.NETWORK_TYPE: 'vlan',
                          api.PHYSICAL_NETWORK: 'fake_physical_network',
                          api.SEGMENTATION_ID: 1234}]
        fake_port_context = TestFakePortContext(fake_port_dict, VLAN_SEGMENTS)
        fake_network = {'id': FAKE_NETWORK_ID}
        fake_context_obj = mock.Mock()
        mock_port_ctxt.return_value = fake_port_context
        mock_ovsvapp_db.return_value = 1234
        with mock.patch.object(self.ovsvapp_callbacks, '_get_port_db',
                               return_value=fake_port_db
                               ) as mock_get_port_db, \
                mock.patch.object(self.plugin, 'get_network',
                                  return_value=fake_network
                                  ) as mock_get_network, \
                mock.patch.object(self.plugin, '_make_port_dict',
                                  return_value=fake_port_dict
                                  ):
            actual = self.ovsvapp_callbacks.get_ports_details_list(
                fake_context_obj, **kwargs)
            self.assertEqual(1, mock_get_port_db.call_count)
            self.assertEqual(1, mock_get_network.call_count)
            self.assertEqual(2, mock_log_debug.call_count)
            expected = [
                {'port_id': FAKE_PORT_ID,
                 'fixed_ips': [{'subnet_id': FAKE_SUBNET_ID,
                                'ip_address': FAKE_IP_ADDRESS}],
                 'device_id': FAKE_DEVICE_1,
                 'device_owner': FAKE_DEVICE_OWNER,
                 'mac_address': FAKE_MAC_ADDRESS,
                 'lvid': 1234,
                 'admin_state_up': True,
                 'network_id': FAKE_NETWORK_ID,
                 'segmentation_id': VLAN_SEGMENTS[0][api.SEGMENTATION_ID],
                 'physical_network': VLAN_SEGMENTS[0][api.PHYSICAL_NETWORK],
                 'security_groups': [FAKE_SECURITY_GROUP],
                 'network_type': VLAN_SEGMENTS[0][api.NETWORK_TYPE]}]
            self.assertEqual(expected, actual)

    @mock.patch('networking_vsphere.ml2.ovsvapp_rpc.ovsvapp_db.get_local_vlan')
    @mock.patch('neutron.plugins.ml2.driver_context.PortContext')
    @mock.patch.object(ovsvapp_rpc.LOG, 'debug')
    def test_get_ports_details_list_ports_not_bound(self, mock_log_debug,
                                                    mock_port_ctxt,
                                                    mock_ovsvapp_db):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'port_ids': [FAKE_PORT_ID],
                  'vcenter_id': FAKE_VCENTER,
                  'cluster_id': FAKE_CLUSTER_ID}
        fake_port_db = mock.Mock()
        fake_port_dict = {'id': FAKE_PORT_ID,
                          'fixed_ips': [{'subnet_id': FAKE_SUBNET_ID,
                                         'ip_address': FAKE_IP_ADDRESS}],
                          'device_id': FAKE_DEVICE_1,
                          'device_owner': FAKE_DEVICE_OWNER,
                          'mac_address': FAKE_MAC_ADDRESS,
                          'admin_state_up': True,
                          'security_groups': [FAKE_SECURITY_GROUP],
                          'network_id': FAKE_NETWORK_ID,
                          portbindings.VIF_TYPE: ''}
        fake_port_context = TestFakePortContext(fake_port_dict)
        fake_network = {'id': FAKE_NETWORK_ID}
        fake_context_obj = mock.Mock()
        mock_port_ctxt.return_value = fake_port_context
        mock_ovsvapp_db.return_value = 1234
        with mock.patch.object(self.ovsvapp_callbacks,
                               '_get_port_db',
                               return_value=fake_port_db
                               ) as mock_get_port_db, \
                mock.patch.object(self.plugin,
                                  'get_network',
                                  return_value=fake_network
                                  ) as mock_get_network, \
                mock.patch.object(self.plugin,
                                  '_make_port_dict',
                                  return_value=fake_port_dict
                                  ):
            actual = self.ovsvapp_callbacks.get_ports_details_list(
                fake_context_obj, **kwargs)
            self.assertEqual(1, mock_get_port_db.call_count)
            self.assertEqual(1, mock_get_network.call_count)
            self.assertEqual(1, mock_log_debug.call_count)
            expected = []
            self.assertEqual(expected, actual)

    def test_update_devices_up(self):
        devices = [FAKE_DEVICE_1, FAKE_DEVICE_2]
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'devices': devices,
                  'host': FAKE_HOST}
        ret_value = {'devices_up': devices,
                     'failed_devices_up': []}
        with mock.patch.object(self.ovsvapp_callbacks, 'update_device_up'
                               ) as mock_update_device_up:
            result = self.ovsvapp_callbacks.update_devices_up('fake_context',
                                                              **kwargs)
            self.assertEqual(ret_value, result)
            self.assertEqual(2, mock_update_device_up.call_count)

    def test_update_devices_up_failed(self):
        devices = [FAKE_DEVICE_1]
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'devices': devices,
                  'host': FAKE_HOST}
        ret_value = {'devices_up': [],
                     'failed_devices_up': devices}
        with mock.patch.object(self.ovsvapp_callbacks, 'update_device_up',
                               side_effect=Exception
                               ) as mock_update_device_up:
            result = self.ovsvapp_callbacks.update_devices_up('fake_context',
                                                              **kwargs)
            self.assertEqual(ret_value, result)
            self.assertEqual(1, mock_update_device_up.call_count)

    def test_update_devices_down(self):
        devices = [FAKE_DEVICE_1, FAKE_DEVICE_2]
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'devices': devices,
                  'host': FAKE_HOST}
        ret_value = {'devices_down': devices,
                     'failed_devices_down': []}
        with mock.patch.object(self.ovsvapp_callbacks, 'update_device_down'
                               ) as mock_update_device_down:
            result = self.ovsvapp_callbacks.update_devices_down('fake_context',
                                                                **kwargs)
            self.assertEqual(ret_value, result)
            self.assertEqual(2, mock_update_device_down.call_count)

    def test_update_devices_down_failed(self):
        devices = [FAKE_DEVICE_1]
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'devices': devices,
                  'host': FAKE_HOST}
        ret_value = {'devices_down': [],
                     'failed_devices_down': devices}
        with mock.patch.object(self.ovsvapp_callbacks, 'update_device_down',
                               side_effect=Exception
                               ) as mock_update_device_down:
            result = self.ovsvapp_callbacks.update_devices_down('fake_context',
                                                                **kwargs)
            self.assertEqual(ret_value, result)
            self.assertEqual(1, mock_update_device_down.call_count)

    @mock.patch('networking_vsphere.db.ovsvapp_db.release_cluster_lock')
    @mock.patch('networking_vsphere.db.ovsvapp_db.set_cluster_threshold')
    @mock.patch.object(ovsvapp_rpc.LOG, 'info')
    def test_update_cluster_lock_success_case(self, log_info, set_threshold,
                                              release_lock):
        kwargs = {'vcenter_id': FAKE_VCENTER,
                  'cluster_id': FAKE_CLUSTER_ID,
                  'success': True}
        self.ovsvapp_callbacks.update_cluster_lock('fake_context', **kwargs)
        self.assertTrue(release_lock.called)
        release_lock.assert_called_with(FAKE_VCENTER, FAKE_CLUSTER_ID)
        self.assertFalse(set_threshold.called)
        self.assertTrue(log_info.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.release_cluster_lock')
    @mock.patch('networking_vsphere.db.ovsvapp_db.set_cluster_threshold')
    @mock.patch.object(ovsvapp_rpc.LOG, 'info')
    def test_update_cluster_lock_failure_case(self, log_info, set_threshold,
                                              release_lock):
        kwargs = {'vcenter_id': FAKE_VCENTER,
                  'cluster_id': FAKE_CLUSTER_ID,
                  'success': False}
        self.ovsvapp_callbacks.update_cluster_lock('fake_context', **kwargs)
        self.assertTrue(set_threshold.called)
        set_threshold.assert_called_with(FAKE_VCENTER, FAKE_CLUSTER_ID)
        self.assertFalse(release_lock.called)

    @mock.patch('networking_vsphere.db.ovsvapp_db.release_cluster_lock')
    @mock.patch('networking_vsphere.db.ovsvapp_db.set_cluster_threshold')
    @mock.patch.object(ovsvapp_rpc.LOG, 'exception')
    def test_update_cluster_lock_db_exception(self, log_exception,
                                              set_threshold,
                                              release_lock):
        kwargs = {'vcenter_id': FAKE_VCENTER,
                  'cluster_id': FAKE_CLUSTER_ID,
                  'success': False}
        set_threshold.side_effect = Exception
        self.ovsvapp_callbacks.update_cluster_lock('fake_context', **kwargs)
        self.assertTrue(set_threshold.called)
        set_threshold.assert_called_with(FAKE_VCENTER, FAKE_CLUSTER_ID)
        self.assertFalse(release_lock.called)
        self.assertTrue(log_exception.called)

    @mock.patch.object(ovsvapp_rpc.LOG, 'error')
    def test_get_port_db_exception(self, log_exception):
        session = mock.Mock()
        with mock.patch.object(session, 'query',
                               side_effect=sa_exc.MultipleResultsFound
                               ) as mock_get_port_db:
            self.ovsvapp_callbacks._get_port_db(session, 'fake_port_id',
                                                'fake_agent_id')
            self.assertTrue(log_exception.called)
            self.assertEqual(1, mock_get_port_db.call_count)


class OVSvAppAgentNotifyAPITest(test_rpc.RpcApiTestCase):

    cluster_device_topic = FAKE_CLUSTER_ID + '_' + ovsvapp_const.DEVICE
    sg_topic = ovsvapp_const.OVSVAPP + '_' + topics.SECURITY_GROUP

    def test_device_create(self):
        rpcapi = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 self.cluster_device_topic,
                                                 topics.CREATE),
                           'device_create', rpc_method='cast',
                           fanout=True,
                           device='fake_device',
                           ports='fake_ports',
                           sg_rules='fake_sg_rules',
                           cluster_id=FAKE_CLUSTER_ID)

    def test_device_update(self):
        rpcapi = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 self.cluster_device_topic,
                                                 topics.UPDATE),
                           'device_update', rpc_method='cast',
                           fanout=True,
                           device_data='fake_device_data',
                           cluster_id=FAKE_CLUSTER_ID)

    def test_device_delete(self):
        rpcapi = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 self.cluster_device_topic,
                                                 topics.DELETE),
                           'device_delete', rpc_method='cast',
                           fanout=True,
                           network_info='fake_network_info',
                           host=FAKE_HOST,
                           cluster_id=FAKE_CLUSTER_ID)

    def test_enhanced_sg_provider_updated(self):
        rpcapi = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 self.sg_topic,
                                                 topics.UPDATE),
                           'enhanced_sg_provider_updated', rpc_method='cast',
                           fanout=True,
                           network_id=FAKE_NETWORK_ID)


class OVSvAppPluginApiTest(test_rpc.RpcApiTestCase):

    def test_get_ports_for_device(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'get_ports_for_device', rpc_method='call',
                           device={'id': 'fake_id',
                                   'vcenter': FAKE_VCENTER,
                                   'cluster_id': FAKE_CLUSTER_ID},
                           agent_id=FAKE_AGENT_ID, host=FAKE_HOST)

    def test_update_device_binding(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'update_device_binding', rpc_method='call',
                           device=FAKE_DEVICE_1,
                           host=FAKE_HOST, agent_id=FAKE_AGENT_ID)

    def test_update_ports_binding(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'update_ports_binding', rpc_method='call',
                           ports=['fake_ports'],
                           host=FAKE_HOST, agent_id=FAKE_AGENT_ID)

    def test_get_ports_details_list(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'get_ports_details_list', rpc_method='call',
                           port_ids=['fake_port_ids'],
                           agent_id=FAKE_AGENT_ID, vcenter_id=FAKE_VCENTER,
                           cluster_id=FAKE_CLUSTER_ID)

    def test_update_local_vlan_assignment(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'update_lvid_assignment', rpc_method='call',
                           net_info='fake_network_info')

    def test_update_devices_up(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'update_devices_up', rpc_method='call',
                           agent_id=FAKE_AGENT_ID,
                           devices=['fake_devices'],
                           host=FAKE_HOST)

    def test_update_devices_down(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'update_devices_down', rpc_method='call',
                           agent_id=FAKE_AGENT_ID,
                           devices=['fake_devices'],
                           host=FAKE_HOST)

    def test_update_cluster_lock(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'update_cluster_lock', rpc_method='call',
                           vcenter_id=FAKE_VCENTER,
                           cluster_id=FAKE_CLUSTER_ID,
                           success='fake_status')


class OVSvAppSecurityGroupServerRpcApiTest(test_rpc.RpcApiTestCase):

    def test_security_group_info_for_esx_devices(self):
        rpcapi = ovsvapp_sg_agent.OVSvAppSecurityGroupServerRpcApi(
            ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'security_group_info_for_esx_devices',
                           rpc_method='call',
                           devices=['fake_devices'])
