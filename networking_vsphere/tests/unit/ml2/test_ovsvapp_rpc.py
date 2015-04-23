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
import contextlib

import mock
from oslo_config import cfg

from neutron.common import topics
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base
from neutron.tests.unit.plugins.ml2 import test_rpc

from networking_vsphere.agent import ovsvapp_agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.ml2 import ovsvapp_rpc

cfg.CONF.import_group('ml2', 'neutron.plugins.ml2.config')

FAKE_CLUSTER_ID = 'fake_cluster_id'
FAKE_VCENTER = 'fake_vcenter'
FAKE_HOST = 'fake_host'
FAKE_AGENT_ID = 'fake_agent_id'
FAKE_PORT_ID = 'fake_port_id'
FAKE_NETWORK_ID = "fake_network_id"
FAKE_SUBNET_ID = "fake_subnet_id"
FAKE_DEVICE_OWNER = "fake_device_owner"
FAKE_DEVICE_ID = "fake_device_id"
FAKE_MAC_ADDRESS = "fake_mac_address"
FAKE_IP_ADDRESS = "fake_ip_address"


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
            mock.Mock())
        self.plugin = self.manager.get_plugin()

    def test_get_ports_for_device(self):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'host': FAKE_HOST,
                  'device': {'id': 1,
                             'cluster_id': FAKE_CLUSTER_ID,
                             'vcenter': FAKE_VCENTER}}

        port = collections.defaultdict(lambda: 'fake')
        network = collections.defaultdict(lambda: 'fake')
        port['id'] = FAKE_PORT_ID
        port['security_groups'] = ['fake-sg1', 'fake-sg2']
        with contextlib.nested(
            mock.patch.object(self.plugin,
                              'get_ports',
                              return_value=[port]),
            mock.patch.object(self.plugin,
                              'get_network',
                              return_value=network),
            mock.patch.object(self.ovsvapp_callbacks.notifier,
                              'device_create'),
            mock.patch.object(ovsvapp_rpc.LOG, 'debug'),
            mock.patch.object(self.plugin, 'get_ports_from_devices'),
            mock.patch.object(self.plugin, 'security_group_rules_for_ports'),
            mock.patch.object(self.ovsvapp_callbacks, 'update_port_binding',
                              return_value=[port])
        ) as (get_ports, get_network, device_create,
              log_debug, get_ports_from_devices, sg_rules_for_ports,
              update_port_binding):
            self.assertTrue(self.ovsvapp_callbacks.get_ports_for_device(
                            'fake_context', **kwargs))
            self.assertTrue(device_create.called)
            self.assertEqual(2, log_debug.call_count)
            self.assertTrue(get_ports_from_devices.called)
            self.assertTrue(sg_rules_for_ports.called)
            self.assertTrue(update_port_binding.called)

    def test_get_ports_for_device_no_security_groups(self):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'host': FAKE_HOST,
                  'device': {'id': 1,
                             'cluster_id': FAKE_CLUSTER_ID,
                             'vcenter': FAKE_VCENTER}}

        port = collections.defaultdict(lambda: 'fake')
        network = collections.defaultdict(lambda: 'fake')
        port['id'] = 'fake-id'
        with contextlib.nested(
            mock.patch.object(self.plugin,
                              'get_ports',
                              return_value=[port]),
            mock.patch.object(self.plugin,
                              'get_network',
                              return_value=network),
            mock.patch.object(self.ovsvapp_callbacks.notifier,
                              'device_create'),
            mock.patch.object(ovsvapp_rpc.LOG, 'debug'),
            mock.patch.object(self.plugin, 'get_ports_from_devices'),
            mock.patch.object(self.ovsvapp_callbacks, 'update_port_binding',
                              return_value=[port])
        ) as (get_ports, get_network, device_create,
              log_debug, get_ports_from_devices, update_port_binding):
            self.assertTrue(self.ovsvapp_callbacks.get_ports_for_device(
                            'fake_context', **kwargs))
            self.assertTrue(device_create.called)
            self.assertEqual(2, log_debug.call_count)
            self.assertFalse(get_ports_from_devices.called)
            self.assertTrue(update_port_binding.called)

    def test_get_ports_for_device_without_port(self):
        self.plugin.get_ports.return_value = None
        with contextlib.nested(
            mock.patch.object(ovsvapp_rpc.LOG, 'debug'),
            mock.patch.object(ovsvapp_rpc.LOG, 'exception')
        ) as (log_debug, log_exception):
            self.assertFalse(self.ovsvapp_callbacks.get_ports_for_device(
                             'fake_context', agent_id=FAKE_AGENT_ID,
                             host=FAKE_HOST,
                             device={'id': 1,
                                     'cluster_id': FAKE_CLUSTER_ID,
                                     'vcenter': FAKE_VCENTER}))
            self.assertEqual(2, log_debug.call_count)
            self.assertTrue(log_exception.called)

    def test_get_ports_for_device_without_device_id(self):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'host': FAKE_HOST,
                  'device': {'id': None,
                             'cluster_id': FAKE_CLUSTER_ID,
                             'vcenter': FAKE_VCENTER}}
        with mock.patch.object(ovsvapp_rpc.LOG, 'debug') as log_debug:
            self.assertFalse(self.ovsvapp_callbacks.get_ports_for_device(
                             'fake_context', **kwargs))
            self.assertTrue(log_debug.called)

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

    def test_update_ports_binding(self):
        kwargs = {'ports': set([FAKE_PORT_ID]), 'host': FAKE_HOST,
                  'agent_id': FAKE_AGENT_ID}
        port = {portbindings.HOST_ID: FAKE_HOST,
                'id': FAKE_PORT_ID}
        self.plugin.update_port.return_value = port
        with contextlib.nested(
            mock.patch.object(self.plugin, 'port_bound_to_host',
                              return_value=False),
            mock.patch.object(ovsvapp_rpc.LOG, 'debug')
        ) as (port_bound_to_host, log_debug):
            status = self.ovsvapp_callbacks.update_ports_binding(
                'fake_context', **kwargs)
            self.assertIn("fake_port_id", status)
            self.assertTrue(log_debug.called)

    def test_update_ports_binding_no_host_change(self):
        kwargs = {'ports': set([FAKE_PORT_ID]), 'host': 'old_fake_host',
                  'agent_id': FAKE_AGENT_ID}
        port = {portbindings.HOST_ID: FAKE_HOST,
                'id': FAKE_PORT_ID}
        self.plugin.update_port.return_value = port
        with contextlib.nested(
            mock.patch.object(self.plugin, 'port_bound_to_host',
                              return_value=True),
            mock.patch.object(ovsvapp_rpc.LOG, 'debug')
        ) as (get_host, log_debug):
            status = self.ovsvapp_callbacks.update_ports_binding(
                'fake_context', **kwargs)
            self.assertIn("fake_port_id", status)
            self.assertFalse(log_debug.called)

    def test_get_ports_details_list_all_ports_bound(self):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'port_ids': [FAKE_PORT_ID],
                  'vcenter_id': FAKE_VCENTER,
                  'cluster_id': FAKE_CLUSTER_ID}
        fake_port_db = mock.Mock()
        fake_port_dict = {'id': FAKE_PORT_ID,
                          'fixed_ips': [{'subnet_id': FAKE_SUBNET_ID,
                                         'ip_address': FAKE_IP_ADDRESS}],
                          'device_id': FAKE_DEVICE_ID,
                          'device_owner': FAKE_DEVICE_OWNER,
                          'mac_address': FAKE_MAC_ADDRESS,
                          'admin_state_up': True,
                          'network_id': FAKE_NETWORK_ID}
        VLAN_SEGMENTS = [{api.ID: 'vlan_segment_id',
                          api.NETWORK_TYPE: 'vlan',
                          api.PHYSICAL_NETWORK: 'fake_physical_network',
                          api.SEGMENTATION_ID: 1234}]
        fake_port_context = TestFakePortContext(fake_port_dict, VLAN_SEGMENTS)
        fake_network = {'id': FAKE_NETWORK_ID}
        fake_context_obj = mock.Mock()
        with contextlib.nested(
            mock.patch('neutron.plugins.ml2.driver_context.PortContext',
                       return_value=fake_port_context),
            mock.patch.object(self.ovsvapp_callbacks,
                              '_get_port_db',
                              return_value=fake_port_db),
            mock.patch.object(self.plugin,
                              'get_network',
                              return_value=fake_network),
            mock.patch.object(self.plugin,
                              '_make_port_dict',
                              return_value=fake_port_dict),
            mock.patch.object(ovsvapp_rpc.LOG, 'debug'),
        ) as (port_ctxt, get_port_db, get_network, make_port_dict, log_debug):
            actual = self.ovsvapp_callbacks.get_ports_details_list(
                fake_context_obj, **kwargs)
            self.assertEqual(1, get_port_db.call_count)
            self.assertEqual(1, get_network.call_count)
            self.assertEqual(2, log_debug.call_count)
            expected = [
                {'port_id': FAKE_PORT_ID,
                 'fixed_ips': [{'subnet_id': FAKE_SUBNET_ID,
                                'ip_address': FAKE_IP_ADDRESS}],
                 'device_id': FAKE_DEVICE_ID,
                 'device_owner': FAKE_DEVICE_OWNER,
                 'mac_address': FAKE_MAC_ADDRESS,
                 'lvid': 1234,
                 'admin_state_up': True,
                 'network_id': FAKE_NETWORK_ID,
                 'segmentation_id': VLAN_SEGMENTS[0][api.SEGMENTATION_ID],
                 'physical_network': VLAN_SEGMENTS[0][api.PHYSICAL_NETWORK],
                 'network_type': VLAN_SEGMENTS[0][api.NETWORK_TYPE]}]
            self.assertEqual(expected, actual)

    def test_get_ports_details_list_ports_not_bound(self):
        kwargs = {'agent_id': FAKE_AGENT_ID,
                  'port_ids': [FAKE_PORT_ID],
                  'vcenter_id': FAKE_VCENTER,
                  'cluster_id': FAKE_CLUSTER_ID}
        fake_port_db = mock.Mock()
        fake_port_dict = {'id': FAKE_PORT_ID,
                          'fixed_ips': [{'subnet_id': FAKE_SUBNET_ID,
                                         'ip_address': FAKE_IP_ADDRESS}],
                          'device_id': FAKE_DEVICE_ID,
                          'device_owner': FAKE_DEVICE_OWNER,
                          'mac_address': FAKE_MAC_ADDRESS,
                          'admin_state_up': True,
                          'network_id': FAKE_NETWORK_ID,
                          portbindings.VIF_TYPE: ''}
        fake_port_context = TestFakePortContext(fake_port_dict)
        fake_network = {'id': FAKE_NETWORK_ID}
        fake_context_obj = mock.Mock()
        with contextlib.nested(
            mock.patch('neutron.plugins.ml2.driver_context.PortContext',
                       return_value=fake_port_context),
            mock.patch.object(self.ovsvapp_callbacks,
                              '_get_port_db',
                              return_value=fake_port_db),
            mock.patch.object(self.plugin,
                              'get_network',
                              return_value=fake_network),
            mock.patch.object(self.plugin,
                              '_make_port_dict',
                              return_value=fake_port_dict),
            mock.patch.object(ovsvapp_rpc.LOG, 'debug'),
        ) as (port_ctxt, get_port_db, get_network, mk_port, log_debug):
            port_ctxt.return_value = fake_port_context
            actual = self.ovsvapp_callbacks.get_ports_details_list(
                fake_context_obj, **kwargs)
            self.assertEqual(1, get_port_db.call_count)
            self.assertEqual(1, get_network.call_count)
            self.assertEqual(1, log_debug.call_count)
            expected = []
            self.assertEqual(expected, actual)


class OVSvAppAgentNotifyAPITest(test_rpc.RpcApiTestCase):

    def test_device_create(self):
        rpcapi = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 ovsvapp_const.DEVICE,
                                                 topics.CREATE),
                           'device_create', rpc_method='cast',
                           fanout=True,
                           device='fake_device',
                           ports='fake_ports',
                           sg_rules='fake_sg_rules')

    def test_device_delete(self):
        rpcapi = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 ovsvapp_const.DEVICE,
                                                 topics.DELETE),
                           'device_delete', rpc_method='call',
                           network_info='fake_network_info',
                           host=FAKE_HOST)

    def test_get_ports_for_device(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'get_ports_for_device', rpc_method='call',
                           device={'id': 'fake_id',
                                   'vcenter': FAKE_VCENTER,
                                   'cluster_id': FAKE_CLUSTER_ID},
                           agent_id=FAKE_AGENT_ID, host=FAKE_HOST)

    def test_update_port_binding(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'update_port_binding', rpc_method='call',
                           port_id=FAKE_PORT_ID,
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
