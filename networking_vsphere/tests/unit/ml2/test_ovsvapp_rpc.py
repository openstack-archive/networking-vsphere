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
from neutron.tests.unit.plugins.ml2 import test_rpc

from networking_vsphere.agent import ovsvapp_agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.ml2 import ovsvapp_rpc

cfg.CONF.import_group('ml2', 'neutron.plugins.ml2.config')


class OVSvAppServerRpcCallbackTest(test_rpc.RpcCallbacksTestCase):

    def setUp(self):
        super(OVSvAppServerRpcCallbackTest, self).setUp()
        self.ovsvapp_callbacks = ovsvapp_rpc.OVSvAppServerRpcCallback(
            mock.Mock())
        self.plugin = self.manager.get_plugin()

    def test_get_ports_for_device(self):
        kwargs = {'agent_id': 'fake_agent_id',
                  'host': 'fake_host',
                  'device': {'id': 1,
                             'cluster_id': 'fake_cluster_id',
                             'vcenter': 'fake_vcenter'}}

        port = collections.defaultdict(lambda: 'fake')
        network = collections.defaultdict(lambda: 'fake')
        port['id'] = 'fake-id'
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
        kwargs = {'agent_id': 'fake_agent_id',
                  'host': 'fake_host',
                  'device': {'id': 1,
                             'cluster_id': 'fake_cluster_id',
                             'vcenter': 'fake_vcenter'}}

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
                             'fake_context', agent_id='fake_agent_id',
                             host='fake_host',
                             device={'id': 1,
                                     'cluster_id': 'fake_cluster_id',
                                     'vcenter': 'fake_vcenter'}))
            self.assertEqual(2, log_debug.call_count)
            self.assertTrue(log_exception.called)

    def test_get_ports_for_device_without_device_id(self):
        kwargs = {'agent_id': 'fake_agent_id',
                  'host': 'fake_host',
                  'device': {'id': None,
                             'cluster_id': 'fake_cluster_id',
                             'vcenter': 'fake_vcenter'}}
        with mock.patch.object(ovsvapp_rpc.LOG, 'debug') as log_debug:
            self.assertFalse(self.ovsvapp_callbacks.get_ports_for_device(
                             'fake_context', **kwargs))
            self.assertTrue(log_debug.called)

    def test_update_port_binding(self):
        kwargs = {'port_id': 'fake_port_id', 'host': 'fake_host',
                  'agent_id': 'fake_agent_id'}
        port = {portbindings.HOST_ID: 'fake_host'}
        self.plugin.update_port.return_value = port
        with mock.patch.object(ovsvapp_rpc.LOG, 'debug') as log_debug:
            updated_port = self.ovsvapp_callbacks.update_port_binding(
                'fake_context', **kwargs)
            self.assertEqual(port[portbindings.HOST_ID],
                             updated_port[portbindings.HOST_ID])
            self.assertTrue(log_debug.called)


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
                           host='fake_host')

    def test_get_ports_for_device(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'get_ports_for_device', rpc_method='call',
                           device={'id': 'fake_id',
                                   'vcenter': 'fake_vcenter',
                                   'cluster_id': 'fake_cluster_id'},
                           agent_id='fake_agent_id', host='fake_host')

    def test_update_port_binding(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'update_port_binding', rpc_method='call',
                           port_id='fake_port_id',
                           host='fake_host', agent_id='fake_agent_id')

    def test_get_ports_details_list(self):
        rpcapi = ovsvapp_agent.OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self._test_rpc_api(rpcapi, None,
                           'get_ports_details_list', rpc_method='call',
                           port_ids=['fake_port_ids'],
                           agent_id='fake_agent_id', vcenter_id='fake_vcenter',
                           cluster_id='fake_cluster_id')
