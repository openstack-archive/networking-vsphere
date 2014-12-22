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
# Unit test for OVSvApp Mechanism Driver

import collections
import contextlib

import mock

from neutron.common import topics
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit.ml2 import _test_mech_agent as base
from neutron.tests.unit.ml2 import test_rpcapi

from networking_vsphere.plugins.ml2.drivers import mech_ovsvapp

OVSVAPP = 'ovsvapp'


class OVSvAppAgentMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OTHER
    CAP_PORT_FILTER = True
    AGENT_TYPE = 'OVSvApp L2 Agent'

    GOOD_CONFIGS = {}
    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS}]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS}]

    def setUp(self):
        super(OVSvAppAgentMechanismBaseTestCase, self).setUp()
        self.driver = mech_ovsvapp.OVSvAppAgentMechanismDriver()
        self.driver.initialize()


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


class OVSvAppServerRpcCallbackTest(test_rpcapi.RpcCallbacksTestCase):

    def setUp(self):
        super(OVSvAppServerRpcCallbackTest, self).setUp()
        self.ovsvapp_callbacks = mech_ovsvapp.OVSvAppServerRpcCallback(
            mock.Mock())
        self.plugin = self.manager.get_plugin()

    def test_get_ports_for_device(self):
        kwargs = {'agent_id': 'fake_agent_id',
                  'device': {'id': 1,
                             'host': 'fake_host',
                             'cluster_id': 'fake_cluster_id'}}
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
            mock.patch.object(mech_ovsvapp.LOG, 'debug'),
            mock.patch.object(self.plugin, 'get_ports_from_devices'),
            mock.patch.object(self.plugin, 'security_group_rules_for_ports'),
        ) as (get_ports, get_network, device_create,
              log_debug, device_ports, sg_method):
            self.assertTrue(self.ovsvapp_callbacks.get_ports_for_device(
                            'fake_context', **kwargs))
            self.assertTrue(device_create.called)
            self.assertEqual(2, log_debug.call_count)
            self.assertTrue(device_ports.called)
            self.assertTrue(sg_method.called)

    def test_get_ports_for_device_no_security_groups(self):
        kwargs = {'agent_id': 'fake_agent_id',
                  'device': {'id': 1,
                             'host': 'fake_host',
                             'cluster_id': 'fake_cluster_id'}}
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
            mock.patch.object(mech_ovsvapp.LOG, 'debug'),
            mock.patch.object(self.plugin, 'get_ports_from_devices'),
        ) as (get_ports, get_network, device_create,
              log_debug, device_ports):
            self.assertTrue(self.ovsvapp_callbacks.get_ports_for_device(
                            'fake_context', **kwargs))
            self.assertTrue(device_create.called)
            self.assertEqual(2, log_debug.call_count)
            self.assertFalse(device_ports.called)

    def test_get_ports_for_device_without_port(self):
        self.plugin.get_ports.return_value = None
        with contextlib.nested(
            mock.patch.object(mech_ovsvapp.LOG, 'debug'),
            mock.patch.object(mech_ovsvapp.LOG, 'exception')
        ) as (log_debug, log_exception):
            self.assertFalse(self.ovsvapp_callbacks.get_ports_for_device(
                             'fake_context', agent_id='fake_agent_id',
                             device={'id': 1,
                                     'host': 'fake_host',
                                     'cluster_id': 'fake_cluster_id'}))
            self.assertEqual(2, log_debug.call_count)
            self.assertTrue(log_exception.called)

    def test_get_ports_for_device_without_device_id(self):
        kwargs = {'agent_id': 'fake_agent_id',
                  'device': {'id': None,
                             'host': 'fake_host',
                             'cluster_id': 'fake_cluster_id'}}
        with mock.patch.object(mech_ovsvapp.LOG, 'debug') as log_debug:
            self.assertFalse(self.ovsvapp_callbacks.get_ports_for_device(
                             'fake_context', **kwargs))
            self.assertTrue(log_debug.called)

    def test_update_port_binding(self):
        kwargs = {'port_id': 'fake_port_id', 'host': 'fake_host',
                  'agent_id': 'fake_agent_id'}
        port = {portbindings.HOST_ID: 'fake_host'}
        self.plugin.update_port.return_value = port
        with mock.patch.object(mech_ovsvapp.LOG, 'debug') as log_debug:
            updated_port = self.ovsvapp_callbacks.update_port_binding(
                'fake_context', **kwargs)
            self.assertEqual(port[portbindings.HOST_ID],
                             updated_port[portbindings.HOST_ID])
            self.assertTrue(log_debug.called)


class OVSvAppAgentNotifyAPITest(test_rpcapi.RpcApiTestCase):

    def test_device_create(self):
        rpcapi = mech_ovsvapp.OVSvAppAgentNotifyAPI(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 mech_ovsvapp.DEVICE,
                                                 topics.CREATE),
                           'device_create', rpc_method='cast',
                           fanout=True,
                           device='fake_device',
                           ports='fake_ports',
                           sg_rules='fake_sg_rules')

    def test_device_update(self):
        rpcapi = mech_ovsvapp.OVSvAppAgentNotifyAPI(topics.AGENT)
        self._test_rpc_api(rpcapi,
                           topics.get_topic_name(topics.AGENT,
                                                 mech_ovsvapp.DEVICE,
                                                 topics.UPDATE),
                           'device_update', rpc_method='cast',
                           fanout=True,
                           device_data='fake_device_data')