#    Copyright 2015 Mirantis, Inc.
#    All Rights Reserved.
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

import mock
from neutron.common import constants as n_const
from neutron.tests import base

from networking_vsphere.common import constants as dvs_const
from networking_vsphere.common import exceptions
from networking_vsphere.ml2 import dvs_mechanism_driver


VALID_HYPERVISOR_TYPE = 'VMware vCenter Server'
INVALID_HYPERVISOR_TYPE = '_invalid_hypervisor_'


class FAKE_SECURITY_GROUPS(object):
    NEW = 'new_sg'
    CONSTANT = 'constant_sg'
    REMOVED = 'removed_sg'


CONSTANT_SG_RULE = {'constant rule': 'some_rule'}


class VMwareDVSMechanismDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(VMwareDVSMechanismDriverTestCase, self).setUp()
        self.driver = dvs_mechanism_driver.VMwareDVSMechanismDriver()
        self.driver._bound_ports = set()
        self.dvs_notifier = mock.Mock()
        self.driver.network_map = {'physnet1': mock.Mock()}

    @mock.patch('neutron.db.api.get_session')
    @mock.patch('networking_vsphere.utils.dvs_util.'
                'create_network_map_from_config', return_value='network_map')
    def test_initialize(self, create_network_map_from_config, get_session):
        pass

    def test_create_network_precommit_when_network_not_mapped(self):
        context = self._create_network_context()
        self.driver.network_map = {}
        with mock.patch('networking_vsphere.common.dvs_agent_rpc_api.'
                        'DVSClientAPI.create_network_cast') as cast_mock:
            self.driver.create_network_precommit(context)
            cast_mock.assert_called_once_with(
                context.current, context.network_segments[0])

    def test_delete_network_postcommit_when_network_is_not_mapped(self):
        context = self._create_network_context()
        self.driver.network_map = {}
        with mock.patch('networking_vsphere.common.dvs_agent_rpc_api.'
                        'DVSClientAPI.delete_network_cast') as cast_mock:
            self.driver.delete_network_postcommit(context)
            cast_mock.assert_called_once_with(
                context.current, context.network_segments[0])

    def test_update_network_precommit(self):
        context = self._create_network_context()
        self.driver.network_map = {}
        with mock.patch('networking_vsphere.common.dvs_agent_rpc_api.'
                        'DVSClientAPI.update_network_cast') as cast_mock:
            self.driver.update_network_precommit(context)
            cast_mock.assert_called_once_with(
                context.current, context.network_segments[0], context.original)

    @mock.patch('networking_vsphere.utils.compute_util.'
                'get_hypervisors_by_host')
    def test_update_port_postcommit(self, hypervisor_by_host):
        hypervisor_by_host.return_value = mock.Mock(
            hypervisor_type=VALID_HYPERVISOR_TYPE)

        current = self._create_port_dict(vif_type='unbound',
                                         status=n_const.PORT_STATUS_DOWN)
        port_ctx = self._create_port_context(current=current)
        segment = port_ctx.network.network_segments[0]
        with mock.patch('networking_vsphere.common.dvs_agent_rpc_api.'
                        'DVSClientAPI.update_postcommit_port_call') as m_call:
            self.driver.update_port_postcommit(port_ctx)
            m_call.assert_called_once_with(
                current, port_ctx.original, segment, port_ctx.host)

    @mock.patch('networking_vsphere.utils.compute_util.'
                'get_hypervisors_by_host')
    def test_update_port_postcommit_non_vmware_port(self, hypervisor_by_host):
        hypervisor_by_host.return_value = mock.Mock(
            hypervisor_type=INVALID_HYPERVISOR_TYPE)
        port_context = self._create_port_context()
        with mock.patch('networking_vsphere.common.dvs_agent_rpc_api.'
                        'DVSClientAPI.update_postcommit_port_call') as m_call:
            self.driver.update_port_postcommit(port_context)
            self.assertEqual(m_call.call_count, 0)

    @mock.patch('networking_vsphere.utils.compute_util.'
                'get_hypervisors_by_host')
    def test__port_belongs_to_vmware__unbinded_port(self, get_hypervisor):
        context = self._create_port_context()
        port = context.curren
        port.pop('binding:host_id')

        func = mock.Mock(__name__='dummy_name')
        decorated = dvs_mechanism_driver.port_belongs_to_vmware(func)
        self.assertFalse(decorated(None, context))
        self.assertFalse(func.called)

    @mock.patch('networking_vsphere.utils.compute_util.'
                'get_hypervisors_by_host')
    def test__port_belongs_to_vmware__invalid_hypervisor(
            self, get_hypervisor):
        context = self._create_port_context()
        get_hypervisor.return_value = mock.Mock(
            hypervisor_type=INVALID_HYPERVISOR_TYPE)

        func = mock.Mock(__name__='dummy_name')
        decorated = dvs_mechanism_driver.port_belongs_to_vmware(func)
        self.assertFalse(decorated(None, context))
        self.assertFalse(func.called)

    @mock.patch('networking_vsphere.utils.compute_util.'
                'get_hypervisors_by_host')
    def test__port_belongs_to_vmware__not_found(self, get_hypervisor):
        get_hypervisor.side_effect = exceptions.HypervisorNotFound
        context = self._create_port_context()

        func = mock.Mock(__name__='dummy_name', return_value=True)
        decorated = dvs_mechanism_driver.port_belongs_to_vmware(func)
        self.assertFalse(decorated(None, context))
        self.assertFalse(func.called)
        self.assertTrue(get_hypervisor.called)

    @mock.patch('networking_vsphere.utils.compute_util.'
                'get_hypervisors_by_host')
    def test_delete_port_postcommit_when_KeyError(self, hypervisor_by_host):
        hypervisor_by_host.return_value = mock.Mock(
            hypervisor_type=VALID_HYPERVISOR_TYPE)

        current = self._create_port_dict(vif_type='unbound',
                                         status=n_const.PORT_STATUS_DOWN)
        port_ctx = self._create_port_context(current=current)
        segment = port_ctx.network.network_segments[0]
        self.driver._bound_ports = set([1, 2])
        with mock.patch('networking_vsphere.common.dvs_agent_rpc_api.'
                        'DVSClientAPI.delete_port_call') as call_mock:
            self.driver.delete_port_postcommit(port_ctx)
            call_mock.assert_called_once_with(
                current, port_ctx.original, segment, port_ctx.host)

        self.assertEqual(set([1, 2]), self.driver._bound_ports)

    @mock.patch('networking_vsphere.utils.compute_util.'
                'get_hypervisors_by_host')
    def test_update_port_precomit_unbound_port(self, hypervisor_by_host):
        hypervisor_by_host.return_value = mock.Mock(
            hypervisor_type=VALID_HYPERVISOR_TYPE)
        current = self._create_port_dict(vif_type='unbound',
                                         status=n_const.PORT_STATUS_DOWN)
        port_ctx = self._create_port_context(current=current)
        network = port_ctx.network
        with mock.patch('networking_vsphere.common.dvs_agent_rpc_api.'
                        'DVSClientAPI.bind_port_call') as cast_mock:
            self.driver.update_port_precommit(port_ctx)
            cast_mock.assert_called_once_with(
                current, network.network_segments, network.current,
                port_ctx.host)

    @mock.patch('networking_vsphere.utils.compute_util.'
                'get_hypervisors_by_host')
    def test_update_port_precomit_not_unbound_port(self, hypervisor_by_host):
        hypervisor_by_host.return_value = mock.Mock(
            hypervisor_type=VALID_HYPERVISOR_TYPE)
        current = self._create_port_dict(vif_type='binding_failed')
        port_ctx = self._create_port_context(current=current)
        with mock.patch('networking_vsphere.common.dvs_agent_rpc_api.'
                        'DVSClientAPI.bind_port_call') as cast_mock:
            self.driver.update_port_precommit(port_ctx)
            self.assertEqual(cast_mock.call_count, 0)

    # TODO(ekosareva): add tests for _get_security_group_info func
    # def test_get_security_group_info_when_security_group_rules_absent(self):
    #    pass

    def _create_port_context(self, current=None, original=None, network=None):
        context = mock.Mock(
            current=current or self._create_port_dict(),
            original=original or self._create_port_dict(),
            network=network or self._create_network_context())
        return context

    def _create_port_dict(self, security_groups=None, vif_type=dvs_const.DVS,
                          status=n_const.PORT_STATUS_DOWN):
        security_groups = security_groups or []
        security_groups = list(security_groups)
        security_groups.append(FAKE_SECURITY_GROUPS.CONSTANT)
        return {
            'id': '_dummy_port_id_%s' % id({}),
            'admin_state_up': True,
            'security_groups': security_groups,
            'binding:host_id': '_id_server_',
            'binding:vif_type': vif_type,
            'status': status,
            'security_group_rules': [CONSTANT_SG_RULE],
            'binding:vif_details': {'dvs_port_key': '_dummy_dvs_port_key_'}
        }

    def _create_network_context(self, network_type='vlan'):
        return mock.Mock(
            current={'id': '_dummy_net_id_'},
            network_segments=[{
                'id': '_id_segment_',
                'network_type': network_type,
                'physical_network': 'physnet1'
            }])
