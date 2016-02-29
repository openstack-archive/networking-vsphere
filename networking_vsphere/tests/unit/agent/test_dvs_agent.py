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
from neutron.plugins.common import constants
from neutron.tests import base

from networking_vsphere.agent import dvs_neutron_agent
from networking_vsphere.common import constants as dvs_const
from networking_vsphere.common import exceptions


NOT_SUPPORTED_TYPES = [
    constants.TYPE_FLAT,
    constants.TYPE_GRE,
    constants.TYPE_LOCAL,
    constants.TYPE_VXLAN,
    constants.TYPE_NONE]


VALID_HYPERVISOR_TYPE = 'VMware vCenter Server'
INVALID_HYPERVISOR_TYPE = '_invalid_hypervisor_'


class FAKE_SECURITY_GROUPS(object):
    NEW = 'new_sg'
    CONSTANT = 'constant_sg'
    REMOVED = 'removed_sg'


CONSTANT_SG_RULE = {'constant rule': 'some_rule'}


class DVSAgentTestCase(base.BaseTestCase):

    def setUp(self):
        class TestDVSAgent(dvs_neutron_agent.DVSAgent):
            def __init__(self, network_map):
                self.network_map = network_map
                self.added_ports = set()
                self.booked_ports = set()

        super(DVSAgentTestCase, self).setUp()
        self.dvs = mock.Mock()
        # mock DVSAgent.__init__() method
        self.agent = TestDVSAgent({'physnet1': self.dvs})
        test_port_data = self._create_port_context()
        self.port_context = test_port_data[0]
        self.sg_info = test_port_data[1]

        sg_util_patch = mock.patch(
            'networking_vsphere.utils.security_group_utils.update_port_rules')
        self.addCleanup(sg_util_patch.stop)
        self.update_port_rules_mock = sg_util_patch.start()

    def test_look_up_dvs_failed(self):
        for type_ in NOT_SUPPORTED_TYPES:
            self.assertRaisesRegexp(exceptions.NotSupportedNetworkType,
                                    "VMWare DVS driver don't support %s "
                                    "network" % type_,
                                    self.agent._lookup_dvs_for_context,
                                    {'network_type': type_})

        segment = {'network_type': constants.TYPE_VLAN,
                   'physical_network': 'wrong_network'}
        self.assertRaisesRegexp(exceptions.NoDVSForPhysicalNetwork,
                                "No dvs mapped for physical network: %s" %
                                segment['physical_network'],
                                self.agent._lookup_dvs_for_context,
                                segment)

        segment = {'network_type': constants.TYPE_VLAN,
                   'physical_network': 'physnet1'}
        try:
            self.agent._lookup_dvs_for_context(segment)
        except Exception:
            self.fail('_lookup_dvs_for_context() function should not throw any'
                      ' exceptions with correct segment data: %s' % segment)

    @mock.patch('networking_vsphere.agent.dvs_neutron_agent.DVSAgent.'
                '_lookup_dvs_for_context')
    def test_update_port_postcommit_uncontrolled_dvs(self, is_valid_dvs):
        is_valid_dvs.side_effect = exceptions.NoDVSForPhysicalNetwork(
            physical_network='_dummy_physical_net_')
        self.port_context.current['admin_state_up'] = True
        self.port_context.original['admin_state_up'] = False

        self.assertRaises(exceptions.InvalidSystemState,
                          self.agent.update_port_postcommit,
                          self.port_context.current,
                          self.port_context.original,
                          self.port_context.network.network_segments[0])
        self.assertTrue(is_valid_dvs.called)
        self.assertFalse(self.dvs.switch_port_blocked_state.called)

    @mock.patch('networking_vsphere.agent.dvs_neutron_agent.DVSAgent.'
                '_lookup_dvs_for_context')
    def test_update_port_postcommit(self, is_valid_dvs):
        is_valid_dvs.return_value = self.dvs
        self.port_context.current['admin_state_up'] = True
        self.port_context.original['admin_state_up'] = False
        self.agent.added_ports = set()
        current_port_id = self.port_context.current['id']
        self.agent.booked_ports.add(current_port_id)
        self.agent.update_port_postcommit(
            self.port_context.current,
            self.port_context.original,
            self.port_context.network.network_segments[0])
        self.assertTrue(is_valid_dvs.called)
        self.assertTrue(self.dvs.switch_port_blocked_state.called)
        self.assertIn(current_port_id, self.agent.added_ports)
        self.assertNotIn(current_port_id, self.agent.booked_ports)

    @mock.patch('networking_vsphere.agent.dvs_neutron_agent.DVSAgent.'
                '_lookup_dvs_for_context')
    def test_delete_port_postcommit_uncontrolled_dvs(self, is_valid_dvs):
        is_valid_dvs.side_effect = exceptions.NoDVSForPhysicalNetwork(
            physical_network='_dummy_physical_net_')

        self.assertRaises(exceptions.InvalidSystemState,
                          self.agent.delete_port_postcommit,
                          self.port_context.current,
                          self.port_context.original,
                          self.port_context.network.network_segments[0])
        self.assertTrue(is_valid_dvs.called)
        self.assertFalse(self.dvs.release_port.called)

    @mock.patch('networking_vsphere.agent.dvs_neutron_agent.DVSAgent.'
                '_lookup_dvs_for_context')
    def test_delete_port_postcommit(self, is_valid_dvs):
        is_valid_dvs.return_value = self.dvs

        self.agent.delete_port_postcommit(
            self.port_context.current,
            self.port_context.original,
            self.port_context.network.network_segments[0]
        )
        self.assertTrue(is_valid_dvs.called)
        self.assertTrue(self.dvs.release_port.called)

    def _create_ports(self, security_groups=None):
        ports = [
            self._create_port_dict(),
            self._create_port_dict(vif_type='ovs',
                                   vif_details={'other': 'details'},
                                   security_groups=security_groups),
            self._create_port_dict(security_groups=security_groups),
            self._create_port_dict(security_groups=['other'])
        ]
        return ports

    def _create_port_context(self, current=None, original=None, ports=None,
                             security_groups=None, sg_member_ips=None):
        current = current or self._create_port_dict()
        original = original or self._create_port_dict()
        original['id'] = current['id']
        ports = ports or self._create_ports(
            security_groups=current['security_groups'])
        ports.append(current)
        context = mock.Mock(
            current=current,
            original=original,
            network=self._create_network_context())

        devices = {p['id']: p for p in ports}
        devices[current['id']] = current
        security_groups = security_groups or {}
        for p in ports:
            for sg in p['security_groups']:
                if sg not in security_groups:
                    security_groups[sg] = []

        sg_info = {
            'devices': devices,
            'security_groups': security_groups,
            'sg_member_ips': sg_member_ips or {},
        }
        return context, sg_info

    def _create_port_dict(self, security_groups=None, vif_type=None,
                          vif_details=None):
        security_groups = security_groups or []
        security_groups = list(security_groups)
        security_groups.append(FAKE_SECURITY_GROUPS.CONSTANT)
        return {
            'id': '_dummy_port_id_%s' % id({}),
            'admin_state_up': True,
            'security_groups': security_groups,
            'binding:host_id': '_id_server_',
            'binding:vif_type': vif_type or dvs_const.DVS,
            'status': 'DOWN',
            'security_group_rules': [CONSTANT_SG_RULE],
            'binding:vif_details': vif_details or {
                'dvs_port_key': '_dummy_dvs_port_key_'}}

    def _create_network_context(self, network_type='vlan'):
        return mock.Mock(current={'id': '_dummy_net_id_'},
                         network_segments=[{'id': '_id_segment_',
                                            'network_type': network_type,
                                            'physical_network': 'physnet1'}])
