# (c) Copyright 2018 SUSE LLC
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

from mock import MagicMock
from mock import mock
from mock import patch

import networking_vsphere
from networking_vsphere.common import constants as const
from networking_vsphere.utils import vim_objects
from oslotest import base


class TestBase(base.BaseTestCase):
    def setUp(self):
        super(TestBase, self).setUp()
        self.addCleanup(patch.stopall)
        self.connection_patcher = patch(
            'networking_vsphere.utils.vim_objects.api.VMwareAPISession')
        self.mocked_session = self.connection_patcher.start()
        session_instance = MagicMock()
        session_instance.invoke_api.return_value = [MagicMock(), MagicMock()]
        self.mocked_session.return_value = session_instance


class TestVcenterProxy(TestBase):
    def setUp(self):
        super(TestVcenterProxy, self).setUp()
        self.sut = vim_objects.VcenterProxy(name='test_dvs',
                                            vcenter_user="username",
                                            vcenter_ip='127.0.0.1',
                                            vcenter_port=443,
                                            vcenter_password='test'
                                            )
        self.sut.connect_to_vcenter()

    def test_connect_to_vcenter(self):
        self.assertIsNotNone(self.sut.cf)

    def test_get_type(self):
        self.sut.connect_to_vcenter()
        self.sut.get_type('fake_type')
        self.sut.cf.create.called_with('ns0:fake_type')

    def test_get_all_objects_of_type(self):
        self.assertIsNotNone(self.sut.get_all_objects_of_type('some_type'))
        self.sut.session.invoke_api.assert_called_with(
            vim_objects.vim_util,
            'get_objects',
            self.sut.session.vim,
            'some_type',
            const.VIM_MAX_OBJETS
        )

    def test_get_vcenter_hosts(self):
        self.assertIsNotNone(self.sut.get_hosts())
        self.sut.session.invoke_api.assert_called_with(
            vim_objects.vim_util,
            'get_objects',
            self.sut.session.vim,
            'HostSystem',
            const.VIM_MAX_OBJETS
        )


class TestDistributedVirtualSwitch(TestBase):
    def setUp(self):
        super(TestDistributedVirtualSwitch, self).setUp()
        self.sut = vim_objects.DistributedVirtualSwitch(
            'test_dvs',
            vcenter_ip='127.0.0.1',
            vcenter_port=443,
            vcenter_password='test',
            host_names=[],
            pnic_devices=[
                'vmnic1',
                'vmnic2']
        )
        self.sut.host_names = ['HostSystem1', 'HostSystem2']
        self.sut.connect_to_vcenter()

    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_type')
    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_used_pnics_keys_in_host')
    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_all_pnic_keys_in_host')
    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_mob_by_name')
    def test_create_spec(self, mocked_get_by_name, mocked_all_keys,
                         mocked_used_keys,
                         mocked_get_type):
        key1 = 'key-vim.host.PhysicalNic-vmnic1'
        key2 = 'key-vim.host.PhysicalNic-vmnic2'
        key3 = 'key-vim.host.PhysicalNic-vmnic3'
        mocked_all_keys.return_value = {key1, key2, key3}
        mocked_used_keys.return_value = {key2}
        mocked_result = MagicMock()
        mocked_get_type.return_value = mocked_result
        mocked_host = MagicMock()
        mocked_host.obj = MagicMock()
        mocked_get_by_name.return_value = MagicMock()
        self.sut.hosts = [mocked_host]
        self.assertEqual(self.sut.create_spec, mocked_result)
        for _type in [
            'DVSCreateSpec',
            'DistributedVirtualSwitchProductSpec',
            'VMwareDVSConfigSpec',
            'ConfigSpecOperation',
            'DistributedVirtualSwitchHostMemberPnicBacking',
            'DistributedVirtualSwitchHostMemberPnicSpec',
            'DVSNameArrayUplinkPortPolicy'
        ]:
            mocked_get_type.assert_any_call(_type)

    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_type')
    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_used_pnics_keys_in_host')
    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_all_pnic_keys_in_host')
    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_mob_by_name')
    def test_config_spec(self, mocked_get_mob_by_name, mocked_all_keys,
                         mocked_used_keys,
                         mocked_get_type):
        key1 = 'key-vim.host.PhysicalNic-vmnic1'
        key2 = 'key-vim.host.PhysicalNic-vmnic2'
        key3 = 'key-vim.host.PhysicalNic-vmnic3'
        mocked_all_keys.return_value = {key1, key2, key3}
        mocked_used_keys.return_value = {key2}
        mocked_result = MagicMock()
        mocked_get_type.return_value = mocked_result
        mocked_host = MagicMock()
        mocked_host.obj = MagicMock()
        mocked_get_mob_by_name.return_value = MagicMock()
        self.sut.hosts = [mocked_host]
        spec = self.sut.config_spec
        self.assertEqual(spec, mocked_result)
        for _type in [
            'VMwareDVSConfigSpec',
            'ConfigSpecOperation',
            'DistributedVirtualSwitchHostMemberPnicBacking',
            'DistributedVirtualSwitchHostMemberPnicSpec',
            'DVSNameArrayUplinkPortPolicy'
        ]:
            mocked_get_type.assert_any_call(_type)
            self.assertEqual(spec.name, self.sut.name)
            self.assertEqual(spec.description, self.sut.description)
            self.assertEqual(spec.maxPorts, self.sut.max_ports)
            self.assertEqual(spec.maxMtu, self.sut.max_mtu)

    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_type')
    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_used_pnics_keys_in_host')
    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_all_pnic_keys_in_host')
    def test_list_of_member_hosts_specs(self, mocked_all_keys,
                                        mocked_used_keys,
                                        mocked_get_type):
        key1 = 'key-vim.host.PhysicalNic-vmnic1'
        key2 = 'key-vim.host.PhysicalNic-vmnic2'
        key3 = 'key-vim.host.PhysicalNic-vmnic3'
        mocked_all_keys.return_value = {key1, key2, key3}
        mocked_used_keys.return_value = {key2}
        mocked_result = MagicMock()
        mocked_host = MagicMock()
        mocked_host.obj = MagicMock()
        self.sut.hosts = [mocked_host]

        mocked_get_type.return_value = mocked_result
        results = self.sut.list_of_host_member_config_specs
        self.assertEqual(len(results),
                         len(self.sut.hosts)
                         )
        for _type in [
            'ConfigSpecOperation',
            'DistributedVirtualSwitchHostMemberPnicBacking',
            'DistributedVirtualSwitchHostMemberPnicSpec',
        ]:
            mocked_get_type.assert_any_call(_type)

    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_type')
    def test_host_member_pnic_backing(self, mocked_get_type):
        mocked_result = MagicMock()
        mocked_result.__len__.return_value = 1
        mocked_get_type.return_value = mocked_result
        results = self.sut.host_member_pnic_backing(['vmnic1'])

        for _type in [
            'DistributedVirtualSwitchHostMemberPnicBacking',
            'DistributedVirtualSwitchHostMemberPnicSpec',
        ]:
            mocked_get_type.assert_any_call(_type)

        self.assertEqual(len(results), 1)

    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_type')
    def test_host_member_pnic_spec(self, mocked_get_type):
        mocked_result = MagicMock()
        mocked_result.__len__.return_value = 1
        mocked_get_type.return_value = mocked_result
        results = self.sut.host_member_pnic_spec(['vmnic1'])
        self.assertEqual(len(results), 1)
        mocked_get_type.assert_any_call(
            'DistributedVirtualSwitchHostMemberPnicSpec')

    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_type')
    def test_uplink_port_policy(self, mocked_get_type):
        mocked_result = MagicMock()
        mocked_result.__len__.return_value = 1
        mocked_get_type.return_value = mocked_result
        results = self.sut.uplink_port_policy
        self.assertEqual(len(results), 1)
        mocked_get_type.assert_any_call('DVSNameArrayUplinkPortPolicy')
        self.assertEqual(len(results.uplinkPortName),
                         len(self.sut.pnic_devices))

    def test_uplink_port_names(self):
        self.assertEqual(self.sut.uplink_port_names,
                         ['dvUplink0', 'dvUplink1'])
        self.sut.pnic_devices = []
        self.assertEqual(self.sut.uplink_port_names, ['dvUplink'])

    @mock.patch.object(networking_vsphere.utils.vim_objects.VcenterProxy,
                       'get_mob_by_name')
    def test_datacenter(self, mocked_get_mob_by_name):
        self.assertIsNotNone(self.sut.datacenter)
        mocked_get_mob_by_name.assert_called_with('Datacenter',
                                                  self.sut.datacenter_name)
