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
from mock import patch

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
