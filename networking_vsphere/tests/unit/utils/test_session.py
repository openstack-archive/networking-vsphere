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

import mock
from oslo_vmware import api
from oslo_vmware import vim

from networking_vsphere.tests import base
from networking_vsphere.utils import vim_session


class TestVmwareApiSession(base.TestCase):

    def setUp(self):
        super(TestVmwareApiSession, self).setUp()
        self.host_ip = "192.168.1.3"
        self.host_username = "user"
        self.host_password = "password"
        self.api_retry_count = 2
        self.wsdl_url = "fake_url"
        self.ca_cert = "fake_cert"
        self.vm_session = vim_session.VMWareAPISession(self.host_ip,
                                                       self.host_username,
                                                       self.host_password,
                                                       self.api_retry_count,
                                                       self.wsdl_url,
                                                       self.ca_cert,
                                                       create_session=False)

    @mock.patch.object(api.VMwareAPISession, "invoke_api")
    def test_call_method(self, mock_invoke_ob):
        with mock.patch.object(self.vm_session,
                               "_is_vim_object",
                               return_value=True):
            self.vm_session._call_method("fake_module",
                                         "get_objects",
                                         "HostSystem", ['name'])
            self.assertTrue(mock_invoke_ob.called)

    @mock.patch.object(api.VMwareAPISession, "invoke_api")
    @mock.patch.object(api.VMwareAPISession, "vim")
    def test_call_method_with_vim_object_false(self, mock_vim_prop,
                                               mock_invoke_ob):
        vim.Vim = mock.Mock()
        mock_vim_prop.return_value = vim.Vim
        with mock.patch.object(self.vm_session,
                               "_is_vim_object",
                               return_value=False):
            self.vm_session._call_method("fake_module",
                                         "get_objects",
                                         "HostSystem", ['name'])
            self.assertTrue(mock_invoke_ob.called)

    @mock.patch.object(api.VMwareAPISession, "vim")
    def test_get_vim(self, mock_vim_prop):
        vim.Vim = mock.Mock(return_value="fake_vim")
        mock_vim_prop.return_value = vim.Vim
        new_vim = self.vm_session._get_vim()
        self.assertEqual(new_vim, self.vm_session.vim)


class TestConnectionHandler(base.TestCase):

    def setUp(self):
        super(TestConnectionHandler, self).setUp()
        self.host_ip = "192.168.1.3"
        self.host_username = "user"
        self.host_password = "password"
        self.api_retry_count = 2
        self.wsdl_url = "fake_url"
        self.ca_cert = 'fake_cert'

    def test_create_connection(self):
        vim_session.ConnectionHandler.set_vc_details(self.host_ip,
                                                     self.host_username,
                                                     self.host_password,
                                                     self.api_retry_count,
                                                     self.wsdl_url,
                                                     self.ca_cert)
        vim_session.ConnectionHandler.create_session = False
        vm_session = vim_session.ConnectionHandler.create_connection()
        self.assertEqual(vim_session.ConnectionHandler.host_ip,
                         self.host_ip)
        self.assertEqual(vim_session.ConnectionHandler.host_username,
                         self.host_username)
        self.assertEqual(vim_session.ConnectionHandler.host_password,
                         self.host_password)
        self.assertEqual(vim_session.ConnectionHandler.api_retry_count, 2)
        self.assertEqual(vim_session.ConnectionHandler.wsdl_url,
                         self.wsdl_url)
        self.assertTrue(vm_session)

    def test_connection_handler_stop(self):
        vim_session.ConnectionHandler.set_vc_details(self.host_ip,
                                                     self.host_username,
                                                     self.host_password,
                                                     self.api_retry_count,
                                                     self.wsdl_url,
                                                     self.ca_cert)
        vim_session.ConnectionHandler.create_session = False
        vim_session.ConnectionHandler.create_connection()
        with mock.patch.object(api.VMwareAPISession,
                               "logout") as log_ob:
            vim_session.ConnectionHandler.stop()
            self.assertTrue(log_ob.called)
            self.assertTrue(vim_session.ConnectionHandler.stopped)

    def test_connection_handler_start(self):
        vim_session.ConnectionHandler.start()
        self.assertFalse(vim_session.ConnectionHandler.stopped)

    def test_get_connection(self):
        vim_session.ConnectionHandler.set_vc_details(self.host_ip,
                                                     self.host_username,
                                                     self.host_password,
                                                     self.api_retry_count,
                                                     self.wsdl_url,
                                                     self.ca_cert)
        vim_session.ConnectionHandler.create_session = False
        vm_session = vim_session.ConnectionHandler.create_connection()
        new_session = vim_session.ConnectionHandler.get_connection()
        self.assertEqual(vm_session, new_session)
