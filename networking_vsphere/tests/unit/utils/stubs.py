# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
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

import fixtures

from networking_vsphere.tests.unit.utils import fake_vmware_api
from networking_vsphere.utils import cache
from networking_vsphere.utils import error_util
from networking_vsphere.utils import vim_session
from networking_vsphere.utils import vim_util


def fake_get_vim_object(arg):
    """Stubs out the VMwareAPISession's get_vim_object method."""
    return fake_vmware_api.FakeVim()


@classmethod
def fake_create_connection(cls):
    cls.session = FakeVMwareSession(cls.host_ip,
                                    cls.host_username,
                                    cls.host_password,
                                    cls.api_retry_count,
                                    cls.wsdl_url)
    return cls.session


class FakeVMwareSession(object):

    def __init__(self, host_ip, host_username, host_password,
                 api_retry_count, wsdl_url, scheme="https", https_port=443,
                 ca_cert=None):
        self._host_ip = host_ip
        self._host_username = host_username
        self._host_password = host_password
        self._https_port = https_port
        self.api_retry_count = api_retry_count
        self.wsdl_url = wsdl_url
        self._scheme = scheme
        self._session_id = None
        self.vim = fake_get_vim_object("fake_module")
        session = self.vim.Login(self.vim.get_service_content().sessionManager,
                                 userName=self._host_username,
                                 password=self._host_password)
        self._session_id = session.key

    def _get_vim(self):
        return self.vim

    def _call_method(self, module, method, *args, **kwargs):
        temp_module = module
        for method_elem in method.split("."):
            temp_module = getattr(temp_module, method_elem)
            return temp_module(self.vim, *args, **kwargs)

    def wait_for_task(self, task_ref):
        task_info = self._call_method(vim_util, "get_dynamic_property",
                                      task_ref, "Task", "info")
        if task_info.state == "error":
            raise error_util.RunTimeError("Incorrect Parameter")
        return


class FakeVmware(fixtures.Fixture):

    def __init__(self):
        self.session = None

    def setUp(self):
        super(FakeVmware, self).setUp()
        fake_vmware_api.reset()
        self.useFixture(fixtures.MonkeyPatch(
            'networking_vsphere.utils.vim_session.'
            'ConnectionHandler.create_connection', fake_create_connection))
        self.vcenter_ip = "192.168.1.3"
        self.vcenter_username = "user"
        self.vcenter_password = "password"
        self.api_retry_count = 2
        self.wsdl_loc = "https://192.168.1.3/sdk/fake.wsdl"
        self.ca_cert = "rui-ca-cert.pem"
        vim_session.ConnectionHandler.set_vc_details(self.vcenter_ip,
                                                     self.vcenter_username,
                                                     self.vcenter_password,
                                                     self.api_retry_count,
                                                     self.wsdl_loc,
                                                     self.ca_cert)
        self.session = vim_session.ConnectionHandler.create_connection()
        self.addCleanup(fake_vmware_api.cleanup)


class CacheFixture(fixtures.Fixture):

    def setUp(self):
        fixtures.Fixture.setUp(self)
        cache.VCCache.reset()
        self.addCleanup(cache.VCCache.reset)
