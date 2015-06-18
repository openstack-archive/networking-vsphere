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

from networking_vsphere.tests import base
from networking_vsphere.utils import error_util


class TestVimException(base.TestCase):

    def test_str(self):
        exc = Exception("Test Exception")
        exception_summary = "Test Summary "
        vim_excep = error_util.VimException(exception_summary, exc)
        self.assertEqual(str(exception_summary) + str(exc), str(vim_excep))


class TestVimFaultException(base.TestCase):

    def test_str(self):
        exc = Exception("Test Exception")
        fault_list = ["NotAuthenticated"]
        vim_fault = error_util.VimFaultException(fault_list, exc)
        self.assertEqual(str(exc), str(vim_fault))
