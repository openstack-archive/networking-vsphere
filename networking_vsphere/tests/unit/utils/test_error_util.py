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


class TestObject:
    pass


class TestFaultCheckers(base.TestCase):

    def test_retrieveproperties_fault_checker_none(self):
        try:
            error_util.FaultCheckers.retrieveproperties_fault_checker(None)
        except error_util.VimFaultException as e:
            self.assertIn("NotAuthenticated", e.fault_list)
        else:
            self.fail("VimFaultException not raised")

    def test_retrieveproperties_fault_checker(self):
        exc1 = error_util.SessionOverLoadException(None, None)
        exc2 = error_util.VimAttributeError(None, None)
        missing_ele1 = TestObject()
        missing_ele1.fault = TestObject()
        missing_ele1.fault.fault = exc1
        missing_ele2 = TestObject()
        missing_ele2.fault = TestObject()
        missing_ele2.fault.fault = exc2
        obj_cont = TestObject()
        obj_cont.missingSet = [missing_ele1, missing_ele2]
        resp_obj = [obj_cont]
        try:
            error_util.FaultCheckers.retrieveproperties_fault_checker(resp_obj)
        except error_util.VimFaultException as e:
            self.assertIn("SessionOverLoadException", e.fault_list)
            self.assertIn("VimAttributeError", e.fault_list)
        else:
            self.fail("VimFaultException not raised")

    def test_retrieveproperties_fault_checker_no_fault(self):
        obj_cont = TestObject()
        resp_obj = [obj_cont]
        self.assertIsNone(error_util.FaultCheckers.
                          retrieveproperties_fault_checker(resp_obj))


class TestVimFaultException(base.TestCase):

    def test_str(self):
        exc = Exception("Test Exception")
        fault_list = ["NotAuthenticated"]
        vim_fault = error_util.VimFaultException(fault_list, exc)
        self.assertEqual(str(exc), str(vim_fault))