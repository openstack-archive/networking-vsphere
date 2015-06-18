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

from networking_vsphere.common import error
from networking_vsphere.common import utils
from networking_vsphere.drivers import driver
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.drivers import fake_driver


class CommonUtilsTestCase(base.TestCase):

    def setUp(self):
        super(CommonUtilsTestCase, self).setUp()
        driver_path = "networking_vsphere.tests.unit.drivers.fake_driver."
        valid_driver = "FakeNetworkDriver"
        invalid_driver = "FakeInvalidDriver"
        self.fake_network_driver = driver_path + valid_driver
        self.fake_invalid_driver = driver_path + invalid_driver

    def test_import_class(self):
        class_obj = utils.import_class(self.fake_network_driver)
        self.assertTrue(class_obj == fake_driver.FakeNetworkDriver)

    def test_import_class_exc(self):
        import_class_fn = utils.import_class
        invalid_class = self.fake_network_driver + "Invalid"
        import_err = ImportError
        self.assertRaises(import_err, import_class_fn, invalid_class)

    def test_load_object(self):
        driver_obj = utils.load_object(
            self.fake_network_driver, driver.NetworkDriver)
        self.assertTrue(isinstance(driver_obj, fake_driver.FakeNetworkDriver))

    def test_non_loadable_object(self):
        load_object_fn = utils.load_object
        invalid_class = self.fake_invalid_driver
        type_err = TypeError
        self.assertRaises(type_err, load_object_fn,
                          invalid_class, driver.NetworkDriver)

    def test_fullname(self):

        class Sample(object):
            pass

        fake_sample = Sample()
        class_name = utils.fullname(fake_sample)
        result = "networking_vsphere.tests.unit.common.test_utils.Sample"
        self.assertTrue(class_name == result)

    def test_require_state(self):

        class TestClass(object):
            @utils.require_state(set(["RUNNING"]), True)
            def method_test(self):
                return "Success"

        obj = TestClass()
        obj.state = "RUNNING"
        self.assertTrue(obj.method_test() == "Success")

    def test_require_state_excp(self):

        class TestClass(object):
            @utils.require_state(set(["RUNNING"]), True)
            def method_test(self):
                return "Success"

        obj = TestClass()
        obj.state = "NOTRUNNING"
        self.assertRaises(error.OVSvAppNeutronAgentError, obj.method_test)
