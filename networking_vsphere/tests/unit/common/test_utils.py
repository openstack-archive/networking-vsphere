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

    def test_fullname(self):
        class_name = utils.fullname(str)
        self.assertTrue(class_name == "str")
