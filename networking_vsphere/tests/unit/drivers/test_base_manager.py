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

from networking_vsphere.drivers import base_manager
from networking_vsphere.tests import base


class DriverManagerTestCase(base.TestCase):

    def setUp(self):
        super(DriverManagerTestCase, self).setUp()
        self.base_manager = base_manager.DriverManager()

    def test_initialize_driver(self):
        self.assertRaises(NotImplementedError,
                          self.base_manager.initialize_driver)

    def test_get_driver(self):
        self.assertIsNone(self.base_manager.get_driver())

    def test_start(self):
        self.assertIsNone(self.base_manager.start())

    def test_pause(self):
        self.assertIsNone(self.base_manager.pause())

    def test_stop(self):
        self.assertIsNone(self.base_manager.stop())
