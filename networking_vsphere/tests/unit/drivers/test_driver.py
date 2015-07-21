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

from networking_vsphere.drivers import driver
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.drivers import fake_driver


class TestNetworkDriver(base.TestCase):

    def setUp(self):
        super(TestNetworkDriver, self).setUp()
        self.driver = driver.NetworkDriver()

    def test_set_callback(self):
        mock_driver = fake_driver.MockNetworkDriver()
        callback = fake_driver.MockCallback()
        mock_driver.set_callback(callback)
        self.assertEqual(mock_driver.callback_impl, callback)

    def test_monitor_events(self):
        self.assertRaises(NotImplementedError,
                          self.driver.monitor_events)

    def test_pause(self):
        self.assertIsNone(self.driver.pause())

    def test_stop(self):
        self.assertIsNone(self.driver.stop())

    def test_is_connected(self):
        self.assertRaises(NotImplementedError,
                          self.driver.is_connected)

    def test_create_network(self):
        self.assertRaises(NotImplementedError,
                          self.driver.create_network, None, None)

    def test_delete_network(self):
        self.assertRaises(NotImplementedError,
                          self.driver.delete_network, None, None)

    def test_prepare_port_group(self):
        self.assertRaises(NotImplementedError,
                          self.driver.prepare_port_group, None, None, None)

    def test_update_port_group(self):
        self.assertRaises(NotImplementedError,
                          self.driver.update_port_group, None, None, None)

    def test_get_vlanid_for_port_group(self):
        self.assertRaises(NotImplementedError,
                          self.driver.get_vlanid_for_port_group, None, None)

    def test_get_vlanid_for_portgroup_key(self):
        self.assertRaises(NotImplementedError,
                          self.driver.get_vlanid_for_portgroup_key, None)

    def test_get_vm_ref_by_uuid(self):
        self.assertRaises(NotImplementedError,
                          self.driver.get_vm_ref_by_uuid, None)

    def test_wait_for_portgroup(self):
        self.assertRaises(NotImplementedError,
                          self.driver.wait_for_portgroup, None, None)

    def test_process_delete_vm(self):
        self.assertRaises(NotImplementedError,
                          self.driver.process_delete_vm, None)


class TestNetworkDriverCallback(base.TestCase):

    def setUp(self):
        super(TestNetworkDriverCallback, self).setUp()
        self.callback = driver.NetworkDriverCallback()

    def test_process_event(self):
        self.assertRaises(NotImplementedError,
                          self.callback.process_event, None)
