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

import eventlet
import mock
import os

from networking_vsphere.drivers import dvs_driver
from networking_vsphere.drivers import manager
from networking_vsphere.drivers import vc_driver
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.drivers import fake_driver
from networking_vsphere.tests.unit.utils import stubs
from networking_vsphere.utils import vim_session


class TestVcenterManager(base.TestCase):

    def setUp(self):
        super(TestVcenterManager, self).setUp()
        self.callback = fake_driver.MockCallback()
        self.manager = manager.VcenterManager(self.callback)
        self.useFixture(stubs.FakeVmware())
        self.LOG = manager.LOG

    def test_parse_mapping(self):
        cluster_dvs_list = self.manager._parse_mapping("abc:123")
        self.assertEqual(len(cluster_dvs_list), 1)

    def test_parse_mapping_multiple(self):
        cluster_dvs_list = self.manager._parse_mapping("abc:123,def:456")
        self.assertEqual(len(cluster_dvs_list), 2)

    def test_initialize_driver_noconf(self):
        with mock.patch.object(vim_session.ConnectionHandler, "stop",
                               return_value=None), \
                mock.patch.object(self.LOG, "error") as mock_log_error:
            self.manager.initialize_driver()
            self.assertIsNone(self.manager.driver)
            self.assertTrue(mock_log_error.called)

    def test_initialize_driver(self):
        fake_tuple = ["dc/host/cluster1:dvs1"]
        self.flags(vcenter_ip="vcenter.test.com", group='VMWARE')
        self.flags(vcenter_username="fake_user", group='VMWARE')
        self.flags(vcenter_password="fake_pass", group='VMWARE')
        self.flags(vcenter_api_retry_count="1", group='VMWARE')
        self.flags(wsdl_location="http://fake.test.com", group='VMWARE')
        self.flags(cluster_dvs_mapping=fake_tuple, group='VMWARE')
        with mock.patch.object(vim_session.ConnectionHandler, "stop",
                               return_value=None), \
                mock.patch.object(eventlet, "spawn"), \
                mock.patch.object(vc_driver.VCNetworkDriver, "add_cluster",
                                  return_value=True):
            self.assertEqual(len(self.manager.cluster_switch_mapping), 0)
            self.manager.initialize_driver()
            self.assertIsNotNone(self.manager.driver)
            self.assertEqual(len(self.manager.cluster_switch_mapping), 1)

    def test_initialize_driver_with_cert_check_and_cert_path(self):
        fake_tuple = ["dc/host/cluster1:dvs1"]
        ca_path = "/etc/ssl/certs/certs.pem"
        self.flags(vcenter_ip="vcenter.test.com", group='VMWARE')
        self.flags(vcenter_username="fake_user", group='VMWARE')
        self.flags(vcenter_password="fake_pass", group='VMWARE')
        self.flags(vcenter_api_retry_count="1", group='VMWARE')
        self.flags(wsdl_location="http://fake.test.com", group='VMWARE')
        self.flags(cert_check=True, group='VMWARE')
        self.flags(cert_path=ca_path, group='VMWARE')
        self.flags(cluster_dvs_mapping=fake_tuple, group='VMWARE')
        with mock.patch.object(vim_session.ConnectionHandler, "stop",
                               return_value=None), \
                mock.patch.object(eventlet, "spawn"), \
                mock.patch.object(vc_driver.VCNetworkDriver, "add_cluster",
                                  return_value=True), \
                mock.patch.object(os.path, "isfile", return_value=True):
            self.assertEqual(len(self.manager.cluster_switch_mapping), 0)
            self.manager.initialize_driver()
            self.assertIsNotNone(self.manager.driver)
            self.assertEqual(len(self.manager.cluster_switch_mapping), 1)
            self.assertEqual(self.manager.ca_path, ca_path)

    def test_initialize_driver_with_cert_check_false_and_cert_path(self):
        fake_tuple = ["dc/host/cluster1:dvs1"]
        self.flags(vcenter_ip="vcenter.test.com", group='VMWARE')
        self.flags(vcenter_username="fake_user", group='VMWARE')
        self.flags(vcenter_password="fake_pass", group='VMWARE')
        self.flags(vcenter_api_retry_count="1", group='VMWARE')
        self.flags(wsdl_location="http://fake.test.com", group='VMWARE')
        self.flags(cert_check=False, group='VMWARE')
        self.flags(cert_path="/etc/ssl/certs/certs.pem", group='VMWARE')
        self.flags(cluster_dvs_mapping=fake_tuple, group='VMWARE')
        with mock.patch.object(vim_session.ConnectionHandler, "stop",
                               return_value=None), \
                mock.patch.object(eventlet, "spawn"), \
                mock.patch.object(vc_driver.VCNetworkDriver, "add_cluster",
                                  return_value=True), \
                mock.patch.object(os.path, "isfile", return_value=True):
            self.assertEqual(len(self.manager.cluster_switch_mapping), 0)
            self.manager.initialize_driver()
            self.assertIsNotNone(self.manager.driver)
            self.assertEqual(len(self.manager.cluster_switch_mapping), 1)
            self.assertIsNone(self.manager.ca_path)

    def test_initialize_driver_without_cert_path_exception(self):
        fake_tuple = ["dc/host/cluster1:dvs1"]
        self.flags(vcenter_ip="vcenter.test.com", group='VMWARE')
        self.flags(vcenter_username="fake_user", group='VMWARE')
        self.flags(vcenter_password="fake_pass", group='VMWARE')
        self.flags(vcenter_api_retry_count="1", group='VMWARE')
        self.flags(wsdl_location="http://fake.test.com", group='VMWARE')
        self.flags(cert_check=True, group='VMWARE')
        self.flags(cert_path=None, group='VMWARE')
        self.flags(cluster_dvs_mapping=fake_tuple, group='VMWARE')
        with mock.patch.object(vim_session.ConnectionHandler, "stop",
                               return_value=None), \
                mock.patch.object(self.LOG, "error") as mock_log_error:
            self.assertEqual(len(self.manager.cluster_switch_mapping), 0)
            self.assertRaises(SystemExit, self.manager.initialize_driver)
            self.assertTrue(mock_log_error.called)

    def test_initialize_driver_invalid_cert_path_exception(self):
        fake_tuple = ["dc/host/cluster1:dvs1"]
        self.flags(vcenter_ip="vcenter.test.com", group='VMWARE')
        self.flags(vcenter_username="fake_user", group='VMWARE')
        self.flags(vcenter_password="fake_pass", group='VMWARE')
        self.flags(vcenter_api_retry_count="1", group='VMWARE')
        self.flags(wsdl_location="http://fake.test.com", group='VMWARE')
        self.flags(cert_check=True, group='VMWARE')
        self.flags(cert_path="/etc/ssl/certs/certs.pem", group='VMWARE')
        self.flags(cluster_dvs_mapping=fake_tuple, group='VMWARE')
        with mock.patch.object(vim_session.ConnectionHandler, "stop",
                               return_value=None), \
                mock.patch.object(self.LOG, "error") as mock_log_error, \
                mock.patch.object(os.path, "isfile", return_value=False):
            self.assertEqual(len(self.manager.cluster_switch_mapping), 0)
            self.assertRaises(SystemExit, self.manager.initialize_driver)
            self.assertTrue(mock_log_error.called)

    def test_start(self):
        self.manager.driver = None
        self.assertIsNone(self.manager.start())

    def test_pause(self):
        with mock.patch.object(dvs_driver.DvsNetworkDriver, "pause") as pause:
            self.manager.driver = dvs_driver.DvsNetworkDriver()
            self.manager.pause()
            self.assertTrue(pause.called)

    def test_pause_none_driver(self):
        self.manager.driver = None
        self.assertIsNone(self.manager.pause())

    @mock.patch.object(vim_session.ConnectionHandler, "stop")
    def test_stop(self, mock_conn_stop):
        mock_conn_stop.return_value = None
        with mock.patch.object(dvs_driver.DvsNetworkDriver, "stop"
                               ) as mock_dvs_stop:
            self.manager.driver = dvs_driver.DvsNetworkDriver()
            self.manager.stop()
            self.assertTrue(mock_dvs_stop.called)
