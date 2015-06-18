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

from networking_vsphere.tests import base
from networking_vsphere.tests.unit.utils import fake_vmware_api
from networking_vsphere.tests.unit.utils import stubs
from networking_vsphere.utils import resource_util


class TestVmwareResourceUtil(base.TestCase):

    def setUp(self):
        super(TestVmwareResourceUtil, self).setUp()
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session
        self.useFixture(stubs.CacheFixture())

    def test_get_host_mor_for_vm(self):
        host_mor = resource_util.get_host_mor_for_vm(
            self.session, fake_vmware_api.Constants.VM_UUID)
        self.assertTrue(host_mor)

    def test_get_host_mor_for_invalid_vm(self):
        host_mor = resource_util.get_host_mor_for_vm(
            self.session, "1234-1234-1234-1234")
        self.assertFalse(host_mor)

    def test_get_host_mor_by_name(self):
        host_mor = resource_util.get_host_mor_by_name(
            self.session, fake_vmware_api.Constants.HOST_NAME)
        self.assertTrue(host_mor)

    def test_get_host_mor_for_invalid_hostname(self):
        host_mor = resource_util.get_host_mor_by_name(
            self.session, "fake_host")
        self.assertFalse(host_mor)

    def test_get_hostname_for_host_mor(self):
        host_mor = resource_util.get_host_mor_by_name(
            self.session, fake_vmware_api.Constants.HOST_NAME)
        host_name = resource_util.get_hostname_for_host_mor(
            self.session, host_mor)
        self.assertTrue(host_name)

    def test_get_vm_mor_by_name(self):
        vm_mor = resource_util.get_vm_mor_by_name(
            self.session, fake_vmware_api.Constants.VM_NAME)
        self.assertTrue(vm_mor)

    def test_get_cluster_mor_for_vm(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_vmware_api.Constants.VM_UUID)
        self.assertTrue(cluster_mor)

    def test_get_cluster_mor_for_invalid_vm(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, "1234-1234-1234-1234")
        self.assertFalse(cluster_mor)

    def test_get_vm_mor_for_uuid(self):
        vm_mor = resource_util.get_vm_mor_for_uuid(
            self.session, fake_vmware_api.Constants.VM_UUID)
        self.assertTrue(vm_mor)

    def test_get_vm_mor_for_invalid_uuid(self):
        vm_mor = resource_util.get_vm_mor_for_uuid(
            self.session, "1234-1234-1234-1234")
        self.assertFalse(vm_mor)

    def test_get_host_mors_for_cluster(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_vmware_api.Constants.VM_UUID)
        self.assertTrue(cluster_mor)
        host_mor = resource_util.get_host_mors_for_cluster(
            self.session, cluster_mor)
        self.assertTrue(host_mor)
        self.assertTrue(isinstance(host_mor, list))

    def test_get_host_mors_for_cluster_with_invalid_mor(self):
        host_mor = resource_util.get_host_mors_for_cluster(self.session, None)
        self.assertFalse(host_mor)

    def test_get_extraconfigs_for_vm(self):
        vm_mor = resource_util.get_vm_mor_for_uuid(
            self.session, fake_vmware_api.Constants.VM_UUID)
        self.assertTrue(vm_mor)
        extraconfigs = resource_util.get_extraconfigs_for_vm(
            self.session, vm_mor)
        self.assertTrue(extraconfigs)

    def tearDown(self):
        base.TestCase.tearDown(self)
