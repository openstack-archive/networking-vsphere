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
from networking_vsphere.tests.unit.utils import fake_vmware_api
from networking_vsphere.tests.unit.utils import stubs
from networking_vsphere.utils import cache


class VCCacheTestCase(base.TestCase):

    def setUp(self):
        base.TestCase.setUp(self)
        self.useFixture(stubs.CacheFixture())

    def test_add_cluster_mor_for_vm(self):
        vm_id = "ABCD-EFG-%s"
        cluster_id = "Cluster-%s"
        for i in range(0, 1000):
            cache.VCCache.add_cluster_mor_for_vm(vm_id % i, cluster_id % i)
        cache.VCCache.add_cluster_mor_for_vm(vm_id % 1000, cluster_id % 1000)
        self.assertEqual(len(cache.VCCache.vm_to_cluster), 1000)
        self.assertEqual(
            cache.VCCache.get_cluster_mor_for_vm(vm_id % 1000),
            cluster_id % 1000)

    def test_get_cluster_id_for_path_notexisting(self):
        cache.VCCache.add_path_for_cluster_id("cluster-1", "path1")
        self.assertIsNone(cache.VCCache.get_cluster_id_for_path("path2"))

    def test_remove_vm_for_uuid(self):
        uuid = "VM-1234-5678"
        vm_mor = fake_vmware_api.DataObject()
        vm_mor._type = "VirtualMachine"
        vm_mor.value = "vm-123"
        cache.VCCache.add_vm_mor_for_uuid(uuid, vm_mor)
        self.assertEqual(cache.VCCache.get_vm_mor_for_uuid(uuid), vm_mor)
        self.assertEqual(cache.VCCache.get_vmuuid_for_moid(vm_mor.value), uuid)
        cache.VCCache.remove_vm_for_uuid(uuid)
        self.assertIsNone(cache.VCCache.get_vm_mor_for_uuid(uuid))
        self.assertIsNone(cache.VCCache.get_vmuuid_for_moid(vm_mor.value))