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

    def test_add_esx_hostname_for_vm(self):
        vm_uuid = "VM-1234-5678"
        hostname = "fake_esx_host"
        cache.VCCache.add_esx_hostname_for_vm(vm_uuid, hostname)
        self.assertEqual(hostname,
                         cache.VCCache.get_esx_hostname_for_vm(vm_uuid))

    def test_add_cluster_mor_for_vm(self):
        vm_uuid = "VM-1234-5678-%s"
        cluster_mor = "Cluster-1234-5678-%s"
        for i in range(0, 1000):
            cache.VCCache.add_cluster_mor_for_vm(vm_uuid % i, cluster_mor % i)
        cache.VCCache.add_cluster_mor_for_vm(vm_uuid % 1000,
                                             cluster_mor % 1000)
        self.assertEqual(1000, len(cache.VCCache.vm_to_cluster))
        self.assertEqual(cluster_mor % 1000,
                         cache.VCCache.get_cluster_mor_for_vm(vm_uuid % 1000))

    def test_add_path_for_cluster_id(self):
        cluster_id = "Cluster-1234-5678"
        cluster_path = "fake_path"
        cache.VCCache.add_path_for_cluster_id(cluster_id, cluster_path)
        self.assertEqual(cluster_path,
                         cache.VCCache.get_cluster_path_for_id(cluster_id))

    def test_get_cluster_path_for_id_notexisting(self):
        cluster_id = "Cluster-1234-5678"
        self.assertIsNone(cache.VCCache.get_cluster_path_for_id(cluster_id))

    def test_add_vm_mor_for_uuid(self):
        uuid = "VM-1234-5678"
        vm_mor = fake_vmware_api.DataObject()
        vm_mor.value = "vm-123"
        cache.VCCache.add_vm_mor_for_uuid(uuid, vm_mor)
        self.assertEqual(vm_mor, cache.VCCache.get_vm_mor_for_uuid(uuid))

    def test_add_vm_model_for_uuid(self):
        vm_uuid = "VM-1234-5678"
        vm = "VirtualMachine"
        cache.VCCache.add_vm_model_for_uuid(vm_uuid, vm)
        self.assertEqual(vm,
                         cache.VCCache.get_vm_model_for_uuid(vm_uuid))

    def test_add_switch_for_cluster_path(self):
        cluster_path = "fake_path"
        switch_name = "fake_switch"
        cache.VCCache.add_switch_for_cluster_path(cluster_path, switch_name)
        self.assertEqual(switch_name,
                         cache.VCCache.get_switch_for_cluster_path(
                             cluster_path))

    def test_remove_vm_for_uuid(self):
        uuid = "VM-1234-5678"
        vm_mor = fake_vmware_api.DataObject()
        vm_mor.value = "vm-123"
        cache.VCCache.add_vm_mor_for_uuid(uuid, vm_mor)
        self.assertEqual(cache.VCCache.get_vm_mor_for_uuid(uuid),
                         vm_mor)
        self.assertEqual(cache.VCCache.get_vmuuid_for_moid(vm_mor.value),
                         uuid)

        cache.VCCache.remove_vm_for_uuid(uuid)
        self.assertIsNone(cache.VCCache.get_vm_mor_for_uuid(uuid))
        self.assertIsNone(cache.VCCache.get_vmuuid_for_moid(vm_mor.value))

    def test_remove_cluster_path(self):
        cluster_path = "fake_path"
        switch_name = "fake_switch"
        cache.VCCache.add_switch_for_cluster_path(cluster_path, switch_name)

        cache.VCCache.remove_cluster_path(cluster_path)
        self.assertIsNone(cache.VCCache.get_switch_for_cluster_path(
                          cluster_path))

    def test_remove_cluster_id(self):
        cluster_id = "Cluster-1234-5678"
        cluster_path = "fake_path"
        cache.VCCache.add_path_for_cluster_id(cluster_id, cluster_path)

        cache.VCCache.remove_cluster_id(cluster_id)
        self.assertIsNone(cache.VCCache.get_cluster_path_for_id(cluster_id))

    def test_get_cluster_id_for_path(self):
        cluster_id = "Cluster-1234-5678"
        cluster_path = "fake_path"
        cache.VCCache.add_path_for_cluster_id(cluster_id, cluster_path)

        self.assertEqual(cluster_id,
                         cache.VCCache.get_cluster_id_for_path(cluster_path))

    def test_get_cluster_id_for_path_notexisting(self):
        cluster_path = "fake_path"
        self.assertIsNone(cache.VCCache.get_cluster_id_for_path(cluster_path))

    def test_get_cluster_switch_mapping(self):
        cluster_path = "fake_path"
        switch_name = "fake_switch"
        cache.VCCache.add_switch_for_cluster_path(cluster_path, switch_name)
        # TODO(romilg): Revisit to use assertEqual here.
        self.assertIsNotNone(cache.VCCache.get_cluster_switch_mapping)
