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
#

from networking_vsphere.tests import base
from networking_vsphere.tests.unit.utils import fake_vmware_api
from networking_vsphere.utils import vim_util


class VimUtilsTestCase(base.TestCase):

    def setUp(self):
        super(VimUtilsTestCase, self).setUp()

    def test_build_recursive_traversal_spec(self):
        client_factory = fake_vmware_api.FakeFactory()
        trav_specs = vim_util.build_recursive_traversal_spec(client_factory)
        spec_names = ["rpToRp", "rpToVm", "crToRp", "crToH",
                      "dcToHf", "dcToVmf", "dcToDs", "hToVm",
                      "dsToVm", "visitFolders"]
        for spec in trav_specs:
            self.assertIn(spec.name, spec_names)

    def test_dynamic_property(self):
        vim = fake_vmware_api.FakeVimUtil()
        mob = {"_type": "vm"}
        vim_util.get_dynamic_property(vim, mob, "VM", "runtime.host")
        self.assertTrue(vim.RetrievePropertiesExCalled)
        self.assertTrue(vim.ContinueRetrievePropertiesExCalled)

    def test_dynamic_property_none_object(self):
        vim = fake_vmware_api.FakeVimUtil()
        vim_util.get_dynamic_property(vim, None, "VM", "runtime.host")
        self.assertFalse(vim.RetrievePropertiesExCalled)

    def test_get_property_filter_specs(self):
        vim = fake_vmware_api.FakeVimUtil()
        property_dict = {"virtualmachine":
                         ["name", "config"]}
        property_filter_spec = vim_util.get_property_filter_specs(
            vim, property_dict, None)
        objSpec = property_filter_spec.objectSet[0]
        self.assertEqual(objSpec.obj, vim.service_content.rootFolder)

    def test_get_properties_for_a_collection_of_objects(self):
        vim = fake_vmware_api.FakeVimUtil()
        obj_list = [fake_vmware_api.FakeDynamicPropertyObject]
        properties = ["name", "config"]
        objs = vim_util.get_properties_for_a_collection_of_objects(
            vim, "FakeDynamicPropertyObject", obj_list, properties)
        self.assertEqual(len(objs), 1)
        self.assertTrue(vim.RetrievePropertiesExCalled)
        for obj in objs:
            for prop in obj.propSet:
                self.assertIn(prop.name, properties)

    def test_get_properties_for_a_collection_empty(self):
        vim = fake_vmware_api.FakeVimUtil()
        obj_list = []
        properties = ["name", "config"]
        objs = vim_util.get_properties_for_a_collection_of_objects(
            vim, "FakeDynamicPropertyObject", obj_list, properties)
        self.assertEqual(len(objs), 0)
        self.assertFalse(vim.RetrievePropertiesExCalled)

    def test_get_objects(self):
        vim = fake_vmware_api.FakeVimUtil()
        vim_util.get_objects(vim, "DataCenter")
        self.assertTrue(vim.RetrievePropertiesExCalled)
