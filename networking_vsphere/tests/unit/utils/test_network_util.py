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

import contextlib

import mock

from networking_vsphere.tests import base
from networking_vsphere.tests.unit.utils import fake_vmware_api
from networking_vsphere.tests.unit.utils import stubs
from networking_vsphere.utils import error_util
from networking_vsphere.utils import network_util
from networking_vsphere.utils import vim_util


class TestVmwareNetworkUtil(base.TestCase):

    def setUp(self):
        super(TestVmwareNetworkUtil, self).setUp()
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session
        self.useFixture(stubs.CacheFixture())

    def test_get_dvs_mor_by_uuid(self):
        self.assertTrue(
            network_util.get_dvs_mor_by_uuid(self.session, "fake_dvs"))

    def test_get_dvs_mor_by_non_uuid(self):
        self.assertFalse(
            network_util.get_dvs_mor_by_uuid(self.session, "invalid_dvs"))

    def test_get_dvs_mor_by_name(self):
        self.assertTrue(
            network_util.get_dvs_mor_by_name(self.session, "test_dvs"))

    def test_get_dvs_mor_by_name_for_invalid_dvs(self):
        self.assertFalse(
            network_util.get_dvs_mor_by_name(self.session, "invalid_dvs"))

    def test_get_portgroup_mor_by_name(self):
        dvs_name = "test_dvs"
        port_group_name = "fake_pg"
        dvs = fake_vmware_api.DataObject()
        dvs_config = fake_vmware_api.DataObject()
        port_group_mors = []
        pg1 = fake_vmware_api.create_network()
        pg1.set("summary.name", "pg1")
        port_group_mors.append(pg1)
        pg2 = fake_vmware_api.create_network()
        pg2.set("summary.name", port_group_name)
        port_group_mors.append(pg2)
        dvs_config.ManagedObjectReference = port_group_mors
        with contextlib.nested(
            mock.patch.object(vim_util,
                              'get_properties_for_a_collection_of_objects',
                              return_value=port_group_mors),
            mock.patch.object(network_util, "get_dvs_mor_by_name",
                              return_value=dvs),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=dvs_config)):
                port_group = network_util.get_portgroup_mor_by_name(
                    self.session, dvs_name, port_group_name)
                self.assertEqual(port_group.value, pg2.value)

    def test_get_portgroup_mor_by_name_no_dvs(self):
        dvs_name = "non_existent_dvs"
        port_group_name = "fake_pg"
        with mock.patch.object(network_util, "get_dvs_mor_by_name",
                               return_value=None):
            port_group = network_util.get_portgroup_mor_by_name(
                self.session, dvs_name, port_group_name)
            self.assertIsNone(port_group)

    def test_get_portgroup_mor_by_name_not_found(self):
        dvs_name = "test_dvs"
        port_group_name = "fake_pg"
        dvs = fake_vmware_api.DataObject()
        dvs_config = fake_vmware_api.DataObject()
        port_group_mors = []
        pg1 = fake_vmware_api.create_network()
        pg1.set("summary.name", "pg1")
        port_group_mors.append(pg1)
        dvs_config.ManagedObjectReference = port_group_mors
        with contextlib.nested(
            mock.patch.object(vim_util,
                              'get_properties_for_a_collection_of_objects',
                              return_value=port_group_mors),
            mock.patch.object(network_util, "get_dvs_mor_by_name",
                              return_value=dvs),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=dvs_config)):
                port_group = network_util.get_portgroup_mor_by_name(
                    self.session, dvs_name, port_group_name)
                self.assertIsNone(port_group)

    def test_get_all_portgroup_mors_for_switch(self):
        port_group_mors = network_util.get_all_portgroup_mors_for_switch(
            self.session, "test_dvs")
        self.assertTrue(port_group_mors)
        self.assertTrue(isinstance(port_group_mors, list))

    def test_get_all_portgroup_mors_for_invalid_switch(self):
        dvs_name = "test_invalid_dvs"
        with mock.patch.object(network_util, "get_dvs_mor_by_name",
                               return_value=None):
            self.assertFalse(network_util.get_all_portgroup_mors_for_switch
                             (self.session, dvs_name))

    def test_get_unused_portgroup_names(self):
        dvp = 'DistributedVirtualPortgroup'
        fake_vmware_api._db_content[dvp].values()[0].propSet[1].val = None
        self.assertTrue(network_util.get_unused_portgroup_names(self.session,
                                                                "test_dvs"))

    def test_get_used_portgroup_names(self):
        self.assertFalse(network_util.get_unused_portgroup_names(self.session,
                                                                 "test_dvs"))

    def test_get_portgroup_details(self):
        self.assertEqual(network_util.get_portgroup_details(self.session,
                                                            "test_dvs",
                                                            "fake_pg"), 100)

    def test_get_portgroup_details_not_found(self):
        with mock.patch.object(network_util, "get_portgroup_mor_by_name",
                               return_value=None):
            self.assertEqual(network_util.get_portgroup_details(
                self.session,
                "test_invalid_dvs",
                "fake_pg"), 0)

    def test_create_port_group_existing(self):
        dvs_name = "test_dvs"
        pg_name = "fake_pg"
        vlanid = "100"
        pg = fake_vmware_api.DataObject()
        defaultPortConfig = fake_vmware_api.DataObject()
        vlan = fake_vmware_api.DataObject()
        vlan.vlanId = vlanid
        defaultPortConfig.vlan = vlan
        port_group_config = fake_vmware_api.DataObject()
        port_group_config.defaultPortConfig = defaultPortConfig
        with contextlib.nested(
            mock.patch.object(network_util, "get_portgroup_mor_by_name",
                              return_value=pg),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=port_group_config)
        ) as (mor, get_prop):
                network_util.create_port_group(self.session, dvs_name, pg_name,
                                               vlanid)
                self.assertTrue(get_prop.called)

    def test_create_port_group_with_invalid_vlanid(self):
        dvs_name = "test_dvs"
        pg_name = "fake_pg"
        vlanid = "100"
        pg = fake_vmware_api.DataObject()
        defaultPortConfig = fake_vmware_api.DataObject()
        vlan = fake_vmware_api.DataObject()
        vlan.vlanId = "200"
        defaultPortConfig.vlan = vlan
        port_group_config = fake_vmware_api.DataObject()
        port_group_config.defaultPortConfig = defaultPortConfig
        with contextlib.nested(
            mock.patch.object(network_util, "get_portgroup_mor_by_name",
                              return_value=pg),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=port_group_config)):
                raised = self.assertRaises(error_util.RunTimeError,
                                           network_util.create_port_group,
                                           self.session,
                                           dvs_name, pg_name, vlanid)
                self.assertTrue(raised)

    def test_create_port_group_err_status(self):
        dvs_name = "test_dvs"
        pg_name = "fake_pg"
        vlanid = "5001"
        task_info = fake_vmware_api.DataObject()
        task_info.name = "AddDVPortgroup_Task"
        task_info.key = "task-1234"
        task_info.state = "error"
        task_info.error = fake_vmware_api.DataObject()
        with contextlib.nested(
            mock.patch.object(network_util, "get_portgroup_mor_by_name",
                              return_value=None),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=task_info)):
                raised = self.assertRaises(error_util.RunTimeError,
                                           network_util.create_port_group,
                                           self.session, dvs_name,
                                           pg_name, vlanid)
                self.assertTrue(raised)
