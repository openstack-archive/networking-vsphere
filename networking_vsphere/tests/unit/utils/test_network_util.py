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

import mock

from networking_vsphere.common import constants
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.utils import fake_vmware_api as fake_api
from networking_vsphere.tests.unit.utils import stubs
from networking_vsphere.utils import error_util
from networking_vsphere.utils import network_util
from networking_vsphere.utils import resource_util
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

    @mock.patch.object(vim_util, 'get_properties_for_a_collection_of_objects')
    @mock.patch.object(network_util, "get_dvs_mor_by_name")
    @mock.patch.object(vim_util, "get_dynamic_property")
    def test_get_portgroup_mor_by_name(self, mock_get_dy_pro,
                                       mock_get_dvs_mor, mock_get_pro):
        dvs_name = "test_dvs"
        port_group_name = fake_api.Constants.PORTGROUP_NAME
        dvs = fake_api.DataObject()
        dvs_config = fake_api.DataObject()
        port_group_mors = []
        pg1 = fake_api.create_network()
        pg1.set("summary.name", "pg1")
        port_group_mors.append(pg1)
        pg2 = fake_api.create_network()
        pg2.set("summary.name", port_group_name)
        port_group_mors.append(pg2)
        dvs_config.ManagedObjectReference = port_group_mors
        mock_get_pro.return_value = port_group_mors
        mock_get_dvs_mor.return_value = dvs
        mock_get_dy_pro.return_value = dvs_config
        port_group = network_util.get_portgroup_mor_by_name(
            self.session, dvs_name, port_group_name)
        self.assertEqual(port_group.value, pg2.value)

    def test_get_portgroup_mor_by_name_no_dvs(self):
        dvs_name = "non_existent_dvs"
        port_group_name = fake_api.Constants.PORTGROUP_NAME
        with mock.patch.object(network_util, "get_dvs_mor_by_name",
                               return_value=None):
            port_group = network_util.get_portgroup_mor_by_name(
                self.session, dvs_name, port_group_name)
            self.assertIsNone(port_group)

    @mock.patch.object(vim_util, 'get_properties_for_a_collection_of_objects')
    @mock.patch.object(network_util, "get_dvs_mor_by_name")
    @mock.patch.object(vim_util, "get_dynamic_property")
    def test_get_portgroup_mor_by_name_not_found(
            self, mock_get_dy_pro, mock_get_dvs_mor, mock_get_pro):
        dvs_name = "test_dvs"
        port_group_name = fake_api.Constants.PORTGROUP_NAME
        dvs = fake_api.DataObject()
        dvs_config = fake_api.DataObject()
        port_group_mors = []
        pg1 = fake_api.create_network()
        pg1.set("summary.name", "pg1")
        port_group_mors.append(pg1)
        dvs_config.ManagedObjectReference = port_group_mors
        mock_get_pro.return_value = port_group_mors
        mock_get_dvs_mor.return_value = dvs
        mock_get_dy_pro.return_value = dvs_config
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
        fake_api._db_content[dvp].values()[0].propSet[1].val = None
        self.assertTrue(network_util.get_unused_portgroup_names(self.session,
                                                                "test_dvs"))

    def test_get_used_portgroup_names(self):
        self.assertFalse(network_util.get_unused_portgroup_names(self.session,
                                                                 "test_dvs"))

    def test_get_portgroup_details(self):
        res = network_util.get_portgroup_details(self.session,
                                                 "test_dvs",
                                                 fake_api.Constants.
                                                 PORTGROUP_NAME)
        self.assertEqual(100, res)

    def test_get_portgroup_details_not_found(self):
        with mock.patch.object(network_util, "get_portgroup_mor_by_name",
                               return_value=None):
            self.assertEqual(network_util.get_portgroup_details(
                self.session,
                "test_invalid_dvs",
                fake_api.Constants.PORTGROUP_NAME), constants.DEAD_VLAN)

    @mock.patch.object(network_util, "get_portgroup_mor_by_name")
    @mock.patch.object(vim_util, "get_dynamic_property")
    def test_create_port_group_existing(self, mock_get_prop, mock_mor):
        dvs_name = "test_dvs"
        pg_name = fake_api.Constants.PORTGROUP_NAME
        vlanid = "100"
        pg = fake_api.DataObject()
        defaultPortConfig = fake_api.DataObject()
        vlan = fake_api.DataObject()
        vlan.vlanId = vlanid
        defaultPortConfig.vlan = vlan
        port_group_config = fake_api.DataObject()
        port_group_config.defaultPortConfig = defaultPortConfig
        mock_mor.return_value = pg
        mock_get_prop.return_value = port_group_config
        network_util.create_port_group(self.session, dvs_name, pg_name,
                                       vlanid)
        self.assertTrue(mock_get_prop.called)

    @mock.patch.object(network_util, "get_portgroup_mor_by_name")
    @mock.patch.object(vim_util, "get_dynamic_property")
    def test_create_port_group_with_invalid_vlanid(self, mock_get_dy_prop,
                                                   mock_mor):
        dvs_name = "test_dvs"
        pg_name = fake_api.Constants.PORTGROUP_NAME
        vlanid = "100"
        pg = fake_api.DataObject()
        defaultPortConfig = fake_api.DataObject()
        vlan = fake_api.DataObject()
        vlan.vlanId = "200"
        defaultPortConfig.vlan = vlan
        port_group_config = fake_api.DataObject()
        port_group_config.defaultPortConfig = defaultPortConfig
        mock_mor.return_value = pg
        mock_get_dy_prop.return_value = port_group_config
        raised = self.assertRaises(error_util.RunTimeError,
                                   network_util.create_port_group,
                                   self.session,
                                   dvs_name, pg_name, vlanid)
        self.assertTrue(raised)

    @mock.patch.object(network_util, "get_portgroup_mor_by_name")
    @mock.patch.object(vim_util, "get_dynamic_property")
    def test_create_port_group_err_status(self, mock_get_dy_prop,
                                          mock_mor):
        dvs_name = "test_dvs"
        pg_name = fake_api.Constants.PORTGROUP_NAME
        vlanid = "5001"
        task_info = fake_api.DataObject()
        task_info.name = "AddDVPortgroup_Task"
        task_info.key = "task-1234"
        task_info.state = "error"
        task_info.error = fake_api.DataObject()
        mock_mor.return_value = None
        mock_get_dy_prop.return_value = task_info
        raised = self.assertRaises(error_util.RunTimeError,
                                   network_util.create_port_group,
                                   self.session, dvs_name,
                                   pg_name, vlanid)
        self.assertTrue(raised)

    def test_wait_until_dvs_portgroup_available(self):
        vm_ref = fake_api._db_content["VirtualMachine"].values()[0].obj
        hs_key = fake_api._db_content["HostSystem"].keys()[0]
        dvs_key = fake_api._db_content[
            "DistributedVirtualPortgroup"].keys()[0]
        dvs_obj = fake_api._db_content[
            "DistributedVirtualPortgroup"][dvs_key].obj
        network_obj = fake_api.DataObject()
        network_obj.name = fake_api.Constants.PORTGROUP_NAME
        network_obj.ManagedObjectReference = [dvs_obj]
        fake_api._db_content["HostSystem"][
            hs_key].propSet[2].val = network_obj
        self.assertTrue(network_util.wait_until_dvs_portgroup_available(
            self.session,
            vm_ref,
            fake_api.Constants.PORTGROUP_NAME,
            3))

    def test_wait_until_dvs_portgroup_unavailable(self):
        vm_ref = fake_api._db_content["VirtualMachine"].values()[0].obj
        hs_key = fake_api._db_content["HostSystem"].keys()[0]
        dvs_key = fake_api._db_content[
            "DistributedVirtualPortgroup"].keys()[0]
        dvs_obj = fake_api._db_content["DistributedVirtualPortgroup"][
            dvs_key].obj
        network_obj = fake_api.DataObject()
        network_obj.name = fake_api.Constants.PORTGROUP_NAME
        network_obj.ManagedObjectReference = [dvs_obj]
        fake_api._db_content["HostSystem"][
            hs_key].propSet[2].val = network_obj
        self.assertFalse(network_util.wait_until_dvs_portgroup_available(
            self.session,
            vm_ref,
            "invalid_pg",
            3))

    def test_delete_port_group(self):
        self.assertTrue(network_util.get_portgroup_mor_by_name(
            self.session, "test_dvs",
            fake_api.Constants.PORTGROUP_NAME))
        network_util.delete_port_group(self.session, "test_dvs",
                                       fake_api.Constants.PORTGROUP_NAME)
        self.assertFalse(network_util.get_portgroup_mor_by_name(
            self.session, "test_dvs", fake_api.Constants.PORTGROUP_NAME))

    def test_delete_port_group_invalid_dvs(self):
        with mock.patch.object(self.session, "wait_for_task") as task_wait:
            network_util.delete_port_group(self.session,
                                           "test_invalid_dvs",
                                           fake_api.Constants.PORTGROUP_NAME)
            self.assertFalse(task_wait.called)

    @mock.patch.object(network_util, "get_portgroup_mor_by_name")
    @mock.patch.object(vim_util, "get_dynamic_property")
    def test_delete_port_group_exc(self, mock_get_dy_prop,
                                   mock_mor):
        dvs_name = "test_dvs"
        pg_name = fake_api.Constants.PORTGROUP_NAME
        task_info = fake_api.DataObject()
        task_info.name = "Destroy_Task"
        task_info.key = "task-777"
        task_info.state = "error"
        task_info.error = fake_api.DataObject()
        mock_mor.return_value = True
        mock_get_dy_prop.return_value = task_info
        raised = self.assertRaises(error_util.RunTimeError,
                                   network_util.delete_port_group,
                                   self.session, dvs_name,
                                   pg_name)
        self.assertTrue(raised)

    def test_enable_disable_port_of_vm_existing(self):
        pg = fake_api._db_content[
            "DistributedVirtualPortgroup"].values()[0]
        backing = fake_api.DataObject()
        backing.port = fake_api.DataObject()
        backing.port.portgroupKey = pg.value
        backing.port.portKey = pg.portKeys[0]
        backing.port.switchUuid = fake_api._db_content[
            "DistributedVirtualPortgroup"].keys()[0]
        vm_key = fake_api._db_content["VirtualMachine"].keys()[0]
        fake_api._db_content["VirtualMachine"][vm_key].propSet[
            6].val.VirtualDevice[0].backing = backing
        self.assertTrue(network_util.enable_disable_port_of_vm(
            self.session,
            fake_api._db_content["VirtualMachine"].values()[0],
            "00:99:88:77:66:ab",
            True))

    def test_enable_disable_port_of_vm_non_existing(self):
        pg = fake_api._db_content[
            "DistributedVirtualPortgroup"].values()[0]
        backing = fake_api.DataObject()
        backing.port = fake_api.DataObject()
        backing.port.portgroupKey = pg.value
        backing.port.portKey = pg.portKeys[0]
        backing.port.switchUuid = fake_api._db_content[
            "DistributedVirtualPortgroup"].keys()[0]
        vm_key = fake_api._db_content["VirtualMachine"].keys()[0]
        fake_api._db_content["VirtualMachine"][vm_key].propSet[
            6].val.VirtualDevice[0].backing = backing
        self.assertFalse(network_util.enable_disable_port_of_vm(
            self.session,
            fake_api._db_content["VirtualMachine"].values()[0],
            "11:99:88:77:66:ab",
            True))

    def test_is_valid_dvswitch(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_api.Constants.VM_UUID)
        self.assertTrue(network_util.is_valid_dvswitch(self.session,
                                                       cluster_mor,
                                                       "test_dvs"))

    def test_is_valid_dvswitch_no_dvs(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_api.Constants.VM_UUID)
        self.assertFalse(network_util.is_valid_dvswitch(self.session,
                                                        cluster_mor,
                                                        "invalid_dvs"))

    def test_is_valid_dvswitch_no_host(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_api.Constants.VM_UUID)
        with mock.patch.object(resource_util, "get_host_mors_for_cluster",
                               return_value=None):
            self.assertFalse(network_util.is_valid_dvswitch(self.session,
                                                            cluster_mor,
                                                            "test_dvs"))
