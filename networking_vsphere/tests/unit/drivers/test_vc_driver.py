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

import copy
import mock

from neutron.plugins.common import constants as p_const

from networking_vsphere.common import constants
from networking_vsphere.common import error
from networking_vsphere.common import model
from networking_vsphere.drivers import vc_driver as vmware_driver
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.utils import fake_vmware_api
from networking_vsphere.tests.unit.utils import stubs
from networking_vsphere.utils import cache
from networking_vsphere.utils import resource_util
from networking_vsphere.utils import vim_util

from oslo_vmware import exceptions

VcCache = cache.VCCache


class TestVmwareDriver(base.TestCase):

    def setUp(self):
        super(TestVmwareDriver, self).setUp()
        self.cluster_dvs_mapping = {"ClusterComputeResource": "test_dvs"}
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session
        self.useFixture(stubs.CacheFixture())
        mock.patch('networking_vsphere.drivers.vc_driver.'
                   'VCNetworkDriver.is_valid_switch',
                   return_value=fake_vmware_api._db_content["HostSystem"
                                                            ].values()
                   ).start()
        mock.patch('networking_vsphere.drivers.vc_driver.'
                   'VCNetworkDriver.get_unused_portgroups',
                   return_value=[]).start()
        mock.patch('networking_vsphere.drivers.vc_driver.'
                   'VCNetworkDriver.delete_portgroup').start()
        mock.patch('networking_vsphere.drivers.vc_driver.'
                   'VCNetworkDriver.create_network').start()
        self.vc_driver = vmware_driver.VCNetworkDriver()
        self.vc_driver.state = constants.DRIVER_RUNNING
        self.vc_driver.add_cluster("ClusterComputeResource", "test_dvs")
        self.LOG = vmware_driver.LOG

    def test_stop(self):
        with mock.patch.object(vim_util, "cancel_wait_for_updates",
                               return_value=None):
            self.vc_driver.stop()
            self.assertEqual(self.vc_driver.state, constants.DRIVER_STOPPED)

    def test_add_cluster_none(self):
        old_mapping = cache.VCCache.get_cluster_switch_mapping()
        self.vc_driver.add_cluster("", "test_dvs")
        self.assertEqual(old_mapping,
                         cache.VCCache.get_cluster_switch_mapping(),
                         "Cluster mapping got changed even for invalid"
                         "mapping")

    def test_add_cluster_invalid_switch(self):
        with mock.patch.object(self.vc_driver, "is_valid_switch",
                               return_value=None):
            self.assertIn("ClusterComputeResource",
                          cache.VCCache.get_cluster_switch_mapping())
            self.vc_driver.add_cluster("ClusterComputeResource", "invalid_dvs")
            self.assertNotIn("ClusterComputeResource",
                             cache.VCCache.get_cluster_switch_mapping())

    def test_add_cluster_invalid_cluster_path(self):
        self.vc_driver.add_cluster("invalid_cluster", "test_dvs")
        self.assertNotIn("invalid_cluster",
                         cache.VCCache.get_cluster_switch_mapping())

    def test_add_cluster_updatevds(self):
        self.assertEqual(cache.VCCache.
                         get_switch_for_cluster_path(
                             "ClusterComputeResource"), "test_dvs")
        self.vc_driver.add_cluster("ClusterComputeResource", "new_dvs")
        self.assertEqual(cache.VCCache.
                         get_switch_for_cluster_path(
                             "ClusterComputeResource"), "new_dvs")

    def test_add_cluster_clusterchanged(self):
        self.vc_driver.state = constants.DRIVER_IDLE
        cluster_mor = resource_util.get_cluster_mor_by_path(
            self.session, "ClusterComputeResource")
        old_clu_id = cluster_mor.value
        object.__setattr__(cluster_mor, 'value', "new_value")
        with mock.patch.object(resource_util, "get_cluster_mor_by_path",
                               return_value=cluster_mor), \
                mock.patch.object(self.vc_driver,
                                  "_unregister_cluster_for_updates",
                                  return_value=None):
            self.assertEqual(cache.VCCache.get_switch_for_cluster_path(
                "ClusterComputeResource"), "test_dvs")
            self.assertIn(old_clu_id,
                          cache.VCCache.cluster_id_to_path)
            self.vc_driver.add_cluster("ClusterComputeResource", "new_dvs")
            self.assertNotIn(old_clu_id,
                             cache.VCCache.cluster_id_to_path)
            self.assertIn("new_value",
                          cache.VCCache.cluster_id_to_path)
            self.assertEqual(cache.VCCache.get_switch_for_cluster_path(
                "ClusterComputeResource"), "new_dvs")
            self.assertEqual(self.vc_driver.state, constants.DRIVER_READY)

    def test_is_connected_none(self):
        self.vc_driver.session = None
        self.assertFalse(self.vc_driver.is_connected())

    def test_create_port(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id)
        virtual_nic = model.VirtualNic(mac_address=None,
                                       port_uuid=None,
                                       vm_id=vm_id,
                                       vm_name=None,
                                       nic_type=None,
                                       pg_id=None)
        with mock.patch.object(model, "VirtualSwitch") as vswitch:
            self.vc_driver.create_port(network, port, virtual_nic)
            self.assertTrue(vswitch.called)

    def test_create_port_exc(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id)
        virtual_nic = model.VirtualNic(mac_address=None,
                                       port_uuid=None,
                                       vm_id=vm_id,
                                       vm_name=None,
                                       nic_type=None,
                                       pg_id=None)
        with mock.patch.object(self.vc_driver, "is_valid_switch",
                               return_value=None):
            exc = self.assertRaises(error.VcenterConfigurationError,
                                    self.vc_driver.create_port,
                                    network, port, virtual_nic)
            self.assertIn("Invalid Switch", str(exc))

    def test_create_port_invalid_cluster(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id)
        virtual_nic = model.VirtualNic(mac_address=None,
                                       port_uuid=None,
                                       vm_id=vm_id,
                                       vm_name=None,
                                       nic_type=None,
                                       pg_id=None)
        cluster_mor = fake_vmware_api.DataObject()
        cluster_mor.value = "invalid_id"
        cache.VCCache.add_cluster_mor_for_vm(vm_id, cluster_mor)
        exc = self.assertRaises(error.VcenterConfigurationError,
                                self.vc_driver.create_port,
                                network, port, virtual_nic)
        self.assertIn("Cluster for VM %s could not be determined" %
                      vm_id, str(exc))

    def test_process_update_set_filterset_none(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        updateSet.filterSet = None
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_process_update_set_objectset_none(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        propFilterUpdate.objectSet = None
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_process_update_set_invalid(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = (
            fake_vmware_api._db_content["ClusterComputeResource"].values()[0])
        objectUpdate.kind = "enter"
        changeSet = []
        objectUpdate.changeSet = changeSet
        for prop in objectUpdate.obj.propSet:
            changeSet.append(prop)
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_process_update_set_modify(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = (
            fake_vmware_api._db_content["VirtualMachine"].values()[0])
        objectUpdate.kind = "modify"
        changeSet = []
        objectUpdate.changeSet = changeSet
        for prop in objectUpdate.obj.propSet:
            if prop.name == "runtime.host":
                delattr(prop, "val")
            changeSet.append(prop)
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, constants.VM_CREATED)

    def test_process_update_set_snapshot(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = (
            fake_vmware_api._db_content["VirtualMachine"].values()[0])
        objectUpdate.kind = "modify"
        changeSet = []
        objectUpdate.changeSet = changeSet
        for prop in objectUpdate.obj.propSet:
            if prop.name == "runtime.host":
                delattr(prop, "val")
            changeSet.append(prop)
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, constants.VM_CREATED)
        self.assertTrue(VcCache.get_vm_mor_for_uuid(
                        fake_vmware_api.Constants.VM_UUID))
        self.assertEqual(VcCache.get_vm_mor_for_uuid(
                         fake_vmware_api.Constants.VM_UUID).value,
                         objectUpdate.obj.value)
        obj_orig = objectUpdate.obj
        objectUpdate.obj = copy.deepcopy(objectUpdate.obj)
        object.__setattr__(objectUpdate.obj, 'value',
                           'aaaa-bbbbb-ccccc-ddddd-eeeee')
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)
        self.assertNotEqual(objectUpdate.obj.value, obj_orig.value)
        self.assertEqual(objectUpdate.obj.get(
                         'config.extraConfig["nvp.vm-uuid"]').value,
                         obj_orig.get(
                         'config.extraConfig["nvp.vm-uuid"]').value)
        self.assertEqual(VcCache.get_vm_mor_for_uuid(
                         fake_vmware_api.Constants.VM_UUID).value,
                         obj_orig.value)

    def test_process_update_set_leave(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = (
            fake_vmware_api._db_content["VirtualMachine"].values()[0])
        objectUpdate.kind = "leave"
        changeSet = []
        objectUpdate.changeSet = changeSet
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_process_update_set_invalid_extraConfig(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = (
            fake_vmware_api._db_content["VirtualMachine"].values()[0])
        objectUpdate.kind = "modify"
        changeSet = []
        objectUpdate.changeSet = changeSet
        for prop in objectUpdate.obj.propSet:
            if prop.name == 'config.extraConfig["nvp.vm-uuid"]':
                delattr(prop, "val")
            changeSet.append(prop)
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_delete_stale_portgroups(self):
        with mock.patch.object(
                self.vc_driver,
                "get_unused_portgroups",
                return_value=[fake_vmware_api.Constants.PORTGROUP_NAME]
                ) as mock_unused_ob, \
                mock.patch.object(self.vc_driver, "delete_portgroup"
                                  ) as mock_delete_pg_ob:
            self.vc_driver.delete_stale_portgroups("test_dvs")
            self.assertTrue(mock_unused_ob.called)
            self.assertTrue(mock_delete_pg_ob.called)

    def test_delete_stale_portgroups_exception(self):
        with mock.patch.object(
                self.vc_driver,
                "get_unused_portgroups",
                return_value=[fake_vmware_api.Constants.PORTGROUP_NAME]
                ) as mock_unused_ob, \
                mock.patch.object(self.vc_driver, "delete_portgroup",
                                  side_effect=Exception()) as mock_del_pg_ob, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_exception_log:
            self.vc_driver.delete_stale_portgroups("test_dvs")
            self.assertTrue(mock_unused_ob.called)
            self.assertTrue(mock_del_pg_ob.called)
            self.assertTrue(mock_exception_log.called)

    def test_post_delete_vm(self):
        uuid = fake_vmware_api.Constants.VM_UUID
        clus_mor = (
            fake_vmware_api._db_content["ClusterComputeResource"].values()[0])
        vm_mor = fake_vmware_api._db_content["VirtualMachine"].values()[0]
        VcCache.add_cluster_mor_for_vm(uuid, clus_mor)
        VcCache.add_vm_mor_for_uuid(uuid, vm_mor)
        vm_model = model.VirtualMachine(name=vm_mor.name,
                                        vnics=[],
                                        uuid=uuid,
                                        key=vm_mor.value)
        VcCache.add_vm_model_for_uuid(uuid, vm_model)
        self.assertIn(uuid, VcCache.vm_to_cluster)
        self.assertIn(uuid, VcCache.vm_uuid_to_mor)
        self.assertIn(vm_mor.value, VcCache.vm_moid_to_uuid)
        self.assertIn(uuid, VcCache.vm_uuid_to_model)
        self.vc_driver.post_delete_vm(vm_model)
        self.assertNotIn(uuid, VcCache.vm_to_cluster)
        self.assertNotIn(uuid, VcCache.vm_uuid_to_mor)
        self.assertNotIn(vm_mor.value, VcCache.vm_moid_to_uuid)
        self.assertNotIn(uuid, VcCache.vm_uuid_to_model)

    def test_remove_cluster(self):
        with mock.patch.object(self.vc_driver,
                               "_unregister_cluster_for_updates"
                               ) as unreg_ob:
            self.vc_driver.remove_cluster("ClusterComputeResource",
                                          "test_dvs")
            self.assertTrue(unreg_ob.called)

    def test_remove_cluster_invalid_cluster_path(self):
        with mock.patch.object(self.vc_driver,
                               "_unregister_cluster_for_updates"
                               ) as mock_unreg_ob, \
                mock.patch.object(self.vc_driver,
                                  "_find_cluster_id_for_path",
                                  return_value="1234") as mock_find_ob:
            self.vc_driver.remove_cluster("invalid_cluster",
                                          "test_dvs")
            self.assertFalse(mock_unreg_ob.called)
            self.assertFalse(mock_find_ob.called)

    def test_remove_cluster_id_none(self):
        with mock.patch.object(self.vc_driver,
                               "_unregister_cluster_for_updates"
                               ) as mock_unreg_ob, \
                mock.patch.object(self.vc_driver,
                                  "_find_cluster_id_for_path",
                                  return_value=None) as mock_find_ob:
            self.vc_driver.remove_cluster("ClusterComputeResource",
                                          "test_dvs")
            self.assertFalse(mock_unreg_ob.called)
            self.assertTrue(mock_find_ob.called)

    @mock.patch('time.sleep', side_effect=Exception())
    def test_monitor_events_with_no_exception(self, time_fn):
        self.vc_driver.state = constants.DRIVER_READY
        with mock.patch.object(self.LOG, 'info') as mock_info_log,\
                mock.patch.object(self.vc_driver, "dispatch_events",
                                  ) as mock_dispatch_events, \
                mock.patch.object(self.vc_driver, "_process_update_set",
                                  ) as mock_process_update_set, \
                mock.patch.object(vim_util, 'wait_for_updates_ex'
                                  ) as mock_wait_for_update_ex, \
                mock.patch.object(self.LOG, 'exception') as mock_except_log:
            self.vc_driver.monitor_events()
            self.assertTrue(mock_info_log.called)
            self.assertTrue(mock_dispatch_events.called)
            self.assertTrue(mock_process_update_set.called)
            self.assertTrue(mock_wait_for_update_ex.called)
            self.assertTrue(mock_except_log.called)

    @mock.patch('time.sleep', side_effect=Exception())
    def test_monitor_events_with_fault_exception(self, time_fn):
        self.vc_driver.state = constants.DRIVER_READY
        with mock.patch.object(self.LOG, 'info') as mock_info_log,\
                mock.patch.object(self.vc_driver, "dispatch_events",
                                  ) as mock_dispatch_events, \
                mock.patch.object(self.vc_driver, "_process_update_set",
                                  ) as mock_process_update_set, \
                mock.patch.object(vim_util, 'wait_for_updates_ex',
                                  side_effect=exceptions.VimFaultException(
                                      [], None)) as mock_vim_fault_exception, \
                mock.patch.object(self.LOG, 'exception') as mock_except_log:
            self.vc_driver.monitor_events()
            self.assertTrue(mock_info_log.called)
            self.assertFalse(mock_dispatch_events.called)
            self.assertFalse(mock_process_update_set.called)
            self.assertTrue(mock_vim_fault_exception.called)
            self.assertTrue(mock_except_log.called)
