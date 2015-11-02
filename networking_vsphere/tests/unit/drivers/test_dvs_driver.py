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

from neutron.plugins.common import constants as p_const

from networking_vsphere.common import constants
from networking_vsphere.common import error
from networking_vsphere.common import model
from networking_vsphere.drivers import dvs_driver
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.utils import fake_vmware_api
from networking_vsphere.tests.unit.utils import stubs
from networking_vsphere.utils import error_util
from networking_vsphere.utils import network_util
from networking_vsphere.utils import resource_util
from networking_vsphere.utils import vim_util


class TestDvsDriver(base.TestCase):

    def setUp(self):
        super(TestDvsDriver, self).setUp()
        self.cluster_dvs_mapping = {"ClusterComputeResource": "test_dvs"}
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session
        self.useFixture(stubs.CacheFixture())
        self.vc_driver = dvs_driver.DvsNetworkDriver()
        self.vc_driver.state = constants.DRIVER_RUNNING
        self.vc_driver.add_cluster("ClusterComputeResource", "test_dvs")

    def test_invalid_cluster(self):
        valid, _ = self.vc_driver.validate_cluster_switch_mapping(
            "InvalidClusterComputeResource", "test_dvs")
        self.assertFalse(valid)

    def test_invalid_dvs(self):
        valid, _ = self.vc_driver.validate_cluster_switch_mapping(
            "ClusterComputeResource", "invalid_dvs")
        self.assertFalse(valid)

    def test_create_network(self):
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        vswitch = model.VirtualSwitch("test_dvs", hosts=None)
        with mock.patch.object(network_util, "get_portgroup_mor_by_name",
                               return_value=None):
            self.vc_driver.create_network(network, vswitch)
            self.assertTrue(fake_vmware_api.is_task_done(
                "AddDVPortgroup_Task"))

    def test_delete_network(self):
        pg_name = fake_vmware_api.Constants.PORTGROUP_NAME
        network = model.Network(
            name=pg_name, network_type=p_const.TYPE_VLAN)
        vswitch = model.VirtualSwitch("test_dvs", hosts=None)
        self.assertFalse(self.vc_driver.delete_network(network, vswitch))

    def test_update_port(self):
        port_id = "PORT-1234-5678"
        vm_id = fake_vmware_api.Constants.VM_UUID
        mac_address = fake_vmware_api.Constants.VM_MAC
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        port = model.Port(uuid=port_id,
                          name=None,
                          mac_address=mac_address,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_DOWN)
        self.vc_driver.update_port(network, port, None)
        self.assertTrue(fake_vmware_api.is_task_done(
            "ReconfigureDVPort_Task"))

    def test_update_port_up(self):
        port_id = "PORT-1234-5678"
        vm_id = fake_vmware_api.Constants.VM_UUID
        mac_address = fake_vmware_api.Constants.VM_MAC
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        port = model.Port(uuid=port_id,
                          name=None,
                          mac_address=mac_address,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_UP)
        self.vc_driver.update_port(network, port, None)
        self.assertTrue(fake_vmware_api.is_task_done(
            "ReconfigureDVPort_Task"))

    def test_update_port_invalid_status(self):
        port_id = "PORT-1234-5678"
        vm_id = fake_vmware_api.Constants.VM_UUID
        mac_address = fake_vmware_api.Constants.VM_MAC
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        port = model.Port(uuid=port_id,
                          name=None,
                          mac_address=mac_address,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status="Invalid")
        self.assertRaises(error.OVSvAppNeutronAgentError,
                          self.vc_driver.update_port,
                          network,
                          port,
                          None)

    def test_update_port_invalid_vm(self):
        port_id = "PORT-1234-5678"
        vm_id = "INVALID-VM"
        mac_address = fake_vmware_api.Constants.VM_MAC
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        port = model.Port(uuid=port_id,
                          name=None,
                          mac_address=mac_address,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_UP)
        done = self.vc_driver.update_port(network, port, None)
        self.assertFalse(done)
        self.assertFalse(fake_vmware_api.is_task_done(
            "ReconfigureDVPort_Task"))

    def test_update_port_invalid_mac(self):
        port_id = "PORT-1234-5678"
        vm_id = fake_vmware_api.Constants.VM_UUID
        mac_address = "in:va:li:d0:ma:c0"
        vlan = model.Vlan(vlan_ids=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=p_const.TYPE_VLAN,
            config=network_config)
        port = model.Port(uuid=port_id,
                          name=None,
                          mac_address=mac_address,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_UP)
        self.vc_driver.update_port(network, port, None)
        self.assertFalse(fake_vmware_api.is_task_done(
            "ReconfigureDVPort_Task"))

    def test_post_create_port(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        network_uuid = fake_vmware_api.Constants.PORTGROUP_NAME
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_UP,
                          network_uuid=network_uuid)
        self.vc_driver.post_create_port(port)
        self.assertTrue(fake_vmware_api.is_task_done(
            "ReconfigureDVPort_Task"))

    def test_post_create_port_status_down(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        network_uuid = fake_vmware_api.Constants.PORTGROUP_NAME
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_DOWN,
                          network_uuid=network_uuid)
        self.vc_driver.post_create_port(port)
        self.assertFalse(fake_vmware_api.is_task_done(
            "ReconfigureDVPort_Task"))

    def test_wait_for_port_update_on_vm_exception(self):
        vm_mor = None
        pg_mor = None
        try:
            with mock.path.object(self.vc_driver,
                                  '_register_vm_for_updates'), \
                    mock.patch.object(vim_util, "wait_for_updates_ex",
                                      side_effect=Exception()):
                self.vc_driver._wait_for_port_update_on_vm(vm_mor, pg_mor)
        except Exception:
            self.assertFalse(fake_vmware_api.is_task_done(
                "ReconfigureDVPort_Task"))

    def test_post_create_port_vm_deleted(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        network_uuid = fake_vmware_api.Constants.PORTGROUP_NAME
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_UP,
                          network_uuid=network_uuid)
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.kind = "leave"
        objectSet.append(objectUpdate)
        with mock.patch.object(vim_util, "wait_for_updates_ex",
                               return_value=updateSet) as wait_update:
            self.vc_driver.post_create_port(port)
            self.assertTrue(wait_update.called)

    def test_post_create_port_nic_devices_none(self):
        try:
            vm_id = fake_vmware_api.Constants.VM_UUID
            network_uuid = fake_vmware_api.Constants.PORTGROUP_NAME
            port = model.Port(name=None,
                              mac_address=None,
                              ipaddresses=None,
                              vm_id=vm_id,
                              port_status=constants.PORT_STATUS_UP,
                              network_uuid=network_uuid)
            updateSet = fake_vmware_api.DataObject()
            updateSet.version = 1
            filterSet = []
            updateSet.filterSet = filterSet
            propFilterUpdate = fake_vmware_api.DataObject()
            filterSet.append(propFilterUpdate)
            objectSet = []
            propFilterUpdate.objectSet = objectSet
            objectUpdate = fake_vmware_api.DataObject()
            objectSet.append(objectUpdate)
            with mock.patch.object(vim_util, "wait_for_updates_ex",
                                   return_value=updateSet):
                self.vc_driver.post_create_port(port)
        except Exception:
            self.assertFalse(fake_vmware_api.
                             is_task_done("ReconfigureDVPort_Task"))

    def test_post_create_port_excp1(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        network_uuid = fake_vmware_api.Constants.PORTGROUP_NAME
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_UP,
                          network_uuid=network_uuid)
        with mock.patch.object(network_util, "get_portgroup_mor_by_name",
                               return_value=None):
            self.assertRaises(error_util.RunTimeError,
                              self.vc_driver.post_create_port,
                              port)
            self.assertFalse(fake_vmware_api.is_task_done(
                "ReconfigureDVPort_Task"))

    def test_post_create_port_excp2(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        network_uuid = fake_vmware_api.Constants.PORTGROUP_NAME
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_UP,
                          network_uuid=network_uuid)
        with mock.patch.object(dvs_driver.DvsNetworkDriver,
                               "_find_cluster_switch_for_vm",
                               return_value=[None, None, "test_vds"]), \
                mock.patch.object(network_util, "get_portgroup_mor_by_name",
                                  return_value="pg_mor"), \
                mock.patch.object(resource_util, "get_vm_mor_for_uuid",
                                  return_value=None):
            self.assertRaises(error_util.RunTimeError,
                              self.vc_driver.post_create_port,
                              port)
            self.assertFalse(fake_vmware_api.is_task_done(
                             "ReconfigureDVPort_Task"))

    def test_post_create_port_excp3(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        network_uuid = fake_vmware_api.Constants.PORTGROUP_NAME
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id,
                          port_status=constants.PORT_STATUS_UP,
                          network_uuid=network_uuid)
        with mock.patch.object(dvs_driver.DvsNetworkDriver,
                               "_register_vm_for_updates",
                               side_effect=error_util.RunTimeError(
                                   "Exception in registering vm for updates")):
            self.assertRaises(error_util.RunTimeError,
                              self.vc_driver.post_create_port,
                              port)
            self.assertFalse(fake_vmware_api.is_task_done(
                "ReconfigureDVPort_Task"))
