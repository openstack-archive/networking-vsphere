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
#

from networking_vsphere.common import model
from networking_vsphere.tests import base


class CommonModelTestCase(base.TestCase):

    def setUp(self):
        super(CommonModelTestCase, self).setUp()

    def test_model_entity(self):
        entity1 = model.ResourceEntity(key="key1",
                                       uuid="uuid1")
        entity2 = model.ResourceEntity(key="key1",
                                       uuid="uuid1")
        self.assertTrue(entity1)
        self.assertTrue(entity2)
        self.assertTrue(entity1 == entity2)
        entity2.uuid = "uuid2"
        self.assertTrue(entity1 != entity2)

    def test_model_host(self):
        key = "host1"
        name = "hostname1"
        host = model.Host(name, key)
        self.assertFalse(host.uuid is None, "Host uuid is none")
        self.assertTrue(host.key == key, "Host key does not match")
        self.assertTrue(host.name == name, "Host name does not match")
        self.assertTrue(str(host) is not None)

    def test_model_physicalnic(self):
        key = "1-2-3"
        name = "eth0"
        mac_address = "ABC-DEFG-HIJK"
        config = None
        nic = model.PhysicalNic(name, mac_address, config, key)
        self.assertFalse(nic.uuid is None, "uuid is none")
        self.assertTrue(nic.key == key, "key does not match")
        self.assertTrue(nic.name == name, "name does not match")
        self.assertTrue(nic.mac_address == mac_address,
                        "mac_address does not match")
        self.assertTrue(nic.config == config, "config does not match")

    def test_model_virtualswitch(self):
        key = "1-2-3"
        name = "dvs1"
        pnic_name = "eth0"
        net_name = "net1"
        pnic = model.PhysicalNic(name="eth0", mac_address=None, config=None)
        network = model.Network(name=net_name, network_type=None)
        dvs = model.VirtualSwitch(name,
                                  pnics=[pnic],
                                  networks=[network],
                                  key=key)
        self.assertFalse(dvs.uuid is None, "uuid is none")
        self.assertTrue(dvs.key == key, "key does not match")
        self.assertTrue(dvs.name == name, "name does not match")
        self.assertTrue(len(dvs.pnics) == 1)
        self.assertTrue(dvs.pnics[0].name == pnic_name)
        self.assertTrue(len(dvs.networks) == 1)
        self.assertTrue(dvs.networks[0].name == net_name)

    def test_model_network(self):
        key = "1-2-3"
        name = "net1"
        network_type = model.IPAddressType.IPV4
        vs_name = "dvs1"
        port_name = "port1"
        vlanIds = [1001]
        operation_mode = "mode1"
        vlan_type = "Native"
        vlan = model.Vlan(vlanIds, operation_mode, vlan_type)
        config = model.NetworkConfig(vlan)
        vs = model.VirtualSwitch(vs_name)
        port = model.Port(port_name, None, None, None, None)
        network = model.Network(name, network_type, config, [vs], [port], key)
        self.assertFalse(network.uuid is None, "uuid is none")
        self.assertTrue(network.key == key, "key does not match")
        self.assertTrue(network.name == name, "name does not match")
        self.assertTrue(network.network_type == network_type,
                        "network_type does not match")
        self.assertTrue(network.config is not None)
        self.assertTrue(network.config.vlan is not None)
        self.assertTrue(network.config.vlan.operation_mode == operation_mode)
        self.assertTrue(network.config.vlan.vlan_type == vlan_type)
        self.assertTrue(len(network.config.vlan.vlanIds) == 1)
        self.assertTrue(network.config.vlan.vlanIds[0] == vlanIds[0])
        self.assertTrue(len(network.vswitches) == 1)
        self.assertTrue(network.vswitches[0].name == vs_name)
        self.assertTrue(len(network.ports) == 1)
        self.assertTrue(network.ports[0].name == port_name)

    def test_model_port(self):
        key = "1-2-3"
        name = "net1"
        mac_address = "ABC-DEFG-HIJK"
        ipaddresses = ["100.100.10.1"]
        vswitch_uuid = "uuid1"
        network_uuid = "uuid2"
        vm_id = "uuid3"
        port_config = None
        port_status = None
        port = model.Port(name, mac_address, ipaddresses,
                          vswitch_uuid, vm_id, network_uuid, port_config,
                          port_status, key)
        self.assertFalse(port.uuid is None, "uuid is none")
        self.assertTrue(port.key == key, "key does not match")
        self.assertTrue(port.name == name, "name does not match")
        self.assertTrue(len(port.ipaddresses) == 1)
        self.assertTrue(port.ipaddresses[0] == ipaddresses[0])
        self.assertTrue(port.mac_address == mac_address,
                        "mac_address does not match")
        self.assertTrue(port.vswitch_uuid == vswitch_uuid,
                        "vswitch_uuid does not match")
        self.assertTrue(port.vm_id == vm_id,
                        "vm_id does not match")
        self.assertTrue(port.network_uuid == network_uuid,
                        "network_uuid does not match")

    def test_model_virtualnic(self):
        key = "1-2-3"
        mac_address = "ABC-DEFG-HIJK"
        port_uuid = "uuid1"
        vm_id = "uuid2"
        vm_name = "vm1"
        nic_type = "VMXNET"
        virtual_nic = model.VirtualNic(mac_address, port_uuid,
                                       vm_id, vm_name, nic_type, key)
        self.assertTrue(virtual_nic.key == key, "key does not match")
        self.assertTrue(virtual_nic.mac_address == mac_address,
                        "mac_address does not match")
        self.assertTrue(virtual_nic.port_uuid == port_uuid,
                        "port_uuid does not match")
        self.assertTrue(virtual_nic.vm_id == vm_id, "vm_id does not match")
        self.assertTrue(virtual_nic.vm_name == vm_name,
                        "vm_name does not match")
        self.assertTrue(virtual_nic.nic_type == nic_type,
                        "nic_type does not match")

    def test_model_virtualmachine(self):
        key = "1-2-3"
        vm_name = "vm1"
        vm_uuid = "uuid1"
        vnic = model.VirtualNic(None, None, vm_uuid, vm_name, None, None)
        vm = model.VirtualMachine(vm_name, [vnic], vm_uuid, key)
        self.assertTrue(vm.uuid == vm_uuid, "uuid does not match")
        self.assertTrue(vm.key == key, "key does not match")
        self.assertTrue(vm.name == vm_name, "name does not match")
        self.assertTrue(len(vm.vnics) == 1, "vnics size does not match")
        self.assertTrue(vm.vnics[0].vm_id == vm_uuid,
                        "vnics vm_id does not match")

    def test_model_virtualmachine_none_uuid(self):
        key = "1-2-3"
        vm_name = "vm1"
        vm = model.VirtualMachine(vm_name, None, None, key)
        self.assertTrue(vm.uuid is not None, "uuid is none")
        self.assertTrue(vm.key == key, "key does not match")
        self.assertTrue(vm.name == vm_name, "name does not match")

    def test_model_event(self):
        event_type = 'VM_CREATED'
        src_obj = "vm1"
        hostname = 'host1'
        clustername = 'cluster1'
        clusterid = 'domain-xyz'
        event = model.Event(event_type, src_obj, None,
                            hostname, clustername, clusterid)
        self.assertTrue(event.event_type == event_type)
        self.assertTrue(event.host_name == hostname)
        self.assertTrue(event.cluster_name == clustername)
        self.assertTrue(event.cluster_id == clusterid)
