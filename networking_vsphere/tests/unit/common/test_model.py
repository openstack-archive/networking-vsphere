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

from neutron.plugins.common import constants as p_const

from networking_vsphere.common import model
from networking_vsphere.tests import base


class CommonModelTestCase(base.TestCase):

    def setUp(self):
        super(CommonModelTestCase, self).setUp()

    def test_model_entity(self):
        entity = model.ResourceEntity(key="key1",
                                      uuid="uuid1")
        self.assertEqual(entity.key, "key1", "Entity key does not match")
        self.assertEqual(entity.uuid, "uuid1", "Entity uuid does not match")

    def test_model_host(self):
        key = "host1"
        name = "hostname1"
        host = model.Host(name, key)
        self.assertFalse(host.uuid is None, "Host uuid is none")
        self.assertEqual(host.key, key, "Host key does not match")
        self.assertEqual(host.name, name, "Host name does not match")
        self.assertTrue(str(host) is not None)

    def test_model_physicalnic(self):
        key = "1-2-3"
        name = "eth0"
        mac_address = "ABC-DEFG-HIJK"
        config = None
        nic = model.PhysicalNic(name, mac_address, config, key)
        self.assertFalse(nic.uuid is None, "Phy nic uuid is none")
        self.assertEqual(nic.key, key, "Phy nic key does not match")
        self.assertEqual(nic.name, name, "Phy nic name does not match")
        self.assertEqual(nic.mac_address, mac_address,
                         "Phy nic mac_address does not match")
        self.assertEqual(nic.config, config,
                         "Phy nic config does not match")

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
        self.assertFalse(dvs.uuid is None, "DVS uuid is none")
        self.assertEqual(dvs.key, key, "DVS key does not match")
        self.assertEqual(dvs.name, name, "DVS name does not match")
        self.assertEqual(len(dvs.pnics), 1)
        self.assertEqual(dvs.pnics[0].name, pnic_name)
        self.assertEqual(len(dvs.networks), 1)
        self.assertEqual(dvs.networks[0].name, net_name)

    def test_model_network(self):
        key = "1-2-3"
        name = "net1"
        network_type = p_const.TYPE_VLAN
        vs_name = "dvs1"
        port_name = "port1"
        vlan_ids = [1001]
        operation_mode = "mode1"
        vlan_type = "Native"
        vlan = model.Vlan(vlan_ids, operation_mode, vlan_type)
        config = model.NetworkConfig(vlan)
        vs = model.VirtualSwitch(vs_name)
        port = model.Port(port_name, None, None, None, None)
        network = model.Network(name, network_type, config, [vs], [port], key)
        self.assertFalse(network.uuid is None, "Network uuid is none")
        self.assertEqual(network.key, key, "Network key does not match")
        self.assertEqual(network.name, name, "Network name does not match")
        self.assertEqual(network.network_type, network_type,
                         "Network network_type does not match")
        self.assertTrue(network.config is not None)
        self.assertTrue(network.config.vlan is not None)
        self.assertEqual(network.config.vlan.operation_mode, operation_mode)
        self.assertEqual(network.config.vlan.vlan_type, vlan_type)
        self.assertEqual(len(network.config.vlan.vlanIds), 1)
        self.assertEqual(network.config.vlan.vlanIds[0], vlan_ids[0])
        self.assertEqual(len(network.vswitches), 1)
        self.assertEqual(network.vswitches[0].name, vs_name)
        self.assertEqual(len(network.ports), 1)
        self.assertEqual(network.ports[0].name, port_name)

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
        self.assertFalse(port.uuid is None, "Port uuid is none")
        self.assertEqual(port.key, key, "Port key does not match")
        self.assertEqual(port.name, name, "Port name does not match")
        self.assertEqual(len(port.ipaddresses), 1)
        self.assertEqual(port.ipaddresses[0], ipaddresses[0])
        self.assertEqual(port.mac_address, mac_address,
                         "Port mac_address does not match")
        self.assertEqual(port.vswitch_uuid, vswitch_uuid,
                         "Port vswitch_uuid does not match")
        self.assertEqual(port.vm_id, vm_id,
                         "Port vm_id does not match")
        self.assertEqual(port.network_uuid, network_uuid,
                         "Port network_uuid does not match")

    def test_model_virtualnic(self):
        key = "1-2-3"
        mac_address = "ABC-DEFG-HIJK"
        port_uuid = "uuid1"
        vm_id = "uuid2"
        vm_name = "vm1"
        nic_type = "VMXNET"
        pg_id = "PortGroup-270"
        virtual_nic = model.VirtualNic(mac_address, port_uuid,
                                       vm_id, vm_name, nic_type, pg_id, key)
        self.assertEqual(virtual_nic.key, key, "vnic key does not match")
        self.assertEqual(virtual_nic.mac_address, mac_address,
                         "vnic mac_address does not match")
        self.assertEqual(virtual_nic.port_uuid, port_uuid,
                         "vnic port_uuid does not match")
        self.assertEqual(virtual_nic.vm_id, vm_id,
                         "vnic vm_id does not match")
        self.assertEqual(virtual_nic.vm_name, vm_name,
                         "vnic vm_name does not match")
        self.assertEqual(virtual_nic.nic_type, nic_type,
                         "vnic nic_type does not match")
        self.assertEqual(virtual_nic.pg_id, pg_id,
                         "vnic pg_id does not match")

    def test_model_virtualmachine(self):
        key = "1-2-3"
        vm_name = "vm1"
        vm_uuid = "uuid1"
        vnic = model.VirtualNic(None, None, vm_uuid, vm_name, None, None)
        vm = model.VirtualMachine(vm_name, [vnic], vm_uuid, key)
        self.assertEqual(vm.uuid, vm_uuid, "vm uuid does not match")
        self.assertEqual(vm.key, key, "vm key does not match")
        self.assertEqual(vm.name, vm_name, "vm name does not match")
        self.assertEqual(len(vm.vnics), 1, "vm vnics size does not match")
        self.assertEqual(vm.vnics[0].vm_id, vm_uuid,
                         "vm vnics vm_id does not match")

    def test_model_virtualmachine_none_uuid(self):
        key = "1-2-3"
        vm_name = "vm1"
        vm = model.VirtualMachine(vm_name, None, None, key)
        self.assertTrue(vm.uuid is not None, "vm uuid is none")
        self.assertEqual(vm.key, key, "vm key does not match")
        self.assertEqual(vm.name, vm_name, "vm name does not match")

    def test_model_event(self):
        event_type = 'VM_CREATED'
        src_obj = "vm1"
        hostname = 'host1'
        clustername = 'cluster1'
        clusterid = 'domain-xyz'
        host_changed = False
        event = model.Event(event_type, src_obj, None,
                            hostname, clustername, clusterid,
                            host_changed)
        self.assertEqual(event.event_type, event_type,
                         "event event_type does not match")
        self.assertEqual(event.host_name, hostname,
                         "event host_name does not match")
        self.assertEqual(event.cluster_name, clustername,
                         "event cluster_name does not match")
        self.assertEqual(event.cluster_id, clusterid,
                         "event cluster_id does not match")
        self.assertEqual(event.host_changed, host_changed,
                         "event host_changed does not match")
