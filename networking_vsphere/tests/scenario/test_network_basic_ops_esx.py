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

from networking_vsphere.tests.scenario import manager

from tempest_lib.common.utils import data_utils


class OVSVAPPTestJSON(manager.ESXNetworksTestJSON):

    def _create_custom_security_group(self):
        group_create_body, _ = self._create_security_group()

        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            self.client.create_security_group_rule(
                security_group_id=group_create_body['security_group']['id'],
                protocol=protocol,
                direction='ingress',
                ethertype=self.ethertype
            )
        return group_create_body

    def test_validate_creation_of_portgroup(self):
        """Validate  creation of VM in ESX environment will create a Port group

        1. Create a network with subnet attached to it.
        3. Boot VM with default security group.
        4. Validate the Port group with the network name is created.
        5. Validate the vlan-id in the PG is binded with segment id.
        """
        serverid = self._create_server(self.network['name'],
                                       self.network['id'])
        self._fetch_network_segmentid_and_verify_portgroup(self.network['id'])
        self.addCleanup(self._delete_server, serverid)

    def test_validate_vm_created_is_accessible_through_the_floating_ip(self):
        """Validate the VM created in ESX is accessible through the floating ip

        1. Check public connectivity after associating the floating ip
        2. Check public connectivity after dis-associating the floating ip
        3. Check public connectivity after re-associating the floating ip again
        """
        net_id = self.network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid = self._create_server(
            name, net_id, group_create_body['security_group']['id'])
        self.addCleanup(self._delete_server, serverid)
        self._fetch_network_segmentid_and_verify_portgroup(net_id)
        deviceport = self.client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        self._disassociate_floating_ips()
        self._check_public_network_connectivity(floatingiptoreach,
                                                should_connect=False)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        self._check_public_network_connectivity(floatingiptoreach)

    def test_Validate_vm_creation_with_multiple_nics_with_different_networks(
            self):
        """Validate VM creation with multiple nics belonging to different

        networks in ESX environment.
        1.  Create a two different network with subnet attached to it.
        2.  Create a custom security group.
        3.  Boot VM with custom security rule.
        4.  Validate multiple PG creation each with network id.
        5.  Validate the vlan-ids of PG are properly binded with segment-ids.
        """
        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router2-'),
                                     external_network_id=self.ext_net_id,
                                     admin_state_up="true")
        self.create_router_interface(router2['id'], subnet2['id'])
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid = self._create_server_multiple_nic(
            name, self.network['id'], network2['id'],
            group_create_body['security_group']['id'])
        self.addCleanup(self._delete_server, serverid)
        self._fetch_network_segmentid_and_verify_portgroup(self.network['id'])
        self._fetch_network_segmentid_and_verify_portgroup(network2['id'])
        deviceport = self.client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)

    def test_validate_vreation_of_vm_attach_to_user_created_multiple_ports(
            self):
        """Validate_Creation_of_VM_attach_to_user_created_multiple_ports.

        1.  Create a 2 network with subnet attached to it.
        2.  Create a custom security group.
        3.  Create ports for both the networks.
        3.  Boot VM with custom security rule with user created ports.
        4.  Validate multiple PG creation each with network id.
        5.  Validate the vlan-ids of PG are properly binded with segment-ids.
        """
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router1 = self.create_router(data_utils.rand_name('router1-'),
                                     external_network_id=self.ext_net_id,
                                     admin_state_up="true")
        self.create_router_interface(router1['id'], subnet1['id'])
        port1 = self.create_port(network1)

        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router2-'),
                                     external_network_id=self.ext_net_id,
                                     admin_state_up="true")
        self.create_router_interface(router2['id'], subnet2['id'])
        port2 = self.create_port(network2)
        name = data_utils.rand_name('server-smoke')
        group_create_body, _ = self._create_security_group()

        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            self.client.create_security_group_rule(
                security_group_id=group_create_body['security_group']['id'],
                protocol=protocol,
                direction='ingress',
                ethertype=self.ethertype
            )
        serverid = self._create_server_multiple_nic_user_created_port(
            name, port1['id'], port2['id'],
            group_create_body['security_group']['id'])
        self.addCleanup(self._delete_server, serverid)
        self._fetch_network_segmentid_and_verify_portgroup(network1['id'])
        self._fetch_network_segmentid_and_verify_portgroup(network2['id'])
        deviceport = self.client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)

    def test_PG_gets_deleted_when_the_last_vm_in_the_network_is_deleted(self):
        """Validate_Creation_of_VM_attach_to_user_created_multiple_ports.

        1. Create a 2 network with subnet attached to it.
        2. Create a custom security group.
        3. Create ports for both the networks.
        3. Boot VM with custom security rule with user created ports.
        4. Validate multiple PG creation each with network id.
        5. Validate the vlan-ids of PG are properly binded with segment-ids.
        """
        net_id = self.network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid1 = self._create_server(
            name, net_id, group_create_body['security_group']['id'])
        serverid2 = self._create_server(
            name, net_id, group_create_body['security_group']['id'])
        self._fetch_network_segmentid_and_verify_portgroup(net_id)
        deviceport = self.client.list_ports(device_id=serverid1)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        self._delete_server(serverid1)
        self._fetch_network_segmentid_and_verify_portgroup(net_id)
        self._delete_server(serverid2)
        self._verify_portgroup_after_vm_delete(net_id)

    def test_Validate_deletion_of_vm_attached_to_multiple_networks(self):
        """Validate_deletion_of_vm_attached_to_multiple_networks.

        1. Create a two different network with subnet attached to it.
        2. Create a custom security group.
        3. Boot VM with custom security rule.
        4. Validate multiple PG creation each with network id.
        5. Validate the vlan-ids of PG are properly binded with segment-ids.
        6. Delete VM and check both the PG's gets deleted.
        """
        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router2-'),
                                     external_network_id=self.ext_net_id,
                                     admin_state_up="true")
        self.create_router_interface(router2['id'], subnet2['id'])
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid = self._create_server_multiple_nic(
            name, self.network['id'], network2['id'],
            group_create_body['security_group']['id'])
        self._fetch_network_segmentid_and_verify_portgroup(self.network['id'])
        self._fetch_network_segmentid_and_verify_portgroup(network2['id'])
        deviceport = self.client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        self._delete_server(serverid)
        self._verify_portgroup_after_vm_delete(self.network['id'])
        self._verify_portgroup_after_vm_delete(network2['id'])

    def test_update_instance_port_admin_state(self):
        """Perform a port update on the VM located on ESX hypervisor.

        1. Check public connectivity before updating
                admin_state_up attribute of instance port to False
        2. Check public connectivity after updating
                admin_state_up attribute of instance port to False
        3. Check public connectivity after updating
                admin_state_up attribute of instance port to True
        """
        net_id = self.network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid = self._create_server(name, net_id, group_create_body[
            'security_group']['id'])
        self.addCleanup(self._delete_server, serverid)
        self._fetch_network_segmentid_and_verify_portgroup(net_id)
        deviceport = self.client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        new_name = "New_Port"
        body = self.client.update_port(deviceport['ports'][0]['id'],
                                       name=new_name,
                                       admin_state_up=False)
        updated_port = body['port']
        self.assertEqual(updated_port['name'], new_name)
        self.assertFalse(updated_port['admin_state_up'])
        self._check_public_network_connectivity(floatingiptoreach,
                                                should_connect=False)
        body = self.client.update_port(deviceport['ports'][0]['id'],
                                       admin_state_up=True)
        updated_port = body['port']
        self.assertTrue(updated_port['admin_state_up'])
        self._check_public_network_connectivity(floatingiptoreach)
