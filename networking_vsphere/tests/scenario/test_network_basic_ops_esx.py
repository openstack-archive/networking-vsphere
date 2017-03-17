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
import netaddr
import subprocess

from networking_vsphere.tests.scenario import manager

from oslo_config import cfg
from tempest.lib.common.utils import data_utils

CONF = cfg.CONF


class OVSVAPPTestJSON(manager.ESXNetworksTestJSON):

    def _create_custom_security_group(self):
        group_create_body, _ = self._create_security_group()

        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            self.security_group_rules_client.create_security_group_rule(
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
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))

    def test_validate_vm_created_is_accessible_through_the_floating_ip(self):
        """Validate the VM created in ESX is accessible through the floating ip

        1. Check public connectivity after associating the floating ip
        2. Check public connectivity after dis-associating the floating ip
        3. Check public connectivity after re-associating the floating ip again
        """
        net_id = self.network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid = self._create_server_with_sec_group(
            name, net_id, group_create_body['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))
        deviceport = self.ports_client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        self._disassociate_floating_ips()
        self._check_public_network_connectivity(
            floatingiptoreach,
            should_connect=False,
            should_check_floating_ip_status=False)
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
        group_create_body = self._create_custom_security_group()
        network2 = self.create_network()
        sub_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr).next()
        self.create_subnet(network2, cidr=sub_cidr, gateway=None)
        name = data_utils.rand_name('server-smoke')
        serverid = self._create_server_multiple_nic(
            name, self.network['id'], network2['id'],
            group_create_body['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))
        self.assertTrue(self.verify_portgroup(network2['id'], serverid))
        net_id1 = self.network['id']
        deviceport = self.ports_client.list_ports(device_id=serverid,
                                                  network_id=net_id1)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)

    def test_validate_creation_of_vm_attach_to_user_created_multiple_ports(
            self):
        """Validate_Creation_of_VM_attach_to_user_created_multiple_ports.

        1.  Create a 2 network with subnet attached to it.
        2.  Create a custom security group.
        3.  Create ports for both the networks.
        3.  Boot VM with custom security rule with user created ports.
        4.  Validate multiple PG creation each with network id.
        5.  Validate the vlan-ids of PG are properly binded with segment-ids.
        """
        group_create_body1 = self._create_custom_security_group()
        group_create_body2 = self._create_custom_security_group()
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router1 = self.create_router(data_utils.rand_name('router1-'),
                                     external_network_id=self.ext_net_id,
                                     admin_state_up="true")
        self.create_router_interface(router1['id'], subnet1['id'])
        post_body1 = {
            "name": data_utils.rand_name('port-'),
            "security_groups": [group_create_body1['security_group']['id']],
            "network_id": network1['id'],
            "admin_state_up": True}
        port_body1 = self.ports_client.create_port(**post_body1)
        self.addCleanup(self.ports_client.delete_port,
                        port_body1['port']['id'])
        network2 = self.create_network()
        sub_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr).next()
        self.create_subnet(network2, cidr=sub_cidr, gateway=None)
        post_body2 = {
            "name": data_utils.rand_name('port-'),
            "security_groups": [group_create_body2['security_group']['id']],
            "network_id": network2['id'],
            "admin_state_up": True}
        port_body2 = self.ports_client.create_port(**post_body2)
        self.addCleanup(self.ports_client.delete_port,
                        port_body2['port']['id'])
        name = data_utils.rand_name('server-smoke')
        group_create_body, _ = self._create_security_group()
        serverid = self._create_server_multiple_nic_user_created_port(
            name, port_body1['port']['id'], port_body2['port']['id'])
        self.assertTrue(self.verify_portgroup(network1['id'], serverid))
        self.assertTrue(self.verify_portgroup(network2['id'], serverid))
        net_id1 = self.network['id']
        deviceport = self.ports_client.list_ports(device_id=serverid,
                                                  network_id=net_id1)
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
        serverid1 = self._create_server_with_sec_group(
            name, net_id, group_create_body['security_group']['id'])
        serverid2 = self._create_server_with_sec_group(
            name, net_id, group_create_body['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid1))
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid2))
        deviceport = self.ports_client.list_ports(device_id=serverid1)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        self._delete_server(serverid1)
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid2))
        self._delete_server(serverid2)
        del_status = self.verify_portgroup_after_vm_delete(self.network['id'])
        self.assertFalse(del_status)

    def test_Validate_deletion_of_vm_attached_to_multiple_networks(self):
        """Validate_deletion_of_vm_attached_to_multiple_networks.

        1. Create a two different network with subnet attached to it.
        2. Create a custom security group.
        3. Boot VM with custom security rule.
        4. Validate multiple PG creation each with network id.
        5. Validate the vlan-ids of PG are properly binded with segment-ids.
        6. Delete VM and check both the PG's gets deleted.
        """
        group_create_body = self._create_custom_security_group()
        network2 = self.create_network()
        sub_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr).next()
        self.create_subnet(network2, cidr=sub_cidr, gateway=None)
        name = data_utils.rand_name('server-smoke')
        serverid = self._create_server_multiple_nic(
            name, self.network['id'], network2['id'],
            group_create_body['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))
        self.assertTrue(self.verify_portgroup(network2['id'], serverid))
        net_id1 = self.network['id']
        deviceport = self.ports_client.list_ports(device_id=serverid,
                                                  network_id=net_id1)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        self._delete_server(serverid)
        del_status = self.verify_portgroup_after_vm_delete(self.network['id'])
        self.assertFalse(del_status)
        del_status2 = self.verify_portgroup_after_vm_delete(network2['id'])
        self.assertFalse(del_status2)

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
        serverid = self._create_server_with_sec_group(
            name, net_id, group_create_body['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))
        deviceport = self.ports_client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        new_name = "New_Port"
        body = self.ports_client.update_port(deviceport['ports'][0]['id'],
                                             name=new_name,
                                             admin_state_up=False)
        updated_port = body['port']
        self.assertEqual(updated_port['name'], new_name)
        self.assertFalse(updated_port['admin_state_up'])
        self._check_public_network_connectivity(
            floatingiptoreach,
            should_connect=False,
            should_check_floating_ip_status=False)
        body = self.ports_client.update_port(deviceport['ports'][0]['id'],
                                             admin_state_up=True)
        updated_port = body['port']
        self.assertTrue(updated_port['admin_state_up'])
        self._check_public_network_connectivity(floatingiptoreach)

    def test_update_admin_state_up_of_vm_network_to_false(self):
        """Description of the test.

        1) Create a network, subnet, router
        2) Create a server
        3) Associate a floating ip to the vm port
        4) Verify floatingip connectivity
        5) update admin state of network to false
        6) verify the network namespace got deleted
        7) Verify floatingip connectivity after network update
        """
        network = self.create_network()
        sub_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr).next()
        subnet = self.create_subnet(network, cidr=sub_cidr)
        router = self.create_router(data_utils.rand_name('router-'),
                                    external_network_id=self.ext_net_id,
                                    admin_state_up="true")
        self.create_router_interface(router['id'], subnet['id'])
        net_id = network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid = self._create_server_with_sec_group(
            name, net_id, group_create_body['security_group']['id'])
        self.assertTrue(self.verify_portgroup(net_id, serverid))
        deviceport = self.ports_client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        body = self.networks_client.update_network(net_id,
                                                   admin_state_up=False)
        cont_ip = CONF.VCENTER.controller_ip
        vapp_username = CONF.VCENTER.vapp_username
        HOST = vapp_username + "@" + cont_ip
        cmd = ('sudo ip netns | grep ' + net_id)
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        self.assertEqual([], output)
        self._check_public_network_connectivity(floatingiptoreach)

    def test_creation_of_VM_attach_to_user_created_port(self):
        group_create_body = self._create_custom_security_group()
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'),
                                    external_network_id=self.ext_net_id,
                                    admin_state_up="true")
        self.create_router_interface(router['id'], subnet['id'])
        post_body = {
            "name": data_utils.rand_name('port-'),
            "security_groups": [group_create_body['security_group']['id']],
            "network_id": network['id'],
            "admin_state_up": True}
        port = self.ports_client.create_port(**post_body)
        self.addCleanup(self.ports_client.delete_port, port['port']['id'])
        name = data_utils.rand_name('server-smoke')
        group_create_body, _ = self._create_security_group()
        serverid = self._create_server_user_created_port(
            name, port['port']['id'])
        self.assertTrue(self.verify_portgroup(network['id'], serverid))
        deviceport = self.ports_client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)

    def test_to_verify_communication_between_two_vms_in_diff_network(self):
        net_id = self.network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid = self._create_server_with_sec_group(
            name, net_id, group_create_body['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))
        deviceport = self.ports_client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        fip1 = body['floatingip']['floating_ip_address']
        network2 = self.create_network()
        sub_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr).next()
        subnet2 = self.create_subnet(network2, cidr=sub_cidr)
        router2 = self.create_router(data_utils.rand_name('router2-'),
                                     external_network_id=self.ext_net_id,
                                     admin_state_up="true")
        self.create_router_interface(router2['id'], subnet2['id'])
        serverid2 = self._create_server_with_sec_group(
            name, network2['id'], group_create_body['security_group']['id'])
        deviceport2 = self.ports_client.list_ports(device_id=serverid2)
        body = self._associate_floating_ips(
            port_id=deviceport2['ports'][0]['id'])
        fip2 = body['floatingip']['floating_ip_address']
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))
        self.assertTrue(self.verify_portgroup(network2['id'], serverid2))
        self.assertTrue(self._check_remote_connectivity(fip1, fip2))

    def test_vm_after_restarting_ovsvvapp_agent_and_openvswitch(self):
        net_id = self.network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        server_id = self._create_server_with_sec_group(
            name, net_id, group_create_body['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], server_id))
        deviceport = self.admin_manager.ports_client.list_ports(
            device_id=server_id)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        binding_host = deviceport['ports'][0]['binding:host_id']
        host_dic = self._get_host_name(server_id)
        host_name = host_dic['host_name']
        vapp_ipadd = self._get_vapp_ip(str(host_name), binding_host)
        HOST = self.vapp_username + "@" + vapp_ipadd
        cmd = ('sudo service neutron-ovsvapp-agent stop')
        subprocess.Popen(["ssh", "%s" % HOST, cmd],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        self.assertTrue(self.ping_ip_address(
            floatingiptoreach,
            should_succeed=True))
        self._check_public_network_connectivity(floatingiptoreach)
        cmd = ('sudo service neutron-ovsvapp-agent start')
        subprocess.Popen(["ssh", "%s" % HOST, cmd],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        self.assertTrue(self.ping_ip_address(
            floatingiptoreach,
            should_succeed=True))
        cmd = ('sudo service openvswitch-switch stop')
        subprocess.Popen(["ssh", "%s" % HOST, cmd],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        self.assertTrue(self.ping_ip_address(
            floatingiptoreach,
            should_succeed=False))
        cmd = ('sudo service openvswitch-switch start')
        subprocess.Popen(["ssh", "%s" % HOST, cmd],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        self.assertTrue(self.ping_ip_address(
            floatingiptoreach,
            should_succeed=True))
        cmd = ('sudo service neutron-ovsvapp-agent stop')
        subprocess.Popen(["ssh", "%s" % HOST, cmd],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        cmd = ('sudo service openvswitch-switch stop')
        subprocess.Popen(["ssh", "%s" % HOST, cmd],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        self.assertTrue(self.ping_ip_address(
            floatingiptoreach,
            should_succeed=False))
        cmd = ('sudo service neutron-ovsvapp-agent start')
        subprocess.Popen(["ssh", "%s" % HOST, cmd],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        cmd = ('sudo service openvswitch-switch start')
        subprocess.Popen(["ssh", "%s" % HOST, cmd],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        self.assertTrue(self.ping_ip_address(
            floatingiptoreach,
            should_succeed=True))

    def test_validatate_tenant_isolation_when_using_overlapping_of_ips(self):
        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router2-'),
                                     external_network_id=self.ext_net_id,
                                     admin_state_up="true")
        self.create_router_interface(router2['id'], subnet2['id'])
        test_sever, access_server = \
            self._create_multiple_server_on_same_host(network2['id'])

        device_port1 = self.ports_client.list_ports(device_id=test_sever)
        port_id1 = device_port1['ports'][0]['id']
        device_port2 = self.ports_client.list_ports(
            device_id=access_server)
        port_id2 = device_port2['ports'][0]['id']
        floating_ip1 = self._associate_floating_ips(port_id=port_id1)
        fip1 = floating_ip1['floatingip']['floating_ip_address']
        create_floating_ip2 = self.create_floatingip(self.ext_net_id)
        floating_ip2 = self.floating_ips_client.update_floatingip(
            create_floating_ip2['id'], port_id=port_id2)
        updated_floating_ip = floating_ip2['floatingip']
        self.assertEqual(updated_floating_ip['port_id'], port_id2)
        self.wait_for_floating_ip_status(create_floating_ip2['id'], "ACTIVE")
        fip2 = floating_ip2['floatingip']['floating_ip_address']
        sg_test_sever = device_port1['ports'][0]['security_groups'][0]
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_test_sever,
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype
        )
        self.assertTrue(self.ping_ip_address(
            fip1,
            should_succeed=True))
        self.assertTrue(self.ping_ip_address(
            fip2,
            should_succeed=True))
