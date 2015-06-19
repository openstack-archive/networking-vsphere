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


class OVSvAppSecurityGroupTestJSON(manager.ESXNetworksTestJSON):

    def _check_connectivity(self, source_ip, dest_ip, should_succeed=True):
        if should_succeed:
            msg = "Timed out waiting for %s to become reachable" % dest_ip
        else:
            msg = "%s is reachable" % dest_ip
        self.assertTrue(self._check_remote_connectivity(source_ip, dest_ip,
                                                        should_succeed), msg)

    def test_port_runtime_update_new_security_group_rule(self):
        """Validate new security group rule update.

        This test verifies the traffic after updating the vm port with new
        security group rule with exsisting security group.
        """
        # Create security group for the server
        group_create_body_update, _ = self._create_security_group()

        # Create server with security group
        name = data_utils.rand_name('server-with-security-group')
        server_id = self._create_server_with_sec_group(
            name, self.network['id'],
            group_create_body_update['security_group']['id'])
        self.addCleanup(self._delete_server, server_id)
        self._fetch_network_segmentid_and_verify_portgroup(self.network['id'])
        device_port = self.client.list_ports(device_id=server_id)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)
        self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False)

        # Update security group rule for the existing security group
        self.client.create_security_group_rule(
            security_group_id=group_create_body_update['security_group']['id'],
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype
        )
        self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True)

    def test_port_update_new_security_group(self):
        """This test verifies the traffic after updating.

        the vm port with new security group having appropriate rule.
        """
        # Create security group to update the server
        sg_body, _ = self._create_security_group()
        self.client.create_security_group_rule(
            security_group_id=sg_body['security_group']['id'], protocol='icmp',
            direction='ingress', ethertype=self.ethertype)

        # Create server with default security group
        name = data_utils.rand_name('server-with-default-security-group')
        server_id = self._create_server(name,
                                        self.network['id'])
        self.addCleanup(self._delete_server, server_id)
        self._fetch_network_segmentid_and_verify_portgroup(self.network['id'])
        device_port = self.client.list_ports(device_id=server_id)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)
        self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False)
        # update port with new security group and check connectivity
        update_body = {"security_groups": [sg_body['security_group']['id']]}
        self.client.update_port(port_id, **update_body)
        self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True)

    def test_port_creation_with_multiple_security_group(self):
        """Validate port creation with multiple security group.

        This test verifies the traffic after creating a port with
        multiple security groups.
        """
        # Create security groups
        first_security_group, _ = self._create_security_group()
        second_security_group, _ = self._create_security_group()
        post_body = {
            "name": data_utils.rand_name('port-'),
            "security_groups": [first_security_group['security_group']['id'],
                                second_security_group['security_group']['id']],
            "network_id": self.network['id'],
            "admin_state_up": True}

        # Create port with multiple security group
        body = self.client.create_port(**post_body)
        self.addCleanup(self.client.delete_port, body['port']['id'])
        self.client.create_security_group_rule(
            security_group_id=first_security_group['security_group']['id'],
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype)
        self.client.create_security_group_rule(
            security_group_id=second_security_group['security_group']['id'],
            protocol='tcp',
            direction='ingress',
            ethertype=self.ethertype)

        # Create server with given port
        name = data_utils.rand_name('server_with_user_created_port')
        port_id = body['port']['id']

        serverid = self._create_server_user_created_port(
            name, port_id)
        self.addCleanup(self._delete_server, serverid)
        floating_ip = self._associate_floating_ips(
            port_id=port_id)
        self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False)
        self._check_public_network_connectivity(
            floating_ip['floatingip']['floating_ip_address'])
