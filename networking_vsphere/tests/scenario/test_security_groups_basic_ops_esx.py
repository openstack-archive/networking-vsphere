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
