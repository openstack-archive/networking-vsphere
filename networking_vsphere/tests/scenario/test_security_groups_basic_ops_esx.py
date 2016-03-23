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

from neutron.tests.tempest import exceptions

from tempest.lib.common.utils import data_utils


class OVSvAppSecurityGroupTestJSON(manager.ESXNetworksTestJSON):

    def _create_security_group_rule_with_specified_port_range(self):
        # Create security group for the server
        group_create_body_update, _ = self._create_security_group()

        # Create server with security group
        name = data_utils.rand_name('server-with-security-group')
        server_id = self._create_server_with_sec_group(
            name, self.network['id'],
            group_create_body_update['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], server_id))
        device_port = self.admin_client.list_ports(device_id=server_id)
        binding_host = device_port['ports'][0]['binding:host_id']
        mac_addr = device_port['ports'][0]['mac_address']
        network = self.admin_client.show_network(self.network['id'])
        segment_id = network['network']['provider:segmentation_id']
        host_dic = self._get_host_name(server_id)
        host_name = host_dic['host_name']
        vapp_ipadd = self._get_vapp_ip(str(host_name), binding_host)
        security_group = group_create_body_update['security_group']['id']
        return (security_group, vapp_ipadd, segment_id, mac_addr,
                self.network['id'])

    def _check_connectivity(self, source_ip, dest_ip, should_succeed=True):
        if should_succeed:
            msg = "Timed out waiting for %s to become reachable" % dest_ip
        else:
            msg = "%s is reachable" % dest_ip
        self.assertTrue(self._check_remote_connectivity(source_ip, dest_ip,
                                                        should_succeed), msg)

    def _create_server_associate(self, test_sever, access_server):
        device_port1 = self.client.list_ports(device_id=test_sever)
        port_id1 = device_port1['ports'][0]['id']
        sg_test_sever = device_port1['ports'][0]['security_groups'][0]
        device_port2 = self.client.list_ports(device_id=access_server)
        port_id2 = device_port2['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id2)
        fip = floating_ip['floatingip']['floating_ip_address']
        sg_access_server = device_port2['ports'][0]['security_groups'][0]
        dest_ip = device_port2['ports'][0]['fixed_ips'][0]['ip_address']
        # Add tcp rule to ssh to first server.
        self.client.create_security_group_rule(
            security_group_id=sg_access_server,
            protocol='tcp',
            direction='ingress',
            ethertype=self.ethertype
        )
        remote_prefix_ip = self.get_server_ip(access_server,
                                              self.network['name'])
        return (sg_test_sever, sg_access_server, dest_ip, fip,
                port_id1, port_id2, remote_prefix_ip)

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
        self.assertTrue(self.verify_portgroup(self.network['id'], server_id))
        device_port = self.client.list_ports(device_id=server_id)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False))

        # Update security group rule for the existing security group
        self.client.create_security_group_rule(
            security_group_id=group_create_body_update['security_group']['id'],
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype
        )
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))

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
        self.assertTrue(self.verify_portgroup(self.network['id'], server_id))
        device_port = self.client.list_ports(device_id=server_id)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False))
        # update port with new security group and check connectivity
        update_body = {"security_groups": [sg_body['security_group']['id']]}
        self.client.update_port(port_id, **update_body)
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))

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

        self._create_server_user_created_port(name, port_id)
        floating_ip = self._associate_floating_ips(
            port_id=port_id)
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))
        self._check_public_network_connectivity(
            floating_ip['floatingip']['floating_ip_address'])

    def test_validate_addition_of_ingress_rule(self):
        """test_validate_addition_of_ingress_rule

        This test case is used for validating addition ofingress rule
        """
        # Create security group to update the server
        group_create_body_new, _ = self._create_security_group()
        sg_body, _ = self._create_security_group()
        # Create server with default security group
        name = data_utils.rand_name('server-smoke')
        group_id = group_create_body_new['security_group']['id']
        serverid = self._create_server_with_sec_group(name,
                                                      self.network['id'],
                                                      group_id)
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))
        device_port = self.client.list_ports(device_id=serverid)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)

        # Now ping the server with the default security group & it should fail.
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False))
        self._check_public_network_connectivity(
            floating_ip['floatingip']['floating_ip_address'],
            should_connect=False, should_check_floating_ip_status=False)

        protocols = ['icmp', 'tcp']
        for protocol in protocols:
            self.client.create_security_group_rule(
                security_group_id=sg_body['security_group']['id'],
                protocol=protocol,
                direction='ingress',
                ethertype=self.ethertype
            )
        update_body = {"security_groups": [sg_body['security_group']['id']]}
        self.client.update_port(port_id, **update_body)

        # Now ping & SSH to recheck the connectivity & verify.
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))
        self._check_public_network_connectivity(
            floating_ip['floatingip']['floating_ip_address'])

    def test_port_update_with_no_security_group(self):
        """Validate port update with no security group.

        This test verifies the traffic after updating the vm port with no
        security group
        """
        # Create security group for the server
        group_create_body_update, _ = self._create_security_group()

        # Create server with security group
        name = data_utils.rand_name('server-with-security-group')
        server_id = self._create_server_with_sec_group(
            name, self.network['id'],
            group_create_body_update['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], server_id))
        device_port = self.client.list_ports(device_id=server_id)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)

        # Update security group rule for the existing security group
        self.client.create_security_group_rule(
            security_group_id=group_create_body_update['security_group']['id'],
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype
        )
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))
        self.client.update_port(port_id, security_groups=[])
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False))

    def test_security_group_rule_with_default_security_group_id(self):
        """Validate security group rule with default security group id.

        This test verifies the traffic after updating the default security
        group with a new security group rule.
        """
        # Create server with default security group.
        name = data_utils.rand_name('server-with-security-group')
        server_id = self._create_server(
            name, self.network['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], server_id))
        device_port = self.client.list_ports(device_id=server_id)
        port_id = device_port['ports'][0]['id']
        sec_grp_id = device_port['ports'][0]['security_groups'][0]
        floating_ip = self._associate_floating_ips(port_id=port_id)
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False))

        # Update security group rule for the default security group.
        self.client.create_security_group_rule(
            security_group_id=sec_grp_id,
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype
        )
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))

    def test_security_group_rule_with_remote_sg(self):
        """Validate security group rule with remote security group.

        This test verifies the traffic after adding the remote
        security group rule with exsisting security group.
        """
        # Create two server with different security group.
        test_sever, access_server = \
            self._create_multiple_server_on_different_host()
        sg_test_sever, sg_access_server, dest_ip, fip, port1, port2, rp_ip = \
            self._create_server_associate(test_sever, access_server)
        # Add group id of first sg to second sg.
        self.client.create_security_group_rule(
            security_group_id=sg_test_sever,
            direction='ingress',
            remote_group_id=sg_access_server,
            ethertype=self.ethertype
        )
        # Ping second server from first server.
        self.assertTrue(self._check_remote_connectivity(fip, dest_ip))

    def test_validate_addition_of_sec_with_remote_ip_prefix_as_dest_ip(self):

        """Validate security group rule with remote security group.

        This test verifies the traffic after adding the remote prefix
        as destination ip address
        """
        # Create two server with different security group.
        sg_body, _ = self._create_security_group()
        test_sever, access_server = \
            self._create_multiple_server_on_different_host()
        sg_test_sever, sg_access_server, dest_ip, fip, port1, port2, rp_ip = \
            self._create_server_associate(test_sever, access_server)
        update_body = {"security_groups": []}
        self.client.update_port(port1, **update_body)
        # Add remote_ip_prefix as dest_ip
        self.client.create_security_group_rule(
            security_group_id=sg_body['security_group']['id'],
            direction='ingress',
            ethertype=self.ethertype,
            protocol='icmp',
            remote_ip_prefix=str(rp_ip)
        )

        update_body = {"security_groups": [sg_body['security_group']['id']]}
        self.client.update_port(port1, **update_body)
        # Ping second server from first server.
        self.assertTrue(self._check_remote_connectivity(fip, dest_ip))

    def test_validate_addition_of_sec_with_remote_ip_prefix_as_0_0_0_0(self):

        """Validate security group rule with remote security group.

        This test verifies the traffic after adding the remote prefix
        as 0.0.0.0
        """
        # Create two server with different security group.
        sg_body, _ = self._create_security_group()
        test_sever, access_server = \
            self._create_multiple_server_on_different_host()
        sg_test_sever, sg_access_server, dest_ip, fip, port1, port2, rp_ip = \
            self._create_server_associate(test_sever, access_server)
        update_body = {"security_groups": []}
        self.client.update_port(port1, **update_body)
        # Add remote_ip_prefix as 0.0.0.0
        self.client.create_security_group_rule(
            security_group_id=sg_body['security_group']['id'],
            direction='ingress',
            ethertype=self.ethertype,
            protocol='icmp',
            remote_ip_prefix=str("0.0.0.0")
        )

        update_body = {"security_groups": [sg_body['security_group']['id']]}
        self.client.update_port(port1, **update_body)
        # Ping second server from first server.
        self.assertTrue(self._check_remote_connectivity(fip, dest_ip))

    def test_udp_security_group_rule_with_port_range(self):
        """Validate upd security group rule with port range.

        This test verifies the flow creation on br-sec
        for udp security group at OVSvApp Agent.
        """
        security_group, vapp_ipadd, segment_id, mac_addr, net_id = \
            self._create_security_group_rule_with_specified_port_range()
        self.client.create_security_group_rule(
            security_group_id=security_group,
            protocol='udp',
            direction='ingress',
            ethertype=self.ethertype,
            port_range_min=22,
            port_range_max=22,
            )
        self._dump_flows_on_br_sec(vapp_ipadd, 'udp',
                                   segment_id, mac_addr, '22', net_id)

    def test_create_security_group_rule_with_specified_tcp_port_range(self):

        """Validate secgroup rules for tcp protocol with specified port-range.

        This test verifies the tcp rules for a given range based on the flow
        creation on br-sec at the OVSvApp Agent.
        """
        security_group, vapp_ipadd, segment_id, mac_addr, net_id = \
            self._create_security_group_rule_with_specified_port_range()

        self.client.create_security_group_rule(
            security_group_id=security_group,
            protocol='tcp',
            direction='ingress',
            ethertype=self.ethertype,
            port_range_min=20,
            port_range_max=23,
            )
        for key in range(20, 24):
            self._dump_flows_on_br_sec(vapp_ipadd, 'tcp', segment_id,
                                       mac_addr, key, net_id)

    def test_icmp_security_group_rule_with_port_range(self):
        """Validate upd security group rule with port range.

        This test verifies the flow creation on br-sec
        for icmp security group at OVSvApp Agent.
        """
        security_group, vapp_ipadd, segment_id, mac_addr, net_id = \
            self._create_security_group_rule_with_specified_port_range()
        self.client.create_security_group_rule(
            security_group_id=security_group,
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype,
            port_range_min=22,
            port_range_max=23,
            )
        self._dump_flows_on_br_sec_for_icmp_rule(vapp_ipadd, 'icmp',
                                                 segment_id, mac_addr, '22',
                                                 '23', net_id)

    def test_flows_consistent_across_ovsvapp_in_cluster(self):
        """Validate the Flows are consistent across OVSvAPPs in the same

        cluster
        """
        net_id = self.network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body_update, _ = self._create_security_group()
        self.client.create_security_group_rule(
            security_group_id=group_create_body_update['security_group']['id'],
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype,
            port_range_min=8,
            port_range_max=0,
        )
        serverid = self._create_server_with_sec_group(
            name, net_id, group_create_body_update['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], serverid))
        device_port = self.admin_client.list_ports(device_id=serverid)
        binding_host = device_port['ports'][0]['binding:host_id']
        mac_addr = device_port['ports'][0]['mac_address']
        network = self.admin_client.show_network(self.network['id'])
        segment_id = network['network']['provider:segmentation_id']
        host_dic = self._get_host_name(serverid)
        host_name = host_dic['host_name']
        vapp_ipadd = self._get_vapp_ip(str(host_name), binding_host)
        body = self._associate_floating_ips(
            port_id=device_port['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self.assertTrue(self.ping_ip_address(
            floatingiptoreach,
            should_succeed=True))
        self._dump_flows_on_br_sec_for_icmp_type(vapp_ipadd, 'icmp',
                                                 segment_id, mac_addr, '8',
                                                 net_id)
        body = self.admin_client.list_agents(agent_type='OVSvApp Agent')
        agents = body['agents']
        vapp_ipadd_of_host = ""
        for agent in agents:
                if binding_host != agent['host']:
                        agent_alive_status = agent['alive']
                        if agent_alive_status is True:
                                vapp_agent_name = agent['host']
                                vapp_ipadd_of_host = \
                                    self._get_vapp_ip_from_agent_list(
                                        str(vapp_agent_name))
        if vapp_ipadd_of_host:
            self._dump_flows_on_br_sec_for_icmp_type(vapp_ipadd_of_host,
                                                     'icmp', segment_id,
                                                     mac_addr, '8', net_id)
        else:
            error_msg = "Host not found"
            raise exceptions.BadRequest(error_msg)
