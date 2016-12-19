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
from networking_vsphere.tests.scenario import manager

from oslo_config import cfg

from tempest.lib.common.utils import data_utils

CONF = cfg.CONF


class OVSvAppVmotionTestJSON(manager.ESXNetworksTestJSON):

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

    def _create_server_associate(self, test_sever, access_server, net=None):
        device_port1 = self.ports_client.list_ports(device_id=test_sever)
        port_id1 = device_port1['ports'][0]['id']
        sg_test_sever = device_port1['ports'][0]['security_groups'][0]
        device_port2 = self.ports_client.list_ports(
            device_id=access_server)
        port_id2 = device_port2['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id2)
        fip = floating_ip['floatingip']['floating_ip_address']
        sg_access_server = device_port2['ports'][0]['security_groups'][0]
        dest_ip = device_port1['ports'][0]['fixed_ips'][0]['ip_address']
        # Add tcp rule to ssh to first server.
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_access_server,
            protocol='tcp',
            direction='ingress',
            ethertype=self.ethertype
        )
        if net is None:
            net = self.network['name']
        remote_prefix_ip = self.get_server_ip(access_server,
                                              net)
        return (sg_test_sever, sg_access_server, dest_ip, fip,
                port_id1, port_id2, remote_prefix_ip)

    def test_vm_migration_across_hosts(self):
        """Validate added security group consistent even after vm migration.

        This test verifies the traffic after migrating the vms across the
        host in a cluster is consistent.
        """

        # Create security group for the server
        group_create_body_update, _ = self._create_security_group()

        # Create server with security group
        name = data_utils.rand_name('server-with-security-group')
        server_id = self._create_server_with_sec_group(
            name, self.network['id'],
            group_create_body_update['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], server_id))
        device_port = self.ports_client.list_ports(device_id=server_id)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False))

        # Update security group rule for the existing security group
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=group_create_body_update['security_group']['id'],
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype
        )
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))
        cluster = cfg.CONF.VCENTER.cluster_in_use
        content = self._create_connection()
        host_dic = self._get_host_name(server_id)
        vm_host = host_dic['host_name']
        vm_host_ip = vm_host.name
        cluster_hosts = self._get_hosts_for_cluster(content, cluster)
        if len(cluster_hosts.host) < 2:
            msg = "Min two hosts needed in cluster for Vmotion"
            raise testtools.TestCase.skipException(msg)
        for host in cluster_hosts.host:
            if host.name != vm_host_ip:
                dest_host = host
        # Live Migration
        task = self._migrate_vm(content, server_id, dest_host)
        self._wait_for_task(task, content)
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))

    def test_port_update_after_vm_migration(self):
        """Verify port update after moving a VM from one host to another host

        """
        # Create security group for the server
        group_create_body_update, _ = self._create_security_group()

        # Create server with security group
        name = data_utils.rand_name('server-with-security-group')
        server_id = self._create_server_with_sec_group(
            name, self.network['id'],
            group_create_body_update['security_group']['id'])
        self.assertTrue(self.verify_portgroup(self.network['id'], server_id))
        device_port = self.ports_client.list_ports(device_id=server_id)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=False))
        cluster = cfg.CONF.VCENTER.cluster_in_use
        content = self._create_connection()
        host_dic = self._get_host_name(server_id)
        vm_host = host_dic['host_name']
        vm_host_ip = vm_host.name
        cluster_hosts = self._get_hosts_for_cluster(content, cluster)
        if len(cluster_hosts.host) < 2:
            msg = "Min two hosts needed in cluster for Vmotion"
            raise testtools.TestCase.skipException(msg)
        for host in cluster_hosts.host:
            if host.name != vm_host_ip:
                dest_host = host
        # Live Migration
        task = self._migrate_vm(content, server_id, dest_host)
        self._wait_for_task(task, content)
        # Update security group rule for the existing security group
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=group_create_body_update['security_group']['id'],
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype
        )
        self.assertTrue(self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True))

    def test_vm_communication_part_of_diff_network_after_migrating_vm(self):
        network2 = self.create_network()
        sub_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr).next()
        subnet2 = self.create_subnet(network2, cidr=sub_cidr)
        self.create_router_interface(self.router['id'], subnet2['id'])
        net_name = network2['name']
        sg_body, _ = self._create_security_group()
        test_sever, access_server = \
            self._create_multiple_server_on_same_host(network2['id'])
        sg_test_sever, sg_access_server, dest_ip, fip, port1, port2, rp_ip = \
            self._create_server_associate(test_sever, access_server, net_name)
        update_body = {"security_groups": []}
        self.ports_client.update_port(port1, **update_body)
        # Add remote_ip_prefix as dest_ip
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_body['security_group']['id'],
            direction='ingress',
            ethertype=self.ethertype,
            protocol='icmp',
            remote_ip_prefix=str(rp_ip)
        )

        update_body = {"security_groups": [sg_body['security_group']['id']]}
        self.ports_client.update_port(port1, **update_body)
        # Ping second server from first server.
        cluster = cfg.CONF.VCENTER.cluster_in_use
        content = self._create_connection()
        host_dic = self._get_host_name(test_sever)
        vm_host = host_dic['host_name']
        vm_host_ip = vm_host.name
        cluster_hosts = self._get_hosts_for_cluster(content, cluster)
        if len(cluster_hosts.host) < 2:
            msg = "Min two hosts needed in cluster for Vmotion"
            raise testtools.TestCase.skipException(msg)
        for host in cluster_hosts.host:
            if host.name != vm_host_ip:
                dest_host = host
        # Live Migration
        task = self._migrate_vm(content, test_sever, dest_host)
        self._wait_for_task(task, content)
        self.assertTrue(self._check_remote_connectivity(fip, dest_ip))
