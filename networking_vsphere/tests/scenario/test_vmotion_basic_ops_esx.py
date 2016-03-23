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

from oslo_config import cfg

from tempest.lib.common.utils import data_utils

CONF = cfg.CONF


class OVSvAppVmotionTestJSON(manager.ESXNetworksTestJSON):

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
        cluster = cfg.CONF.VCENTER.cluster_in_use
        content = self._create_connection()
        host_dic = self._get_host_name(server_id)
        vm_host = host_dic['host_name']
        vm_host_ip = vm_host.name
        cluster_hosts = self._get_hosts_for_cluster(content, cluster)
        if len(cluster_hosts.host) < 2:
            raise Exception('Min two hosts needed in cluster for Vmotion')
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
        device_port = self.client.list_ports(device_id=server_id)
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
            raise Exception('Min two hosts needed in cluster for Vmotion')
        for host in cluster_hosts.host:
            if host.name != vm_host_ip:
                dest_host = host
        # Live Migration
        task = self._migrate_vm(content, server_id, dest_host)
        self._wait_for_task(task, content)
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
