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

from tempest_lib.common.utils import data_utils

CONF = cfg.CONF


class OVSvAppVmotionTestJSON(manager.ESXNetworksTestJSON):

    def test_vm_migration_across_hosts(self):
        """Validate added security group consistent even after vm migration.
        This test verifies the traffic after migrating the vms across the
        host in a cluster is consistent."""

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
        vcenter_ip = cfg.CONF.VCENTER.vcenter_ip
        vcenter_user = cfg.CONF.VCENTER.vcenter_username
        vcenter_pwd = cfg.CONF.VCENTER.vcenter_password
        cluster = cfg.CONF.VCENTER.cluster
        content = self._create.connection(vcenter_ip, vcenter_user,
                                          vcenter_pwd)
        vm_host = self._get_host_name(server_id)
        cluster_hosts = self._get_hosts_for_cluster(content, cluster)
        for host in cluster_hosts:
            if host.name != vm_host:
                dest_host = host
        # Live Migration
        task = self.migrate_vm(content, server_id, dest_host)
        self._wait_for_task(task, content)
        self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True)

    def test_port_update_after_vm_migration(self):
        """Verify port update after moving a VM from one host to another
        host"""
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
        vcenter_ip = cfg.CONF.VCENTER.vcenter_ip
        vcenter_user = cfg.CONF.VCENTER.vcenter_username
        vcenter_password = cfg.CONF.VCENTER.vcenter_password
        cluster = cfg.CONF.VCENTER.cluster
        content = self._create.connection(vcenter_ip, vcenter_user,
                                          vcenter_password)
        vm_host = self._get_host_name(server_id)
        cluster_hosts = self._get_hosts_for_cluster(content, cluster)
        for host in cluster_hosts:
            if host.name != vm_host:
                dest_host = host
        # Live Migration
        task = self.migrate_vm(content, server_id, dest_host)
        self._wait_for_task(task, content)
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

    def test_flows_consistent_across_ovsvapp_in_cluster(self):
        """Validate the Flows are consistent across OVSvAPPs in the same
        cluster"""
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
        binding_host = device_port['ports'][0]['binding:host_id']
        mac_addr = device_port['ports'][0]['mac_address']
        network = self.admin_client.show_network(self.network['id'])
        segment_id = network['network']['provider:segmentation_id']
        host_dic = self._get_host_name(server_id)
        host_name = host_dic['host_name']
        vapp_ipadd = self._get_vapp_ip(str(host_name), binding_host)
        port_id = device_port['ports'][0]['id']
        floating_ip = self._associate_floating_ips(port_id=port_id)
        self.client.create_security_group_rule(
            security_group_id=group_create_body_update['security_group']['id'],
            protocol='icmp',
            direction='ingress',
            ethertype=self.ethertype
        )
        self.ping_ip_address(
            floating_ip['floatingip']['floating_ip_address'],
            should_succeed=True)
        self._dump_flows_on_br_sec(vapp_ipadd, 'icmp', segment_id, mac_addr,
                                   device_port)
        body = self.admin_client.list_agents(agent_type='OVSvApp L2 Agent')
        agents = body['agents']
        for agent in agents:
            if binding_host != agent['host']:
                vapp_agent_name = agent['host']
        self._dump_flows_on_br_sec(vapp_agent_name, 'icmp', segment_id,
                                   mac_addr, device_port)
