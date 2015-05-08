# Copyright 2012 OpenStack Foundation
# Copyright 2013 Hewlett-Packard Development Company, L.P.
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

import collections
import re
import time

from oslo_log import log as logging
from tempest_lib.common.utils import data_utils

from networking_vsphere.tests.scenario import manager
from networking_vsphere.tests.tempest import config
from networking_vsphere.tests.tempest import test

from neutron.tests.tempest import exceptions
from neutron.tests.tempest.services.network import resources as net_resources

CONF = config.CONF
LOG = logging.getLogger(__name__)
Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestNetworkBasicOps(manager.NetworkScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestNetworkBasicOps, cls).skip_checks()
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        # Create no network resources for these tests.
        cls.set_network_resources()
        super(TestNetworkBasicOps, cls).setup_credentials()

    def setUp(self):
        super(TestNetworkBasicOps, self).setUp()
        self.keypairs = {}
        self.servers = []
        self.portgroup_list = []

    def _setup_network_and_servers(self, **kwargs):
        boot_with_port = kwargs.pop('boot_with_port', False)
        self.security_group = (
            self._create_security_group(tenant_id=self.tenant_id))
        self.network, self.subnet, self.router = self.create_networks(**kwargs)
        self.check_networks()

        self.port_id = None
        if boot_with_port:
            # create a port on the network and boot with that
            self.port_id = self._create_port(self.network['id']).id

        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, self.network, self.port_id)
        self._check_tenant_network_connectivity()

        floating_ip = self.create_floating_ip(server)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)

    def check_networks(self):
        """Checks that we see the newly created network/subnet/router via

        checking the result of list_[networks,routers,subnets]
        """

        seen_nets = self._list_networks()
        seen_names = [n['name'] for n in seen_nets]
        seen_ids = [n['id'] for n in seen_nets]
        self.assertIn(self.network.name, seen_names)
        self.assertIn(self.network.id, seen_ids)

        if self.subnet:
            seen_subnets = self._list_subnets()
            seen_net_ids = [n['network_id'] for n in seen_subnets]
            seen_subnet_ids = [n['id'] for n in seen_subnets]
            self.assertIn(self.network.id, seen_net_ids)
            self.assertIn(self.subnet.id, seen_subnet_ids)

        if self.router:
            seen_routers = self._list_routers()
            seen_router_ids = [n['id'] for n in seen_routers]
            seen_router_names = [n['name'] for n in seen_routers]
            self.assertIn(self.router.name,
                          seen_router_names)
            self.assertIn(self.router.id,
                          seen_router_ids)

    def _create_server(self, name, network, port_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': self.security_group['name']}]
        create_kwargs = {
            'networks': [
                {'uuid': network.id},
            ],
            'key_name': keypair['name'],
            'security_groups': security_groups,
        }
        if port_id is not None:
            create_kwargs['networks'][0]['port'] = port_id
        server = self.create_server(name=name, create_kwargs=create_kwargs)
        self.servers.append(server)
        return server

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _check_tenant_network_connectivity(self):
        ssh_login = CONF.compute.image_ssh_user
        for server in self.servers:
            # call the common method in the parent class
            super(TestNetworkBasicOps, self)._check_tenant_net_connectivity(
                server, ssh_login, self._get_server_key(server),
                servers_for_debug=self.servers)

    def check_public_network_connectivity(
            self, should_connect=True, msg=None,
            should_check_floating_ip_status=True):
        ssh_login = CONF.compute.image_ssh_user
        floating_ip, server = self.floating_ip_tuple
        ip_address = floating_ip.floating_ip_address
        private_key = None
        floatingip_status = 'DOWN'
        if should_connect:
            private_key = self._get_server_key(server)
            floatingip_status = 'ACTIVE'
        # Check FloatingIP Status before initiating a connection
        if should_check_floating_ip_status:
            self.check_floating_ip_status(floating_ip, floatingip_status)
        # call the common method in the parent class
        super(TestNetworkBasicOps, self).check_public_network_connectivity(
            ip_address, ssh_login, private_key, should_connect, msg,
            self.servers)

    def _disassociate_floating_ips(self):
        floating_ip, server = self.floating_ip_tuple
        self._disassociate_floating_ip(floating_ip)
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, None)

    def _reassociate_floating_ips(self):
        floating_ip, server = self.floating_ip_tuple
        name = data_utils.rand_name('new_server-smoke')
        # create a new server for the floating ip
        server = self._create_server(name, self.network)
        self._associate_floating_ip(floating_ip, server)
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, server)

    def _create_new_network(self, create_gateway=False):
        self.new_net = self._create_network(tenant_id=self.tenant_id)
        if create_gateway:
            self.new_subnet = self._create_subnet(
                network=self.new_net)
        else:
            self.new_subnet = self._create_subnet(
                network=self.new_net,
                gateway_ip=None)

    def _hotplug_server(self):
        old_floating_ip, server = self.floating_ip_tuple
        ip_address = old_floating_ip.floating_ip_address
        private_key = self._get_server_key(server)
        ssh_client = self.get_remote_client(ip_address,
                                            private_key=private_key)
        old_nic_list = self._get_server_nics(ssh_client)
        # get a port from a list of one item
        port_list = self._list_ports(device_id=server['id'])
        self.assertEqual(1, len(port_list))
        old_port = port_list[0]
        interface = self.interface_client.create_interface(
            server=server['id'],
            network_id=self.new_net.id)
        self.addCleanup(self.network_client.wait_for_resource_deletion,
                        'port',
                        interface['port_id'])
        self.addCleanup(self.delete_wrapper,
                        self.interface_client.delete_interface,
                        server['id'], interface['port_id'])

        def check_ports():
            self.new_port_list = [port for port in
                                  self._list_ports(device_id=server['id'])
                                  if port['id'] != old_port['id']]
            return len(self.new_port_list) == 1

        if not test.call_until_true(check_ports, CONF.network.build_timeout,
                                    CONF.network.build_interval):
            raise exceptions.TimeoutException(
                "No new port attached to the server in time (%s sec)! "
                "Old port: %s. Number of new ports: %d" % (
                    CONF.network.build_timeout, old_port,
                    len(self.new_port_list)))
        new_port = net_resources.DeletablePort(client=self.network_client,
                                               **self.new_port_list[0])

        def check_new_nic():
            new_nic_list = self._get_server_nics(ssh_client)
            self.diff_list = [n for n in new_nic_list if n not in old_nic_list]
            return len(self.diff_list) == 1

        if not test.call_until_true(check_new_nic, CONF.network.build_timeout,
                                    CONF.network.build_interval):
            raise exceptions.TimeoutException("Interface not visible on the "
                                              "guest after %s sec"
                                              % CONF.network.build_timeout)

        num, new_nic = self.diff_list[0]
        ssh_client.assign_static_ip(nic=new_nic,
                                    addr=new_port.fixed_ips[0]['ip_address'])
        ssh_client.turn_nic_on(nic=new_nic)

    def _get_server_nics(self, ssh_client):
        reg = re.compile(r'(?P<num>\d+): (?P<nic_name>\w+):')
        ipatxt = ssh_client.get_ip_list()
        return reg.findall(ipatxt)

    def _check_network_internal_connectivity(self, network,
                                             should_connect=True):
        """via ssh check VM internal connectivity:

        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        """
        floating_ip, server = self.floating_ip_tuple
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self._list_ports(tenant_id=server['tenant_id'],
                                         network_id=network.id)
                        if p['device_owner'].startswith('network'))

        self._check_server_connectivity(floating_ip,
                                        internal_ips,
                                        should_connect)

    def _check_network_external_connectivity(self):
        """ping public network default gateway to external connectivity."""
        if not CONF.network.public_network_id:
            msg = 'public network not defined.'
            LOG.info(msg)
            return

        # We ping the external IP from the instance using its floating IP
        # which is always IPv4, so we must only test connectivity to
        # external IPv4 IPs if the external network is dualstack.
        v4_subnets = [s for s in self._list_subnets(
            network_id=CONF.network.public_network_id) if s['ip_version'] == 4]
        self.assertEqual(1, len(v4_subnets),
                         "Found %d IPv4 subnets" % len(v4_subnets))

        external_ips = [v4_subnets[0]['gateway_ip']]
        self._check_server_connectivity(self.floating_ip_tuple.floating_ip,
                                        external_ips)

    def _check_server_connectivity(self, floating_ip, address_list,
                                   should_connect=True):
        ip_address = floating_ip.floating_ip_address
        private_key = self._get_server_key(self.floating_ip_tuple.server)
        ssh_source = self._ssh_to_server(ip_address, private_key)

        for remote_ip in address_list:
            if should_connect:
                msg = "Timed out waiting for "
                "%s to become reachable" % remote_ip
            else:
                msg = "ip address %s is reachable" % remote_ip
            try:
                self.assertTrue(self._check_remote_connectivity
                                (ssh_source, remote_ip, should_connect),
                                msg)
            except Exception:
                msg = _('Unable to access {dest} via ssh to')
                raise exceptions.TimeoutException(msg)

    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_create_server_with_two_nics(self):
        self.security_group = (
            self._create_security_group(tenant_id=self.tenant_id))
        network1, subnet1, router1 = self.create_networks()
        network2, subnet2, router2 = self.create_networks()
        name = data_utils.rand_name('server-smoke')
        server = self._create_server_multiple_nics(name, network1,
                                                   network2)
        time.sleep(20)
        ports = self._list_ports(device_id=server['id'])
        port_id = ports[0]['id']
        floating_ip = self.create_floating_ip(server, port_id=port_id)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
        self._check_tenant_network_connectivity()
        self.check_public_network_connectivity(
            should_connect=True)
        self._fetch_network_segmentid_and_verify_portgroup(network1.id)
        self._fetch_network_segmentid_and_verify_portgroup(network2.id)

    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_deletion_of_vm_attached_to_multiple_networks(self):
        """Test portgroup for the multiple network for a VM."""
        self.security_group = (
            self._create_security_group(tenant_id=self.tenant_id))
        network1, subnet1, router1 = self.create_networks()
        network2, subnet2, router2 = self.create_networks()
        name = data_utils.rand_name('server-smoke')
        server = self._create_server_multiple_nics_without_deleting(name,
                                                                    network1,
                                                                    network2)
        time.sleep(20)
        ports = self._list_ports(device_id=server['id'])
        port_id = ports[0]['id']
        floating_ip = self.create_floating_ip(server, port_id=port_id)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
        self._check_tenant_network_connectivity()
        self.check_public_network_connectivity(
            should_connect=True)
        self._fetch_network_segmentid_and_verify_portgroup(network1.id)
        self._fetch_network_segmentid_and_verify_portgroup(network2.id)
        self.servers_client.delete_server(server['id'])
        time.sleep(20)
        self._verify_portgroup_after_vm_delete(network1.id)
        self._verify_portgroup_after_vm_delete(network2.id)

    @test.services('compute', 'network')
    def test_Creation_of_VM_attach_to_user_created_multiple_ports(self):
        self.security_group = (
            self._create_security_group(tenant_id=self.tenant_id))
        network1, subnet1, router1 = self.create_networks()
        network2, subnet2, router2 = self.create_networks()
        kwargs = {
            'security_groups': [self.security_group['id']],
        }

        port1 = self._create_port(network1.id, **kwargs)
        port2 = self._create_port(network2.id, **kwargs)
        name = data_utils.rand_name('server-smoke')
        server = self._create_server_multiple_nics_user_created_port(name,
                                                                     port1.id,
                                                                     port2.id)
        time.sleep(20)
        ports = self._list_ports(device_id=server['id'])
        port_id = ports[0]['id']
        floating_ip = self.create_floating_ip(server, port_id=port_id)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
        self._check_tenant_network_connectivity()
        self.check_public_network_connectivity(
            should_connect=True)
        self._fetch_network_segmentid_and_verify_portgroup(network1.id)
        self._fetch_network_segmentid_and_verify_portgroup(network2.id)

    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_create_server_and_verify_port_group(self):
        self.security_group = (
            self._create_sec_group_without_deleting())
        network, router, subnet = self._create_network_subnet_router()
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': self.security_group['name']}]
        kwargs = {
            'networks': [
                {'uuid': network.id},
            ],
            'key_name': keypair['name'],
            'security_groups': security_groups,
        }
        server1 = self._create_server_without_deleting(create_kwargs=kwargs)
        server2 = self._create_server_without_deleting(create_kwargs=kwargs)
        time.sleep(10)
        self.servers.append(server1)
        floating_ip = self.create_floating_ip(server1)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server1)
        time.sleep(10)
        self._check_tenant_network_connectivity()
        self.check_public_network_connectivity(
            should_connect=True)
        self._fetch_network_segmentid_and_verify_portgroup(network.id)
        self.servers_client.delete_server(server1['id'])
        time.sleep(10)
        self._fetch_network_segmentid_and_verify_portgroup(network.id)
        self.servers_client.delete_server(server2['id'])
        time.sleep(10)
        self._verify_portgroup_after_vm_delete(network.id)
        self.network_client.remove_router_interface_with_subnet_id(router.id,
                                                                   subnet.id)
        self.network_client.delete_router(router['id'])
        self.network_client.delete_security_group(self.security_group['id'])

    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_creation_of_server_attached_to_user_created_port(self):
        self.security_group = (
            self._create_security_group(tenant_id=self.tenant_id))
        network, subnet, router = self.create_networks()
        kwargs = {
            'security_groups': [self.security_group['id']],
        }

        port = self._create_port(network.id, **kwargs)
        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, network, port.id)
        self._check_tenant_network_connectivity()
        floating_ip = self.create_floating_ip(server)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
        self.check_public_network_connectivity(
            should_connect=True)
	self._fetch_network_segmentid_and_verify_portgroup(network.id)
