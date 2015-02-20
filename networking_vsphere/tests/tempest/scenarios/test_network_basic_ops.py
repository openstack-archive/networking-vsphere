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
import atexit
import collections
import pyVim
from pyVim import connect
from pyVim.connect import Disconnect
import pyVmomi
from pyVmomi import vim
import re

from tempest_lib import decorators
import testtools

from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest.services.network import resources as net_resources
from tempest import test

CONF = config.CONF
LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestNetworkBasicOps(manager.NetworkScenarioTest):

    """
    This smoke test suite assumes that Nova has been configured to
    boot VM's with Neutron-managed networking, and attempts to
    verify network connectivity as follows:

     There are presumed to be two types of networks: tenant and
     public.  A tenant network may or may not be reachable from the
     Tempest host.  A public network is assumed to be reachable from
     the Tempest host, and it should be possible to associate a public
     ('floating') IP address with a tenant ('fixed') IP address to
     facilitate external connectivity to a potentially unroutable
     tenant IP address.

     This test suite can be configured to test network connectivity to
     a VM via a tenant network, a public network, or both.  If both
     networking types are to be evaluated, tests that need to be
     executed remotely on the VM (via ssh) will only be run against
     one of the networks (to minimize test execution time).

     Determine which types of networks to test as follows:

     * Configure tenant network checks (via the
       'tenant_networks_reachable' key) if the Tempest host should
       have direct connectivity to tenant networks.  This is likely to
       be the case if Tempest is running on the same host as a
       single-node devstack installation with IP namespaces disabled.

     * Configure checks for a public network if a public network has
       been configured prior to the test suite being run and if the
       Tempest host should have connectivity to that public network.
       Checking connectivity for a public network requires that a
       value be provided for 'public_network_id'.  A value can
       optionally be provided for 'public_router_id' if tenants will
       use a shared router to access a public network (as is likely to
       be the case when IP namespaces are not enabled).  If a value is
       not provided for 'public_router_id', a router will be created
       for each tenant and use the network identified by
       'public_network_id' as its gateway.

    """

    @classmethod
    def check_preconditions(cls):
        super(TestNetworkBasicOps, cls).check_preconditions()
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)
        # Create no network resources for these tests.
        cls.set_network_resources()
        super(TestNetworkBasicOps, cls).resource_setup()

    def setUp(self):
        super(TestNetworkBasicOps, self).setUp()
        self.keypairs = {}
        self.servers = []

    def _setup_network_and_servers(self, **kwargs):
        self.security_group = \
            self._create_security_group(tenant_id=self.tenant_id)
        self.network, self.subnet, self.router = self.create_networks(**kwargs)
        self.check_networks()

        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, self.network)
        self._check_tenant_network_connectivity()

        floating_ip = self.create_floating_ip(server)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)

    def check_networks(self):
        """
        Checks that we see the newly created network/subnet/router via
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

    def _create_server(self, name, network):
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
        server = self.create_server(name=name, create_kwargs=create_kwargs)
        self.servers.append(server)
        return server

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _check_tenant_network_connectivity(self):
        ssh_login = CONF.compute.image_ssh_user
        for server in self.servers:
            # call the common method in the parent class
            super(TestNetworkBasicOps, self).\
                _check_tenant_network_connectivity(
                    server, ssh_login, self._get_server_key(server),
                    servers_for_debug=self.servers)

    def check_public_network_connectivity(
            self, should_connect=True, msg=None,
            should_check_floating_ip_status=True):
        """Verifies connectivty to a VM via public network and floating IP,
        and verifies floating IP has resource status is correct.

        :param should_connect: bool. determines if connectivity check is
        negative or positive.
        :param msg: Failure message to add to Error message. Should describe
        the place in the test scenario where the method was called,
        to indicate the context of the failure
        :param should_check_floating_ip_status: bool. should status of
        floating_ip be checked or not
        """
        ssh_login = CONF.compute.image_ssh_user
        floating_ip, server = self.floating_ip_tuple
        ip_address = floating_ip.floating_ip_address
        private_key = None
        floatingip_status = 'DOWN'
        if should_connect:
            private_key = self._get_server_key(server)
            floatingip_status = 'ACTIVE'
        # call the common method in the parent class
        super(TestNetworkBasicOps, self).check_public_network_connectivity(
            ip_address, ssh_login, private_key, should_connect, msg,
            self.servers)
        if should_check_floating_ip_status:
            self.check_floating_ip_status(floating_ip, floatingip_status)

    def _disassociate_floating_ips(self):
        floating_ip, server = self.floating_ip_tuple
        self._disassociate_floating_ip(floating_ip)
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, None)

    def _reassociate_floating_ips(self):
        floating_ip, server = self.floating_ip_tuple
        name = data_utils.rand_name('new_server-smoke-')
        # create a new server for the floating ip
        server = self._create_server(name, self.network)
        self._associate_floating_ip(floating_ip, server)
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, server)

    def _create_new_network(self):
        self.new_net = self._create_network(tenant_id=self.tenant_id)
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
        _, interface = self.interface_client.create_interface(
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

    def _check_network_internal_connectivity(self, network):
        """
        via ssh check VM internal connectivity:
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

        self._check_server_connectivity(floating_ip, internal_ips)

    def _check_network_external_connectivity(self):
        """
        ping public network default gateway to imply external connectivity

        """
        if not CONF.network.public_network_id:
            msg = 'public network not defined.'
            LOG.info(msg)
            return

        subnet = self._list_subnets(
            network_id=CONF.network.public_network_id)
        self.assertEqual(1, len(subnet), "Found %d subnets" % len(subnet))

        external_ips = [subnet[0]['gateway_ip']]
        self._check_server_connectivity(self.floating_ip_tuple.floating_ip,
                                        external_ips)

    def _check_server_connectivity(self, floating_ip, address_list):
        ip_address = floating_ip.floating_ip_address
        private_key = self._get_server_key(self.floating_ip_tuple.server)
        ssh_source = self._ssh_to_server(ip_address, private_key)

        for remote_ip in address_list:
            try:
                self.assertTrue(self._check_remote_connectivity(ssh_source,
                                                                remote_ip),
                                "Timed out waiting for %s to become "
                                "reachable" % remote_ip)
            except Exception:
                LOG.exception("Unable to access {dest} via ssh to "
                              "floating-ip {src}".format(dest=remote_ip,
                                                         src=floating_ip))
                raise

    def get_obj(self, content, vimtype, name):
        """
        Get the vsphere object associated with a given text name
        """
        obj = None
        container = content.viewManager.CreateContainerView(content.rootFolder,
                                                            vimtype, True)
        for c in container.view:
                if c.name == name:
                    obj = c
                    break
        return obj

    def vsphere(self, vcenter_ip, vcenter_username, vcenter_password):
            si = None
            try:
                msg = 'Trying to connect .....'
                LOG.info(msg)
                si = connect.Connect(vcenter_ip, 443, vcenter_username,
                                     vcenter_password, service="hostd")
            except Exception:
                LOG.exception("Could not connect to the specified host")
                raise
            atexit.register(Disconnect, si)
            content = si.RetrieveContent()
            return content

    def _portgroup_verify(self, portgroup):
        vcenter_ip = CONF.network.vcenter_ip
        trunk_dvswitch_name = CONF.network.trunk_dvswitch_name
        vcenter_username = CONF.network.vcenter_username
        vcenter_password = CONF.network.vcenter_password
        content = self.vsphere(vcenter_ip, vcenter_username, vcenter_password)
        dvswitch_obj = self.get_obj(content, [vim.DistributedVirtualSwitch],
                                    trunk_dvswitch_name)
        port_groups = dvswitch_obj.portgroup
        for port_group in port_groups:
                portgroupname = port_group.name
                self.portgroup_list.append(portgroupname)
        self.assertIn(portgroup, self.portgroup_list)

    def _setup_server_with_multiple_network(self):
        self.network, self.subnet, self.router = self.create_networks()
        self.check_networks()
        self.network1, self.subnet1, self.router1 = self.create_networks()
        name = data_utils.rand_name('server-smoke')
        self._create_server_multiple_nics(name, self.network, self.network1)

    def _create_server_multiple_nics(self, name, network, network1):
        create_kwargs = {
            'networks': [
                {'uuid': network.id},
                {'uuid': network1.id},
            ],
        }
        server = self.create_server(name=name, create_kwargs=create_kwargs)
        self.servers.append(server)
        return server

    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_network_basic_ops(self):
        """
        For a freshly-booted VM with an IP address ("port") on a given
            network:

        - the Tempest host can ping the IP address.  This implies, but
         does not guarantee (see the ssh check that follows), that the
         VM has been assigned the correct IP address and has
         connectivity to the Tempest host.

        - the Tempest host can perform key-based authentication to an
         ssh server hosted at the IP address.  This check guarantees
         that the IP address is associated with the target VM.

        - the Tempest host can ssh into the VM via the IP address and
         successfully execute the following:

         - ping an external IP address, implying external connectivity.

         - ping an external hostname, implying that dns is correctly
           configured.

         - ping an internal IP address, implying connectivity to another
           VM on the same network.

        - detach the floating-ip from the VM and verify that it becomes
        unreachable

        - associate detached floating ip to a new VM and verify connectivity.
        VMs are created with unique keypair so connectivity also asserts that
        floating IP is associated with the new VM instead of the old one

        Verifies that floating IP status is updated correctly after each change


        """
        self._setup_network_and_servers()
        self.check_public_network_connectivity(should_connect=True)
        self._check_network_internal_connectivity(network=self.network)
        self._check_network_external_connectivity()
        self._disassociate_floating_ips()
        self.check_public_network_connectivity(should_connect=False,
                                               msg="after disassociate "
                                                   "floating ip")
        self._reassociate_floating_ips()
        self.check_public_network_connectivity(should_connect=True,
                                               msg="after re-associate "
                                                   "floating ip")

    @testtools.skipUnless(CONF.compute_feature_enabled.interface_attach,
                          'NIC hotplug not available')
    @testtools.skipIf(CONF.network.port_vnic_type in ['direct', 'macvtap'],
                      'NIC hotplug not supported for '
                      'vnic_type direct or macvtap')
    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_hotplug_nic(self):
        """
        1. create a new network, with no gateway (to prevent overwriting VM's
            gateway)
        2. connect VM to new network
        3. set static ip and bring new nic up
        4. check VM can ping new network dhcp port

        """
        self._setup_network_and_servers()
        self.check_public_network_connectivity(should_connect=True)
        self._create_new_network()
        self._hotplug_server()
        self._check_network_internal_connectivity(network=self.new_net)

    @testtools.skipIf(CONF.baremetal.driver_enabled,
                      'Router state cannot be altered on a shared baremetal '
                      'network')
    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_update_router_admin_state(self):
        """
        1. Check public connectivity before updating
                admin_state_up attribute of router to False
        2. Check public connectivity after updating
                admin_state_up attribute of router to False
        3. Check public connectivity after updating
                admin_state_up attribute of router to True
        """
        self._setup_network_and_servers()
        self.check_public_network_connectivity(
            should_connect=True, msg="before updating "
            "admin_state_up of router to False")
        self._update_router_admin_state(self.router, False)
        # TODO(alokmaurya): Remove should_check_floating_ip_status=False check
        # once bug 1396310 is fixed

        self.check_public_network_connectivity(
            should_connect=False, msg="after updating "
            "admin_state_up of router to False",
            should_check_floating_ip_status=False)
        self._update_router_admin_state(self.router, True)
        self.check_public_network_connectivity(
            should_connect=True, msg="after updating "
            "admin_state_up of router to True")

    def _check_dns_server(self, ssh_client, dns_servers):
        servers = ssh_client.get_dns_servers()
        self.assertEqual(set(dns_servers), set(servers),
                         'Looking for servers: {trgt_serv}. '
                         'Retrieved DNS nameservers: {act_serv} '
                         'From host: {host}.'
                         .format(host=ssh_client.ssh_client.host,
                                 act_serv=servers,
                                 trgt_serv=dns_servers))

    @decorators.skip_because(bug="1412325")
    @testtools.skipUnless(CONF.scenario.dhcp_client,
                          "DHCP client is not available.")
    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_subnet_details(self):
        """Tests that subnet's extra configuration details are affecting
        the VMs

         NOTE: Neutron subnets push data to servers via dhcp-agent, so any
         update in subnet requires server to actively renew its DHCP lease.

         1. Configure subnet with dns nameserver
         2. retrieve the VM's configured dns and verify it matches the one
         configured for the subnet.
         3. update subnet's dns
         4. retrieve the VM's configured dns and verify it matches the new one
         configured for the subnet.

         TODO(yfried): add host_routes

         any resolution check would be testing either:
            * l3 forwarding (tested in test_network_basic_ops)
            * Name resolution of an external DNS nameserver - out of scope for
            Tempest
        """
        # this test check only updates (no actual resolution) so using
        # arbitrary ip addresses as nameservers, instead of parsing CONF
        initial_dns_server = '1.2.3.4'
        alt_dns_server = '9.8.7.6'
        self._setup_network_and_servers(dns_nameservers=[initial_dns_server])
        self.check_public_network_connectivity(should_connect=True)

        floating_ip, server = self.floating_ip_tuple
        ip_address = floating_ip.floating_ip_address
        private_key = self._get_server_key(server)
        ssh_client = self._ssh_to_server(ip_address, private_key)

        self._check_dns_server(ssh_client, [initial_dns_server])

        self.subnet.update(dns_nameservers=[alt_dns_server])
        # asserts that Neutron DB has updated the nameservers
        self.assertEqual([alt_dns_server], self.subnet.dns_nameservers,
                         "Failed to update subnet's nameservers")

        # server needs to renew its dhcp lease in order to get the new dns
        # definitions from subnet
        ssh_client.renew_lease(fixed_ip=floating_ip['fixed_ip_address'])
        self._check_dns_server(ssh_client, [alt_dns_server])

    @testtools.skipIf(CONF.baremetal.driver_enabled,
                      'admin_state of instance ports cannot be altered '
                      'for baremetal nodes')
    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_update_instance_port_admin_state(self):
        """
        1. Check public connectivity before updating
                admin_state_up attribute of instance port to False
        2. Check public connectivity after updating
                admin_state_up attribute of instance port to False
        3. Check public connectivity after updating
                admin_state_up attribute of instance port to True
        """
        self._setup_network_and_servers()
        floating_ip, server = self.floating_ip_tuple
        server_id = server['id']
        port_id = self._list_ports(device_id=server_id)[0]['id']
        self.check_public_network_connectivity(
            should_connect=True, msg="before updating "
            "admin_state_up of instance port to False")
        self.network_client.update_port(port_id, admin_state_up=False)
        self.check_public_network_connectivity(
            should_connect=False, msg="after updating "
            "admin_state_up of instance port to False",
            should_check_floating_ip_status=False)
        self.network_client.update_port(port_id, admin_state_up=True)
        self.check_public_network_connectivity(
            should_connect=True, msg="after updating "
            "admin_state_up of instance port to True")

    @test.attr(type='smoke')
    @test.services('compute', 'network', 'esx')
    def test_esx_network_basic_ops(self):
        """
            Test portgroup for the created VM using ESX hypervisor
        """
        self._setup_network_and_servers()
        self._portgroup_verify(portgroup=self.network.id)

    @test.attr(type='smoke')
    @test.services('compute', 'network', 'esx')
    def test_multiple_nic_for_vm(self):
        """
            Test portgroup for the multiple network for a VM
        """
        self._setup_server_with_multiple_network()
        self._portgroup_verify(portgroup=self.network.id)
        self._check_network_internal_connectivity(network=self.network.id)
        self._portgroup_verify(portgroup=self.network1.id)
        self._check_network_internal_connectivity(network=self.network1.id)
