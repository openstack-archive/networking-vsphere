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

import time

from networking_vsphere.tests.scenario import manager

from neutron.common import exceptions
from neutron.tests.tempest import manager as auth_manager

from oslo_config import cfg
from oslo_serialization import jsonutils
from tempest_lib.common import rest_client
from tempest_lib.common.utils import data_utils

CONF = cfg.CONF


class OVSVAPPTestadminJSON(manager.ESXNetworksTestJSON):

    @classmethod
    def resource_setup(cls):
        super(OVSVAPPTestadminJSON, cls).resource_setup()
        cls.auth_provider = auth_manager.get_auth_provider(
            cls.isolated_creds.get_admin_creds())
        cls.ext_net_id = CONF.network.public_network_id
        cls.network = cls.create_shared_network()
        cls.subnet = cls.create_subnet(cls.network, client=cls.admin_client)

    def create_server_with_sec_group(self, name=None, network=None,
                                     securitygroup=None, wait_on_boot=True):
        region = CONF.compute.region
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        endpoint_type = CONF.compute.endpoint_type
        build_interval = CONF.compute.build_interval
        build_timeout = CONF.compute.build_timeout
        disable_ssl_cert = CONF.identity.disable_ssl_certificate_validation
        ca_certs = CONF.identity.ca_certificates_file
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           region, endpoint_type,
                                           build_interval, build_timeout,
                                           disable_ssl_cert,
                                           ca_certs)
        data = {"server": {"name": name, "imageRef": image,
                "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"uuid": network}],
                           "security_groups": [{"name": securitygroup}]}}

        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        self.wait_for_server_status_to_active(server_id, "ACTIVE")
        return server_id

    def wait_for_server_status_to_active(self, server_id, status):
        """Waits for a server to reach a given status."""
        region = CONF.compute.region
        endpoint_type = CONF.compute.endpoint_type
        build_interval = CONF.compute.build_interval
        build_timeout = CONF.compute.build_timeout
        disable_ssl_cert = CONF.identity.disable_ssl_certificate_validation
        ca_certs = CONF.identity.ca_certificates_file
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           region, endpoint_type,
                                           build_interval, build_timeout,
                                           disable_ssl_cert,
                                           ca_certs)
        resp, body = rs_client.get("servers/%s" % str(server_id))
        body = jsonutils.loads(body)
        server_status = body['server']['status']
        start = int(time.time())

        while server_status != status:
            time.sleep(build_interval)
            rs_client = rest_client.RestClient(self.auth_provider,
                                               "compute", region,
                                               endpoint_type,
                                               build_interval,
                                               build_timeout,
                                               disable_ssl_cert,
                                               ca_certs)
            resp, body = rs_client.get("servers/%s" % str(server_id))
            body = jsonutils.loads(body)
            server_status = body['server']['status']
            if int(time.time()) - start >= build_timeout:
                message = ('server %s failed to reach'
                           ' %s status (current %s) '
                           'within the required time (%s s).' %
                           (server_id, status, server_status,
                            build_timeout))
                raise exceptions.TimeoutException(message)

    def _wait_for_floating_ip_status(self, floating_ip_id, status):
        """Waits for a floating_ip to reach a given status."""
        build_timeout = CONF.compute.build_timeout
        build_interval = CONF.boto.build_interval
        floating_ip = self.admin_client.show_floatingip(floating_ip_id)
        shown_floating_ip = floating_ip['floatingip']
        floating_ip_status = shown_floating_ip['status']
        start = int(time.time())

        while floating_ip_status != status:
            time.sleep(build_interval)
            floating_ip = self.admin_client.show_floatingip(floating_ip_id)
            shown_floating_ip = floating_ip['floatingip']
            floating_ip_status = shown_floating_ip['status']
            if int(time.time()) - start >= build_timeout:
                message = ('floating_ip %s failed to reach'
                           ' %s status (current %s) '
                           'within the required time (%s s).' %
                           (floating_ip, status, floating_ip_status,
                            build_timeout))
                raise exceptions.TimeoutException(message)

    def test_validate_creation_of_VM_in_Shared_network(self):
        """Validate  creation of VM in Shared network.

        1.  Create a network with Shared network and attached the subnet to it.
        2.  Create a custom security group.
        3.  Boot VM with custom security rule.
        4.  Validate the Port group with the network name is created.
        5.  Validate the vlan-id in the PG is binded with segment id.
        6.  Check public connectivity after associating the floating ip.
        """
        netid = self.network['id']
        group_create_body = self.admin_client.create_security_group()
        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            self.admin_client.create_security_group_rule(
                security_group_id=group_create_body['security_group']['id'],
                protocol=protocol,
                direction='ingress',
                ethertype=self.ethertype
            )
        name = data_utils.rand_name('router-')
        router = self.admin_client.create_router(
            name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=True)
        self.addCleanup(self.admin_client.delete_router,
                        router['router']['id'])
        self.admin_client.add_router_interface_with_subnet_id(
            router['router']['id'], self.subnet['id'])
        self.addCleanup(
            self.admin_client.remove_router_interface_with_subnet_id,
            router['router']['id'], self.subnet['id'])
        name = data_utils.rand_name('server-smoke')
        serverid = self.create_server_with_sec_group(
            name, netid, group_create_body['security_group']['id'])
        body = self.admin_client.list_ports(device_id=serverid)
        self.addCleanup(self._delete_server, serverid)
        port_id = body['ports'][0]['id']
        floating_ip_admin = self.admin_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port_id)
        self.addCleanup(self.admin_client.delete_floatingip,
                        floating_ip_admin['floatingip']['id'])
        self._wait_for_floating_ip_status(
            floating_ip_admin['floatingip']['id'], "ACTIVE")
        self.ping_ip_address(
            floating_ip_admin['floatingip']['floating_ip_address'],
            should_succeed=True)
