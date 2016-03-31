# Copyright (c) 2016 Hewlett-Packard Enterprise Development Company, L.P.
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

import subprocess
import time

from tempest.api.network import base
from tempest.common.utils import data_utils
from tempest import config
from tempest import test


CONF = config.CONF


class L3HAVRRP(base.BaseAdminNetworkTest):

    def _to_find_number_of_l3_agenst_per_routers(self, HOST):
        cmd = ('ps -ef | grep neutron.conf')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        path = output[2].split()[10].split('=')[1]

        ssh = subprocess.Popen(['ssh', "%s" % HOST, 'sudo cat', path],
                               stdout=subprocess.PIPE)
        output = ssh.stdout.readlines()
        find = filter(lambda x: 'max_l3_agents_per_router' in x, output)
        no_of_routers = find[0].split('=')[1]
        return int(no_of_routers)

    def _connect_to_host(self, HOST, total, router_id):
        cmd = ('sudo ip netns exec qrouter-' + router_id + ' ifconfig')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        if output:
            get_ha_link = output[0].split()[0].split("-")[1]
            find = filter(lambda x: get_ha_link in x, total)
            return find
        else:
            return None

    def _verify_ip_address(self, HOST, octet11, octet22, router_id):
        cmd = ('sudo ip netns exec qrouter-' + router_id + ' ifconfig')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        if output:
            ip_address = output[1].split()[1].split(':')[1].split('.')
            octet1 = ip_address[0]
            octet2 = ip_address[1]
            octet3 = ip_address[2]
            octet4 = ip_address[3]
            if octet11 == octet1 and octet22 == octet2:
                if int(octet3) < 255 and int(octet4) < 255:
                    pass
                else:
                    raise Exception("IP address is not in the given CIDR")
            else:
                raise Exception("IP address is not in the given CIDR")

    def _get_ip_addtess_from_neutron_conf(self, HOST):
        cmd = ('ps -ef | grep neutron.conf')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        path = output[4].split()[10].split('=')[1]
        ssh = subprocess.Popen(['ssh', "%s" % HOST, 'sudo cat', path],
                               stdout=subprocess.PIPE)
        output = ssh.stdout.readlines()
        find = filter(lambda x: 'l3_ha_net_cidr' in x, output)
        x = find[0].split()[2].split()[0].split('.')
        octet11 = x[0]
        octet22 = x[1]
        return octet11, octet22

    @test.requires_ext(service='network', extension='hos')
    @test.idempotent_id('acca05b1-3ff3-4e37-bdcf-56673066b4dc')
    @test.services('network')
    def test_HA_link_present_on_controllers(self):
        self.external_network_id = CONF.network.public_network_id
        name = data_utils.rand_name('router-')
        router = self.admin_client.create_router(
            name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=True)
        router_id = router['router']['id']
        self.addCleanup(self.admin_client.delete_router,
                        router['router']['id'])
        device_owner = "network:router_ha_interface"
        username = CONF.vrrp.host_username
        ctrl_ip_address1 = CONF.vrrp.deployer_ip_1
        ctrl_ip_address2 = CONF.vrrp.deployer_ip_2
        ctrl_ip_address3 = CONF.vrrp.deployer_ip_3
        HOST1 = username + "@" + ctrl_ip_address1
        HOST2 = username + "@" + ctrl_ip_address2
        HOST3 = username + "@" + ctrl_ip_address3

        self.router_list = self._to_find_number_of_l3_agenst_per_routers(HOST1)
        if self.router_list == 3:
            port_body = self.admin_client.list_ports(device_id=router_id,
                                                     device_owner=device_owner)
            first_id = port_body['ports'][0]['id']
            second_id = port_body['ports'][1]['id']
            third_id = port_body['ports'][2]['id']
            total = [first_id, second_id, third_id]
            self.value1 = self._connect_to_host(HOST1, total, router_id)
            self.value2 = self._connect_to_host(HOST2, total, router_id)
            self.value3 = self._connect_to_host(HOST3, total, router_id)
            content = [self.value1, self.value2, self.value3]
            count = 0
            for ww in content:
                if ww == []:
                    count = count + 1

                if count > 0:
                    msg = "All controllers not having a HA link"
                    raise Exception(msg)
        if self.router_list == 2:
            port_body = self.admin_client.list_ports(device_id=router_id,
                                                     device_owner=device_owner)
            first_id = port_body['ports'][0]['id']
            second_id = port_body['ports'][1]['id']
            total = [first_id, second_id]

            self.value1 = self._connect_to_host(HOST1, total, router_id)
            self.value2 = self._connect_to_host(HOST2, total, router_id)
            self.value3 = self._connect_to_host(HOST3, total, router_id)
            content = [self.value1, self.value2, self.value3]
            count = 0
            for ww in content:
                if ww == []:
                    count = count + 1

                if count > 1:
                    msg = "More than one controller not having HA link"
                    raise Exception(msg)

        self.octet11, self.octet22 = self._get_ip_addtess_from_neutron_conf(
            HOST1)

        self._verify_ip_address(HOST1, self.octet11, self.octet22, router_id)
        self._verify_ip_address(HOST2, self.octet11, self.octet22, router_id)
        self._verify_ip_address(HOST3, self.octet11, self.octet22, router_id)

    @test.requires_ext(service='network', extension='hos')
    @test.idempotent_id('adbf3277-2c54-432e-8f75-78f3462d17c9')
    @test.services('network')
    def test_non_preempt_default_option(self):
        self.external_network_id = CONF.network.public_network_id
        name = data_utils.rand_name('router-')
        router = self.admin_client.create_router(
            name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=True)
        time.sleep(20)
        router_id = router['router']['id']
        self.addCleanup(self.admin_client.delete_router,
                        router['router']['id'])
        router = self.admin_client.list_l3_agents_hosting_router(router_id)
        values = router['agents']
        username = CONF.VCENTER.host_username
        ctrl_ip_address1 = CONF.VCENTER.deployer_ip_1
        ctrl_ip_address2 = CONF.VCENTER.deployer_ip_2
        ctrl_ip_address3 = CONF.VCENTER.deployer_ip_3
        HOST1 = username + "@" + ctrl_ip_address1
        HOST2 = username + "@" + ctrl_ip_address2
        HOST3 = username + "@" + ctrl_ip_address3
        device_owner = "network:router_ha_interface"
        self.router_list = self._to_find_number_of_l3_agenst_per_routers(HOST1)
        if self.router_list == 3:
            port_body = self.admin_client.list_ports(device_id=router_id,
                                                     device_owner=device_owner)
            first_id = port_body['ports'][0]['id']
            second_id = port_body['ports'][1]['id']
            third_id = port_body['ports'][2]['id']
            total = [first_id, second_id, third_id]

            self.value1 = self._connect_to_host(HOST1,
                                                total,
                                                router_id)
            self.value2 = self._connect_to_host(HOST2,
                                                total,
                                                router_id)
            self.value3 = self._connect_to_host(HOST3,
                                                total,
                                                router_id)
            content = [self.value1, self.value2, self.value3]
            count = 0
            for item in content:
                if item == []:
                    count = count + 1

                if count > 0:
                    msg = "one of the controller is not having a HA link"
                    raise Exception(msg)
        if self.router_list == 2:
            port_body = self.admin_client.list_ports(device_id=router_id,
                                                     device_owner=device_owner)
            first_id = port_body['ports'][0]['id']
            second_id = port_body['ports'][1]['id']
            total = [first_id, second_id]

            self.value1 = self._connect_to_host(HOST1,
                                                total,
                                                router_id)
            self.value2 = self._connect_to_host(HOST2,
                                                total,
                                                router_id)
            self.value3 = self._connect_to_host(HOST3,
                                                total,
                                                router_id)
            content = [self.value1, self.value2, self.value3]
            count = 0
            for item in content:
                if item == []:
                    count = count + 1

                if count > 1:
                    msg = "more than one controller not having HA link"
                    raise Exception(msg)
        count = 0
        count1 = 0
        for x in values:
            if x['ha_state'] == 'active':
                active_host_name = str(x['host'])
                count = count + 1
            else:
                count1 = count1 + 1

        self.value1 = self._connect_to_host_to_get_hostname(HOST1,
                                                            ctrl_ip_address1)
        self.value2 = self._connect_to_host_to_get_hostname(HOST2,
                                                            ctrl_ip_address2)
        self.value3 = self._connect_to_host_to_get_hostname(HOST3,
                                                            ctrl_ip_address3)

        def _connect_to_host_to_make_ha_link_down(self, HOST, ha_link, router_id):
            cmd1 = ('sudo ip netns exec qrouter-' + router_id)
            cmd2 = (' ip link set ' + ha_link + ' down')
            cmd = cmd1 + cmd2
            subprocess.Popen(["ssh", "%s" % HOST, cmd],
                             shell=False,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        def _connect_to_host_to_make_ha_link_up(self, HOST, ha_link, router_id):
            cmd1 = ('sudo ip netns exec qrouter-' + router_id)
            cmd2 = (' ip link set ' + ha_link + ' up')
            cmd = cmd1 + cmd2
            subprocess.Popen(["ssh", "%s" % HOST, cmd],
                             shell=False,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        if self.value1 == active_host_name and count == 1:
            ha_variable, host1_ha_link = self._get_ha_link_from_namespace(
                HOST1, router_id)
            self._connect_to_host_to_make_ha_link_down(HOST1,
                                                       host1_ha_link,
                                                       router_id)
            ha_variable1, ha_link = self._get_ha_link_from_namespace(HOST1,
                                                                     router_id)
            router = self.admin_client.list_l3_agents_hosting_router(
                router_id)
            check_values = router['agents']
            for r in check_values:
                if (r['ha_state'] == 'standby' and r['host'] == self.value1 and
                        ha_variable1 != 'ha'):
                    self._connect_to_host_to_make_ha_link_up(HOST1,
                                                             host1_ha_link,
                                                             router_id)
                    latest_value, ha_link = self._get_ha_link_from_namespace(
                        HOST2, router_id)
                    if (r['ha_state'] == 'standby' and
                            latest_value == 'ha'):
                        break

        elif self.value2 == active_host_name and count == 1:
            ha_variable, host2_ha_link = self._get_ha_link_from_namespace(
                HOST2, router_id)
            self._connect_to_host_to_make_ha_link_down(HOST2,
                                                       host2_ha_link,
                                                       router_id)
            ha_variable1, ha_link = self._get_ha_link_from_namespace(HOST2,
                                                                     router_id)
            router = self.admin_client.list_l3_agents_hosting_router(
                router_id)
            check_values = router['agents']
            for r in check_values:
                if (r['ha_state'] == 'standby' and r['host'] == self.value2 and
                        ha_variable1 != 'ha'):
                    self._connect_to_host_to_make_ha_link_up(HOST2,
                                                             host2_ha_link,
                                                             router_id)
                    latest_value, ha_link = self._get_ha_link_from_namespace(
                        HOST2, router_id)
                    if (r['ha_state'] == 'standby' and
                            latest_value == 'ha'):
                        break

        elif self.value3 == active_host_name and count == 1:
            ha_variable, host3_ha_link = self._get_ha_link_from_namespace(
                HOST3, router_id)
            self._connect_to_host_to_make_ha_link_down(HOST3,
                                                       host3_ha_link,
                                                       router_id)
            ha_variable1, ha_link = self._get_ha_link_from_namespace(HOST3,
                                                                     router_id)
            router = self.admin_client.list_l3_agents_hosting_router(
                router_id)
            check_values = router['agents']
            for r in check_values:
                if (r['ha_state'] == 'standby' and r['host'] == self.value3 and
                        ha_variable1 != 'ha'):
                    self._connect_to_host_to_make_ha_link_up(HOST3,
                                                             host3_ha_link,
                                                             router_id)
                    latest_value, ha_link = self._get_ha_link_from_namespace(
                        HOST2, router_id)
                    if (r['ha_state'] == 'standby' and
                            latest_value == 'ha'):
                        break

        else:
            raise Exception("HA state of a contoller is not standby state")
