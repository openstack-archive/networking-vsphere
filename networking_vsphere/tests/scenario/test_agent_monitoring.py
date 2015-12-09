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

import subprocess
import time

from networking_vsphere.tests.scenario import manager

from oslo_config import cfg
from tempest_lib.common.utils import data_utils


CONF = cfg.CONF


class OVSVAPPTestJSON(manager.ESXNetworksTestJSON):

    def _create_custom_security_group(self):
        group_create_body, _ = self._create_security_group()

        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            self.client.create_security_group_rule(
                security_group_id=group_create_body['security_group']['id'],
                protocol=protocol,
                direction='ingress',
                ethertype=self.ethertype
            )
        return group_create_body

    def test_mitigation_process_when_OVS_running(self):
        net_id = self.network['id']
        name = data_utils.rand_name('server-smoke')
        group_create_body = self._create_custom_security_group()
        serverid = self._create_server_with_sec_group(
            name, net_id, group_create_body['security_group']['id'])
        deviceport = self.client.list_ports(device_id=serverid)
        body = self._associate_floating_ips(
            port_id=deviceport['ports'][0]['id'])
        floatingiptoreach = body['floatingip']['floating_ip_address']
        self._check_public_network_connectivity(floatingiptoreach)
        port_list = self.client.list_ports(device_id=serverid)
        port_id = port_list['ports'][0]['id']
        port_show = self.admin_client.show_port(port_id)
        host_name = port_show['port']['binding:host_id']
        agent_list = self.admin_client.list_agents(agent_type='OVSvApp Agent',
                                                   alive="True",
                                                   host=host_name)
        ovavapp_ip = agent_list['agents'][0]['configurations']['monitoring_ip']
        vapp_username = cfg.CONF.VCENTER.vapp_username
        HOST = vapp_username + "@" + ovavapp_ip
        cmd = ('ps -ef | grep neutron-ovsvapp-agent | grep neutron.conf')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        ps = output[0].split()
        pid = ps[1]

        cmd1 = ('kill -9' + ' ' + str(pid))
        subprocess.Popen(["ssh", "%s" % HOST, cmd1],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

        agent_down_time = cfg.CONF.VCENTER.agent_down_time
        time.sleep(int(agent_down_time))
        agent_list = self.admin_client.list_agents(agent_type='OVSvApp Agent',
                                                   alive="False")
        length = len(agent_list['agents'])
        if length != 0:
            ovsvapp_name = agent_list['agents'][0]['host']
            ovs_status = self._get_vm_power_status(ovsvapp_name)
            self.assertEqual(ovs_status, 'poweredOn')
        else:
            raise Exception("Ovsvapp agent is not down")
        agent_list = self.admin_client.list_agents(agent_type='OVSvApp Agent',
                                                   alive="False")
        host_ip = agent_list['agents'][0]['configurations']['esx_host_name']
        host_username = cfg.CONF.VCENTER.host_username
        HOST1 = host_username + "@" + host_ip
        command = "vim-cmd hostsvc/hostsummary | grep inMaintenanceMode"
        prog = subprocess.Popen(["ssh", "%s" % HOST1, command],
                                stdout=subprocess.PIPE)
        host_mode = prog.stdout.readlines()
        if 'false' in host_mode[0]:
            pass
        else:
            raise Exception("Host entered in to maintainance mode")
        self._check_public_network_connectivity(floatingiptoreach)
        cmd = 'python  /usr/local/bin/neutron-ovsvapp-agent --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ovsvapp_agent.ini > /dev/null 2>&1 &'
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
