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

import jsonutils
import subprocess

from networking_vsphere.tests.scenario import manager

from oslo_config import cfg


CONF = cfg.CONF


class OVSVAPPTestJSON(manager.ESXNetworksTestJSON):

    def test_datapath_status_after_ovsvapp_agent_restart(self):
        vapp_username = CONF.VCENTER.vapp_username
        agent_list = self.admin_client.list_agents(agent_type='OVSvApp Agent',
                                                   alive="True")
        ovsvapp_ip = agent_list['agents'][0]['configurations']['monitoring_ip']
        cmd = ('ps -ef | grep ovsvapp-agent | grep neutron.conf')
        HOST = vapp_username + "@" + ovsvapp_ip
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
        cmd = ('ps -ef | grep neutron-ovsvapp-agent | grep neutron.conf')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        self.assertEqual([], output)
        cmd1 = ('python  /usr/local/bin/neutron-ovsvapp-agent --config-file')
        cmd2 = (' /etc/neutron/neutron.conf --config-file')
        cmd3 = (' /etc/neutron/plugins/ml2/ovsvapp_agent.ini >')
        cmd4 = (' /dev/null 2>&1 &')
        complete_cmd = cmd1 + cmd2 + cmd3 + cmd4
        ssh = subprocess.Popen(["ssh", "%s" % HOST, complete_cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        cmd = ('ps -ef | grep neutron-ovsvapp-agent | grep neutron.conf')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        self.assertGreaterEqual(len(output), 1)
        path = '/opt/stack/logs/status.json'
        ssh2 = subprocess.Popen(['ssh', "%s" % HOST, 'cat', path],
                                stdout=subprocess.PIPE)
        output = ssh2.stdout.readlines()
        output_loads = jsonutils.loads(output[0])
        output_dumps = jsonutils.dumps(output_loads['ovs'])
        quote = output_dumps[1:-1]
        self.assertEqual(quote, 'OK')
        ovsvapp_ip = agent_list['agents'][1]['configurations']['monitoring_ip']
        cmd = ('ps -ef | grep neutron-ovsvapp-agent | grep neutron.conf')
        HOST = vapp_username + "@" + ovsvapp_ip
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
        cmd = ('ps -ef | grep neutron-ovsvapp-agent | grep neutron.conf')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        self.assertEqual([], output)
        cmd1 = ('python  /usr/local/bin/neutron-ovsvapp-agent --config-file')
        cmd2 = (' /etc/neutron/neutron.conf --config-file')
        cmd3 = (' /etc/neutron/plugins/ml2/ovsvapp_agent.ini >')
        cmd4 = (' /dev/null 2>&1 &')
        complete_cmd = cmd1 + cmd2 + cmd3 + cmd4
        ssh = subprocess.Popen(["ssh", "%s" % HOST, complete_cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        cmd = ('ps -ef | grep neutron-ovsvapp-agent | grep neutron.conf')
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        self.assertGreaterEqual(len(output), 1)
        path = '/opt/stack/logs/status.json'
        ssh2 = subprocess.Popen(['ssh', "%s" % HOST, 'cat', path],
                                stdout=subprocess.PIPE)
        output = ssh2.stdout.readlines()
        output_loads = jsonutils.loads(output[0])
        output_dumps = jsonutils.dumps(output_loads['ovs'])
        quote = output_dumps[1:-1]
        self.assertEqual(quote, 'OK')
