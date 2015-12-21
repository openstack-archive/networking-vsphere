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

import jsonutils
import subprocess

from networking_vsphere.tests.scenario import manager

from oslo_config import cfg


CONF = cfg.CONF


class OVSVAPPTestJSON(manager.ESXNetworksTestJSON):

    def test_datapath_status_after_OVS_crash(self):
        vapp_username = CONF.VCENTER.vapp_username
        agent_list = self.admin_client.list_agents(agent_type='OVSvApp Agent',
                                                   alive="True")
        devstack_status = CONF.VCENTER.devstack
        if devstack_status == 'yes':
            for i in range(2):
                config = agent_list['agents'][i]['configurations']
                ovsvapp_ip = config['monitoring_ip']
                HOST = vapp_username + "@" + ovsvapp_ip
                cmd = ('sudo service openvswitch-switch stop')
                subprocess.Popen(["ssh", "%s" % HOST, cmd],
                                 shell=False,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
                command = '/opt/stack/logs/status.json'
                ssh1 = subprocess.Popen(['ssh', "%s" % HOST, 'cat', command],
                                        stdout=subprocess.PIPE)
                output = ssh1.stdout.readlines()
                output_loads = jsonutils.loads(output[0])
                output_dumps = jsonutils.dumps(output_loads['ovs'])
                quote = output_dumps[1:-1]
                self.assertEqual(quote, 'OK')
        else:
            for i in range(2):
                config = agent_list['agents'][i]['configurations']
                ovsvapp_ip = config['monitoring_ip']
                HOST = vapp_username + "@" + ovsvapp_ip
                cmd = ('sudo service openvswitch-switch stop')
                subprocess.Popen(["ssh", "%s" % HOST, cmd],
                                 shell=False,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
                command = '/var/log/neutron/ovsvapp-agent/status.json'
                ssh1 = subprocess.Popen(['ssh', "%s" % HOST, 'cat', command],
                                        stdout=subprocess.PIPE)
                output = ssh1.stdout.readlines()
                output_loads = jsonutils.loads(output[0])
                output_dumps = jsonutils.dumps(output_loads['ovs'])
                quote = output_dumps[1:-1]
                self.assertEqual(quote, 'OK')
