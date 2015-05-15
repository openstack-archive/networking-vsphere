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

import mock
from oslo_config import cfg

from networking_vsphere.agent import agent
from networking_vsphere.common import constants
from networking_vsphere.common import utils
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.drivers import fake_manager

CONF = cfg.CONF


class TestAgent(base.TestCase):

    def setUp(self):
        super(TestAgent, self).setUp()
        self.agent = agent.Agent()
        self.LOG = agent.LOG

    def test_initialize_managers(self):
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.assertIsNone(fake_net_mgr.get_driver())
        with mock.patch.object(utils, "load_object",
                               return_value=fake_net_mgr):
            self.agent._initialize_managers()
            self.assertTrue(fake_net_mgr.get_driver())
            self.assertTrue(self.agent.state == constants.AGENT_INITIALIZED)

    def test_set_node_state_already_up(self):
        self.agent.node_up = True
        with mock.patch.object(self.LOG, 'info') as log_info:
            self.agent.set_node_state(True)
            self.assertTrue(log_info.called)

    @mock.patch.object(utils, "load_object")
    def test_set_node_state_up(self, mock_load_obj):
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.assertIsNone(fake_net_mgr.get_driver())
        mock_load_obj.return_value = fake_net_mgr
        with mock.patch.object(self.LOG, 'info') as mock_log_info:
            self.agent.set_node_state(True)
            self.assertTrue(mock_log_info.called)
            self.assertTrue(fake_net_mgr.get_driver())
            self.assertTrue("start" in fake_net_mgr.methods)
            self.assertTrue(self.agent.state == constants.AGENT_RUNNING)

    def test_set_node_state_down(self):
        self.agent.node_up = True
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.agent.net_mgr = fake_net_mgr
        self.agent.set_node_state(False)
        self.assertTrue("stop" in fake_net_mgr.methods)
        self.assertTrue(self.agent.state == constants.AGENT_STOPPED)
