# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
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

import contextlib

import mock

from networking_vsphere.agent import ovsvapp_agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.tests import base


class TestOVSvAppL2Agent(base.TestCase):

    def setUp(self):
        super(TestOVSvAppL2Agent, self).setUp()
        with contextlib.nested(
            mock.patch('neutron.common.config.'
                       'init'),
            mock.patch('neutron.common.config.'
                       'setup_logging'),
            mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                       'RpcPluginApi'),
            mock.patch('neutron.agent.rpc.'
                       'PluginReportStateAPI'),
            mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                       'OVSvAppPluginApi'),
            mock.patch('neutron.context.'
                       'get_admin_context_without_session'),
            mock.patch('neutron.agent.rpc.'
                       'create_consumers')):
            self.agent = ovsvapp_agent.OVSvAppL2Agent()
        self.LOG = ovsvapp_agent.LOG

    def test_report_state(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state") as report_st:
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state)
            self.assertEqual(ovsvapp_const.AGENT_TYPE_OVSVAPP,
                             self.agent.agent_state["agent_type"])

    def test_report_state_fail(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state",
                               side_effect=Exception()) as report_st:
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state)