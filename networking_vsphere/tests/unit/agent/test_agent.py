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

import contextlib
import os

import eventlet
from eventlet import timeout
import fixtures
import mock
from oslo.config import cfg

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

    def test_start(self):
        with mock.patch.object(self.agent, "_monitor_conf_updates"):
            self.agent.start()
            self.assertTrue(self.agent.state == constants.AGENT_INITIALIZING)
            self.assertIsNone(self.agent.net_mgr)

    def test_stop_none_netmgr(self):
        self.agent.stop()
        self.assertIsNone(self.agent.net_mgr)
        self.assertTrue(self.agent.state == constants.AGENT_STOPPED)

    def test_stop_netmgr(self):
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.agent.net_mgr = fake_net_mgr
        self.agent.stop()
        self.assertTrue(self.agent.net_mgr)
        self.assertTrue("stop" in fake_net_mgr.methods)

    def _setup_conf(self, conf_suffix, conf_name):
        conf_key = "agent_test_arg_%s" % conf_suffix
        conf_val_file = "agent_test_val_%s" % conf_suffix
        conf_val_def = "agent_test_val_def_%s" % conf_suffix
        conf_dir = self.useFixture(fixtures.TempDir())
        conf_file = os.path.join(conf_dir.path, conf_name)
        with open(conf_file, 'w') as fd:
            fd.write("[DEFAULT]\n%s=%s" % (conf_key, conf_val_file))
        CONF.config_file = [conf_file]
        test_opts = [cfg.
                     StrOpt(conf_key,
                            help=_("Test CONF item"),
                            default=(conf_val_def))]
        CONF.register_opts(test_opts)
        return conf_file, conf_key, conf_val_def, conf_val_file

    def test_monitor_conf_updates_nochange(self):
        conf_file, conf_key, conf_val_def, _conf_val_file = self._setup_conf(
            1, "test_monitor_conf_updates_nochange.conf")
        old_timestamp = os.stat(conf_file).st_mtime
        with mock.patch.object(self.agent, "_get_last_modified_time",
                               return_value=old_timestamp):
            self.agent.state = constants.AGENT_RUNNING
            with timeout.Timeout(1, False):
                self.thread = eventlet.spawn(self.agent._monitor_conf_updates)
                self.thread.wait()
            self.assertTrue(getattr(CONF, conf_key) == conf_val_def)
            self.assertTrue(self.agent.state == constants.AGENT_RUNNING)
            self.agent.stop()

    def test_monitor_conf_updates_excp(self):
        conf_file, conf_key, conf_val_def, conf_val_file = self._setup_conf(
            2, "test_monitor_conf_updates_excp.conf")
        self.agent.state = constants.AGENT_RUNNING
        with contextlib.nested(
            mock.patch.object(self.agent, "_get_last_modified_time",
                              side_effect=OSError()),
            mock.patch.object(self.LOG, 'error')
        ) as (get_time, log_error):
            raised = self.assertRaises(OSError,
                                       self.agent._get_last_modified_time,
                                       conf_file)
            self.assertTrue(raised)
            with timeout.Timeout(1, False):
                self.thread = eventlet.spawn(self.agent._monitor_conf_updates)
                self.thread.wait()
            self.assertTrue(getattr(CONF, conf_key) == conf_val_def)
            self.assertTrue(log_error.called)
            self.assertTrue(self.agent.state == constants.AGENT_RUNNING)
            self.agent.stop()

    def test_monitor_conf_updates_stop(self):
        conf_file, conf_key, conf_val_def, conf_val_file = self._setup_conf(
            3, "test_monitor_conf_updates_stop.conf")
        self.agent.state = constants.AGENT_STOPPED
        with contextlib.nested(
            mock.patch.object(self.LOG, 'info'),
            mock.patch.object(self.LOG, 'debug'),
            mock.patch.object(self.LOG, 'error')
        ) as (log_info, log_debug, log_error):
            self.agent._monitor_conf_updates
            self.assertTrue(getattr(CONF, conf_key) == conf_val_def)
            self.assertFalse(log_info.called)
            self.assertFalse(log_debug.called)
            self.assertFalse(log_error.called)
            self.assertTrue(self.agent.state == constants.AGENT_STOPPED)

    def test_handle_conf_updates_node_down(self):
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.agent.net_mgr = fake_net_mgr
        self.agent._handle_conf_updates()
        self.assertTrue("handle_conf_update" not in fake_net_mgr.methods)
        self.assertTrue(self.agent.state == constants.AGENT_INITIALIZING)

    def test_handle_conf_updates(self):
        self.agent.node_up = True
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.agent.net_mgr = fake_net_mgr
        self.agent._handle_conf_updates()
        self.assertTrue("handle_conf_update" in fake_net_mgr.methods)
        self.assertTrue("start" in fake_net_mgr.methods)
        self.assertTrue(self.agent.state == constants.AGENT_RUNNING)

    def test_handle_conf_updates_no_netmgr(self):
        self.agent.node_up = True
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.agent._handle_conf_updates()
        self.assertTrue("handle_conf_update" not in fake_net_mgr.methods)
        self.assertTrue("start" not in fake_net_mgr.methods)
        self.assertTrue(self.agent.state == constants.AGENT_RUNNING)

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

    def test_set_node_state_up(self):
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.assertIsNone(fake_net_mgr.get_driver())
        with contextlib.nested(
            mock.patch.object(utils, "load_object",
                              return_value=fake_net_mgr),
            mock.patch.object(self.LOG, 'info')
        ) as (load_obj, log_info):
            self.agent.set_node_state(True)
            self.assertTrue(log_info.called)
            self.assertTrue(fake_net_mgr.get_driver())
            self.assertTrue("start" in fake_net_mgr.methods)
            self.assertTrue(self.agent.state == constants.AGENT_RUNNING)

    def test_set_node_state_down(self):
        self.agent.node_up = True
        fake_net_mgr = fake_manager.MockNetworkManager(self.agent)
        self.agent.net_mgr = fake_net_mgr
        self.agent.set_node_state(False)
        self.assertTrue("stop" in fake_net_mgr.methods)
        self.assertTrue(self.agent.state == constants.AGENT_INITIALIZING)
