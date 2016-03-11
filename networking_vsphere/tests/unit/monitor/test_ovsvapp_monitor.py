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

import copy
import datetime
import mock

from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_service import loopingcall
from oslo_utils import timeutils

from neutron.common import constants
from neutron.common import topics
from neutron import context as neutron_context
from neutron.db import agents_db
from neutron import manager
from neutron.tests import base

from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.db import ovsvapp_db
from networking_vsphere.ml2 import ovsvapp_rpc
from networking_vsphere.monitor import ovsvapp_monitor

service_opts = [
    cfg.IntOpt('api_workers',
               help=_('Number of separate API worker processes for service. '
                      'If not specified, the default is equal to the number '
                      'of CPUs available for best performance.')),
]

CONF = cfg.CONF
CONF.register_opts(service_opts)

FAKE_CLUSTER_1 = 'fake_cluster_1'
FAKE_CLUSTER_2 = 'fake_cluster_2'
FAKE_VCENTER = 'fake_vcenter'
FAKE_HOST_1 = 'fake_host_1'
FAKE_HOST_2 = 'fake_host_2'


def make_active_agent(fake_id, fake_agent_type, config=None):
    agent_dict = dict(id=fake_id,
                      agent_type=fake_agent_type,
                      host='localhost_' + str(fake_id),
                      heartbeat_timestamp=timeutils.utcnow(),
                      admin_state_up=True,
                      configurations=config)
    return agent_dict


def make_inactive_agent(fake_id, fake_agent_type, delta, config=None):
    agent_dict = dict(id=fake_id,
                      agent_type=fake_agent_type,
                      host='remotehost_' + str(fake_id),
                      admin_state_up=True,
                      heartbeat_timestamp=(timeutils.utcnow() - datetime.
                                           timedelta(delta)),
                      configurations=config)
    return agent_dict


def make_existing_inactive_agent(fake_id, fake_agent_type, delta, config=None):
    agent_dict = dict(id=fake_id,
                      agent_type=fake_agent_type,
                      host='remotehost_' + str(fake_id),
                      admin_state_up=False,
                      heartbeat_timestamp=(timeutils.utcnow() - datetime.
                                           timedelta(delta)),
                      configurations=config)
    return agent_dict


class FakePlugin(agents_db.AgentDbMixin):

    def get_agents(self, context, filters=None):
        return


class FakeResponse(object):

    def __init__(self, response):
        self.response = response

    def json(self):
        return jsonutils.loads(self.response)


class TestAgentMonitor(base.BaseTestCase):

    fake_active_agent_list = []
    fake_inactive_agent_list = []
    fake_other_agent_list = []
    fake_active_agent_ids = []
    fake_inactive_agent_ids = []

    def setUp(self):
        super(TestAgentMonitor, self).setUp()
        cfg.CONF.set_default('agent_down_time', 10)
        cfg.CONF.set_override('core_plugin',
                              "neutron.plugins.ml2.plugin.Ml2Plugin")
        self.plugin = FakePlugin()
        self.context = neutron_context.get_admin_context()
        self.notifier = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self.ovsvapp_monitor = ovsvapp_monitor.AgentMonitor()
        self.ovsvapp_monitor.context = self.context
        self.ovsvapp_monitor.plugin = self.plugin
        self.ovsvapp_monitor.notifier = self.notifier
        self.ovsvapp_monitor.agent_ext_support = True
        self.LOG = ovsvapp_monitor.LOG

    def _populate_agent_lists(self, config=None):
        self.fake_active_agent_list = []
        self.fake_active_agent_list.append(make_active_agent(
            '1111', ovsvapp_const.AGENT_TYPE_OVSVAPP, config))
        self.fake_active_agent_list.append(make_active_agent(
            '2222', ovsvapp_const.AGENT_TYPE_OVSVAPP, config))
        self.fake_active_agent_list.append(make_active_agent(
            '3333', ovsvapp_const.AGENT_TYPE_OVSVAPP, config))

        self.fake_inactive_agent_list = []
        self.fake_inactive_agent_list.append(make_existing_inactive_agent(
            '4444', ovsvapp_const.AGENT_TYPE_OVSVAPP, 152, config))
        self.fake_inactive_agent_list.append(make_existing_inactive_agent(
            '5555', ovsvapp_const.AGENT_TYPE_OVSVAPP, 155, config))
        self.fake_inactive_agent_list.append(make_inactive_agent(
            '6666', ovsvapp_const.AGENT_TYPE_OVSVAPP, 52, config))
        self.fake_inactive_agent_list.append(make_inactive_agent(
            '8888', ovsvapp_const.AGENT_TYPE_OVSVAPP, 55, config))

        self.fake_other_agent_list = [make_inactive_agent(
            '7777', constants.AGENT_TYPE_OVS, 52)]

        self.fake_active_agent_ids = ['1111', '2222', '3333']
        self.fake_inactive_agent_ids = ['4444', '5555', '6666', '8888']

    def test_initialize_thread(self):
        notifier = self.ovsvapp_monitor.notifier
        with mock.patch.object(loopingcall,
                               'FixedIntervalLoopingCall'
                               ) as call_back_thread, \
                mock.patch.object(self.LOG, 'debug') as logger_debug:
            self.ovsvapp_monitor.initialize_thread(notifier)
            self.assertTrue(call_back_thread.called)
            self.assertTrue(logger_debug.called)

    def test_initialize_thread_exception(self):
        notifier = self.ovsvapp_monitor.notifier
        with mock.patch.object(loopingcall,
                               'FixedIntervalLoopingCall',
                               side_effect=Exception) as call_back_thread, \
                mock.patch.object(self.LOG, 'exception') as logger_exception:
            self.ovsvapp_monitor.initialize_thread(notifier)
            self.assertTrue(call_back_thread.called)
            self.assertTrue(logger_exception.called)

    def test_get_plugin_and_initialize(self):
        with mock.patch.object(neutron_context,
                               'get_admin_context',
                               return_value=self.context
                               ) as get_context, \
                mock.patch.object(manager.NeutronManager,
                                  'get_plugin',
                                  return_value=self.plugin
                                  ) as get_plugin, \
                mock.patch.object(self.ovsvapp_monitor,
                                  '_check_plugin_ext_support'
                                  ) as check_ext, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as logger_call:
            status = self.ovsvapp_monitor.get_plugin_and_initialize()
            self.assertTrue(get_context.called)
            self.assertTrue(get_plugin.called)
            self.assertTrue(check_ext.called)
            self.assertTrue(status)
            self.assertFalse(logger_call.called)

    def test_get_plugin_and_initialize_exception(self):
        with mock.patch.object(neutron_context,
                               'get_admin_context',
                               return_value=self.context
                               ) as get_context, \
                mock.patch.object(manager.NeutronManager,
                                  'get_plugin',
                                  side_effect=Exception
                                  ) as get_plugin, \
                mock.patch.object(self.LOG, 'warning') as logger_call:
            status = self.ovsvapp_monitor.get_plugin_and_initialize()
            self.assertTrue(get_context.called)
            self.assertTrue(get_plugin.called)
            self.assertFalse(status)
            self.assertTrue(logger_call.called)

    def test_get_plugin_and_initialize_no_plugin(self):
        with mock.patch.object(neutron_context,
                               'get_admin_context',
                               return_value=self.context
                               ) as get_context, \
                mock.patch.object(manager.NeutronManager,
                                  'get_plugin',
                                  return_value=None
                                  ) as get_plugin, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as logger_call:
            status = self.ovsvapp_monitor.get_plugin_and_initialize()
            self.assertTrue(get_context.called)
            self.assertTrue(get_plugin.called)
            self.assertFalse(status)
            self.assertFalse(logger_call.called)

    def test_get_eligble_ovsvapp_agent(self):
        config = {'cluster_id': FAKE_CLUSTER_1,
                  'vcenter_id': FAKE_VCENTER}
        self._populate_agent_lists(config)
        fake_all_agent_list = copy.deepcopy(self.fake_inactive_agent_list)
        fake_all_agent_list.extend(self.fake_active_agent_list)
        self.ovsvapp_monitor.active_agents = self.fake_active_agent_ids
        self.ovsvapp_monitor.inactive_agents = self.fake_inactive_agent_ids
        self.ovsvapp_monitor.agents = fake_all_agent_list
        with mock.patch.object(self.plugin,
                               'get_agents',
                               return_value=fake_all_agent_list):
            chosen_agent = self.ovsvapp_monitor._get_eligible_ovsvapp_agent(
                FAKE_CLUSTER_1, FAKE_VCENTER)
        self.assertIsNotNone(chosen_agent)

    def test_get_eligble_ovsvapp_agent_nothing_available(self):
        config = {'cluster_id': FAKE_CLUSTER_1,
                  'vcenter_id': FAKE_VCENTER}
        config1 = {'cluster_id': FAKE_CLUSTER_2,
                   'vcenter_id': FAKE_VCENTER}
        alien_agent = make_inactive_agent('9999',
                                          ovsvapp_const.AGENT_TYPE_OVSVAPP,
                                          52, config1)
        self._populate_agent_lists(config)
        self.fake_inactive_agent_list.append(alien_agent)
        fake_all_agent_list = copy.deepcopy(self.fake_inactive_agent_list)
        fake_all_agent_list.extend(self.fake_active_agent_list)
        self.ovsvapp_monitor.active_agents = self.fake_active_agent_ids
        self.ovsvapp_monitor.inactive_agents = self.fake_inactive_agent_ids
        self.ovsvapp_monitor.agents = fake_all_agent_list
        with mock.patch.object(self.plugin,
                               'get_agents',
                               return_value=fake_all_agent_list):
            chosen_agent = self.ovsvapp_monitor._get_eligible_ovsvapp_agent(
                FAKE_CLUSTER_2, FAKE_VCENTER)
        self.assertIsNone(chosen_agent)

    def test_process_ovsvapp_agent(self):
        dead_agent = {'configurations': {'esx_host_name': FAKE_HOST_1,
                                         'vcenter_id': FAKE_VCENTER,
                                         'cluster_id': FAKE_CLUSTER_1},
                      'host': FAKE_HOST_1,
                      'id': '1234'}
        chosen_agent = {'configurations': {'esx_host_name': FAKE_HOST_2,
                                           'vcenter_id': FAKE_VCENTER,
                                           'cluster_id': FAKE_CLUSTER_2},
                        'host': FAKE_HOST_2,
                        'id': '1111'}
        device_data = {'assigned_agent_host': FAKE_HOST_2,
                       'esx_host_name': FAKE_HOST_1,
                       'ovsvapp_agent': 'ovsvapp-' + FAKE_HOST_1,
                       }
        self.ovsvapp_monitor.active_agents = ['1111']
        with mock.patch.object(self.ovsvapp_monitor,
                               '_get_eligible_ovsvapp_agent',
                               return_value=chosen_agent
                               ) as get_eligible_agent, \
                mock.patch.object(self.ovsvapp_monitor.notifier,
                                  'device_update'
                                  ) as device_update, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as exception_log, \
                mock.patch.object(self.LOG, 'info') as info_log:
            self.ovsvapp_monitor.process_ovsvapp_agent(dead_agent)
            self.assertTrue(get_eligible_agent.called)
            self.assertFalse(exception_log.called)
            self.assertEqual(info_log.call_count, 2)
            self.assertEqual(len(self.ovsvapp_monitor.active_agents), 1)
            device_update.assert_called_with(self.context, device_data,
                                             FAKE_CLUSTER_2)

    def test_process_ovsvapp_agent_no_eligible_agents(self):
        dead_agent = {'configurations': {'esx_host_name': FAKE_HOST_1,
                                         'vcenter_id': FAKE_VCENTER,
                                         'cluster_id': FAKE_CLUSTER_1},
                      'host': FAKE_HOST_1,
                      'id': '1234'}
        with mock.patch.object(self.ovsvapp_monitor,
                               '_get_eligible_ovsvapp_agent',
                               return_value=None
                               ) as get_eligible_agent,\
                mock.patch.object(ovsvapp_db,
                                  'set_cluster_threshold'
                                  ) as set_threshold, \
                mock.patch.object(self.ovsvapp_monitor.notifier,
                                  'device_update'
                                  ) as device_update, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as exception_log, \
                mock.patch.object(self.LOG, 'info') as info_log, \
                mock.patch.object(self.ovsvapp_monitor,
                                  '_update_agent_admin_state'
                                  ) as update_db:
            self.ovsvapp_monitor.process_ovsvapp_agent(dead_agent)
            self.assertTrue(get_eligible_agent.called)
            set_threshold.assert_called_with(FAKE_VCENTER,
                                             FAKE_CLUSTER_1)
            self.assertFalse(exception_log.called)
            self.assertEqual(info_log.call_count, 2)
            self.assertFalse(device_update.called)
            self.assertTrue(update_db.called)

    def test_process_ovsvapp_agent_exception(self):
        dead_agent = {'configurations': {'esx_host_name': FAKE_HOST_1,
                                         'vcenter_id': FAKE_VCENTER,
                                         'cluster_id': FAKE_CLUSTER_1},
                      'host': FAKE_HOST_1,
                      'id': '1234'}
        with mock.patch.object(self.ovsvapp_monitor,
                               '_get_eligible_ovsvapp_agent',
                               side_effect=Exception)as get_eligible_agent,\
                mock.patch.object(ovsvapp_db,
                                  'set_cluster_threshold'
                                  ) as set_threshold, \
                mock.patch.object(self.ovsvapp_monitor.notifier,
                                  'device_update'
                                  ) as device_update, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as exception_log, \
                mock.patch.object(self.LOG, 'info') as info_log:
            self.ovsvapp_monitor.process_ovsvapp_agent(dead_agent)
            self.assertTrue(get_eligible_agent.called)
            set_threshold.assert_called_with(FAKE_VCENTER,
                                             FAKE_CLUSTER_1)
            self.assertTrue(exception_log.called)
            self.assertEqual(info_log.call_count, 1)
            self.assertFalse(device_update.called)

    def test_check_datapath_health_ok(self):
        monitoring_ip = "1.1.1.1"
        url = 'http://1.1.1.1:8080/status.json'
        response = FakeResponse(jsonutils.dumps({"ovs": "OK"}))
        with mock.patch('requests.get', return_value=response) as http_call:
            ret = self.ovsvapp_monitor._check_datapath_health(monitoring_ip)
            self.assertTrue(http_call.called)
            http_call.assert_called_with(url, timeout=5)
            self.assertTrue(ret)

    def test_check_datapath_health_exception(self):
        monitoring_ip = "1.1.1.1"
        url = 'http://1.1.1.1:8080/status.json'
        with mock.patch('requests.get', side_effect=Exception) as http_call:
            ret = self.ovsvapp_monitor._check_datapath_health(monitoring_ip)
            self.assertTrue(http_call.called)
            http_call.assert_called_with(url, timeout=5)
            self.assertFalse(ret)

    def test_check_datapath_health_without_monitoring_ip(self):
        monitoring_ip = None
        ret = self.ovsvapp_monitor._check_datapath_health(monitoring_ip)
        self.assertIsNone(ret)

    def test_monitor_agent_state(self):
        config = {'cluster_id': FAKE_CLUSTER_1, 'vcenter_id': FAKE_VCENTER}
        self._populate_agent_lists(config)
        fake_all_agent_list = copy.deepcopy(self.fake_inactive_agent_list)
        fake_all_agent_list.extend(self.fake_active_agent_list)
        self.ovsvapp_monitor.active_agents = self.fake_active_agent_ids
        self.ovsvapp_monitor.inactive_agents = []
        with mock.patch.object(self.ovsvapp_monitor,
                               '_update_agent_admin_state'
                               ) as update_agent_call, \
                mock.patch.object(self.ovsvapp_monitor.threadpool,
                                  'spawn_n'
                                  ) as spawn_thread_call, \
                mock.patch.object(ovsvapp_db,
                                  'reset_cluster_threshold'), \
                mock.patch.object(ovsvapp_db,
                                  'update_and_get_cluster_lock',
                                  return_value='1') as get_cluster_lock, \
                mock.patch.object(self.plugin, 'get_agents',
                                  return_value=fake_all_agent_list
                                  ) as get_agent_list:
            self.ovsvapp_monitor.monitor_agent_state()
            status = {'agent': {'admin_state_up': False}}
            agent_id = self.fake_inactive_agent_ids[3]
            self.assertTrue(get_agent_list.called)
            self.assertEqual(update_agent_call.call_count, 2)
            spawn_thread_call.assert_called_with(
                self.ovsvapp_monitor.process_ovsvapp_agent,
                self.fake_inactive_agent_list[3])
            self.assertTrue(get_cluster_lock.called)
            self.assertEqual(len(self.ovsvapp_monitor.active_agents),
                             len(self.fake_active_agent_ids))
            self.assertEqual(len(self.ovsvapp_monitor.inactive_agents),
                             len(self.fake_inactive_agent_ids))
            update_agent_call.assert_called_with(self.context,
                                                 agent_id, status)

    def test_monitor_agent_state_nothing_new_to_process(self):
        config = {'cluster_id': FAKE_CLUSTER_1, 'vcenter_id': FAKE_VCENTER}
        self._populate_agent_lists(config)
        fake_all_agent_list = copy.deepcopy(self.fake_inactive_agent_list[:2])
        fake_all_agent_list.extend(self.fake_active_agent_list)
        self.ovsvapp_monitor.active_agents = self.fake_active_agent_ids
        self.ovsvapp_monitor.inactive_agents = self.fake_inactive_agent_ids[:2]
        with mock.patch.object(self.ovsvapp_monitor,
                               '_update_agent_admin_state'
                               ) as update_agent_call, \
                mock.patch.object(self.ovsvapp_monitor,
                                  'process_ovsvapp_agent'
                                  ) as process_ovsvapp, \
                mock.patch.object(self.plugin,
                                  'get_agents',
                                  return_value=fake_all_agent_list
                                  ) as get_agent_list:
            self.ovsvapp_monitor.monitor_agent_state()
            self.assertTrue(get_agent_list.called)
            self.assertEqual(len(self.ovsvapp_monitor.active_agents),
                             len(self.fake_active_agent_ids))
            self.assertEqual(len(self.ovsvapp_monitor.inactive_agents),
                             len(self.fake_inactive_agent_ids[:2]))
            self.assertFalse(update_agent_call.called)
            self.assertFalse(process_ovsvapp.called)

    def test_monitor_agent_state_exception_in_update(self):
        config = {'cluster_id': FAKE_CLUSTER_1, 'vcenter_id': FAKE_VCENTER}
        self._populate_agent_lists(config)
        fake_all_agent_list = copy.deepcopy(self.fake_inactive_agent_list)
        fake_all_agent_list.extend(self.fake_active_agent_list)
        self.ovsvapp_monitor.active_agents = self.fake_active_agent_ids
        self.ovsvapp_monitor.inactive_agents = []
        with mock.patch.object(self.ovsvapp_monitor,
                               '_update_agent_admin_state',
                               side_effect=Exception
                               ) as update_agent_call, \
                mock.patch.object(self.ovsvapp_monitor,
                                  'process_ovsvapp_agent'
                                  ) as process_ovsvapp, \
                mock.patch.object(self.plugin,
                                  'get_agents',
                                  return_value=fake_all_agent_list
                                  ) as get_agent_list, \
                mock.patch.object(self.LOG, 'exception') as exception_log:
            self.ovsvapp_monitor.monitor_agent_state()
            self.assertTrue(get_agent_list.called)
            self.assertEqual(update_agent_call.call_count, 2)
            self.assertTrue(exception_log.called)
            self.assertFalse(process_ovsvapp.called)

    def test_monitor_agent_state_agent_active_to_inactive(self):
        config = {'cluster_id': FAKE_CLUSTER_1, 'vcenter_id': FAKE_VCENTER}
        self._populate_agent_lists(config)
        fake_all_agent_list = copy.deepcopy(self.fake_inactive_agent_list)
        fake_all_agent_list.extend(self.fake_active_agent_list)
        self.ovsvapp_monitor.active_agents = self.fake_active_agent_ids
        self.ovsvapp_monitor.active_agents += self.fake_inactive_agent_ids
        self.ovsvapp_monitor.inactive_agents = []
        with mock.patch.object(self.ovsvapp_monitor,
                               '_update_agent_admin_state'
                               ) as update_agent_call, \
                mock.patch.object(self.ovsvapp_monitor.threadpool,
                                  'spawn_n'
                                  ) as spawn_thread_call, \
                mock.patch.object(ovsvapp_db,
                                  'reset_cluster_threshold'
                                  ) as reset_threshold, \
                mock.patch.object(ovsvapp_db,
                                  'update_and_get_cluster_lock',
                                  return_value='1') as get_cluster_lock, \
                mock.patch.object(self.plugin, 'get_agents',
                                  return_value=fake_all_agent_list
                                  ) as get_agent_list:
            self.ovsvapp_monitor.monitor_agent_state()
            status = {'agent': {'admin_state_up': False}}
            agent_id = self.fake_inactive_agent_ids[3]
            self.assertTrue(get_agent_list.called)
            a_count = len(self.fake_inactive_agent_ids[2:])
            self.assertEqual(update_agent_call.call_count, a_count)
            self.assertEqual(len(self.ovsvapp_monitor.active_agents),
                             len(self.fake_active_agent_ids))
            self.assertEqual(len(self.ovsvapp_monitor.inactive_agents),
                             len(self.fake_inactive_agent_ids))
            update_agent_call.assert_called_with(self.context,
                                                 agent_id, status)
            self.assertTrue(spawn_thread_call.called)
            self.assertEqual(spawn_thread_call.call_count, a_count)
            self.assertFalse(reset_threshold.called)
            self.assertTrue(get_cluster_lock.called)

    def test_monitor_agent_agent_active_to_inactive_cluster_locked(self):
        config = {'cluster_id': FAKE_CLUSTER_1, 'vcenter_id': FAKE_VCENTER}
        self._populate_agent_lists(config)
        fake_all_agent_list = copy.deepcopy(self.fake_inactive_agent_list)
        fake_all_agent_list.extend(self.fake_active_agent_list)
        self.ovsvapp_monitor.active_agents = self.fake_active_agent_ids
        self.ovsvapp_monitor.active_agents += self.fake_inactive_agent_ids
        self.ovsvapp_monitor.inactive_agents = []
        with mock.patch.object(self.ovsvapp_monitor,
                               '_update_agent_admin_state'), \
                mock.patch.object(self.ovsvapp_monitor,
                                  'process_ovsvapp_agent'
                                  ) as process_ovsvapp, \
                mock.patch.object(ovsvapp_db,
                                  'reset_cluster_threshold'
                                  ) as reset_threshold, \
                mock.patch.object(ovsvapp_db,
                                  'update_and_get_cluster_lock',
                                  return_value='0') as get_cluster_lock, \
                mock.patch.object(self.plugin, 'get_agents',
                                  return_value=fake_all_agent_list
                                  ) as get_agent_list:
            self.ovsvapp_monitor.monitor_agent_state()
            self.assertTrue(get_agent_list.called)
            self.assertEqual(0, process_ovsvapp.call_count)
            self.assertEqual(2, len(self.ovsvapp_monitor.inactive_agents))
            self.assertFalse(reset_threshold.called)
            self.assertTrue(get_cluster_lock.called)

    def test_monitor_agent_state_agent_inactive_to_active(self):
        config = {'cluster_id': FAKE_CLUSTER_1, 'vcenter_id': FAKE_VCENTER}
        self._populate_agent_lists(config)
        fake_all_agent_list = copy.deepcopy(self.fake_inactive_agent_list[:2])
        fake_all_agent_list.extend(self.fake_active_agent_list)
        self.ovsvapp_monitor.inactive_agents = self.fake_inactive_agent_ids[:2]
        self.ovsvapp_monitor.inactive_agents += self.fake_active_agent_ids
        self.ovsvapp_monitor.active_agents = []
        with mock.patch.object(self.ovsvapp_monitor,
                               '_update_agent_admin_state'
                               ) as update_agent_call, \
                mock.patch.object(self.ovsvapp_monitor,
                                  'process_ovsvapp_agent'
                                  ) as process_ovsvapp, \
                mock.patch.object(ovsvapp_db,
                                  'reset_cluster_threshold'
                                  ) as reset_threshold, \
                mock.patch.object(self.plugin, 'get_agents',
                                  return_value=fake_all_agent_list
                                  ) as get_agent_list:
            self.ovsvapp_monitor.monitor_agent_state()
            status = {'agent': {'admin_state_up': True}}
            agent_id = self.fake_active_agent_ids[2]
            self.assertTrue(get_agent_list.called)
            self.assertEqual(update_agent_call.call_count,
                             len(self.fake_active_agent_ids))
            self.assertEqual(len(self.ovsvapp_monitor.active_agents),
                             len(self.fake_active_agent_ids))
            self.assertEqual(len(self.ovsvapp_monitor.inactive_agents),
                             len(self.fake_inactive_agent_ids[:2]))
            update_agent_call.assert_called_with(self.context,
                                                 agent_id, status)
            self.assertFalse(process_ovsvapp.called)
            self.assertTrue(reset_threshold.called)

    def test_monitor_agent_state_agent_no_plugin(self):
        self.ovsvapp_monitor.plugin = None
        with mock.patch.object(self.ovsvapp_monitor,
                               'get_plugin_and_initialize',
                               return_value=False
                               ) as get_plugin, \
                mock.patch.object(self.LOG, 'warning') as warn_log, \
                mock.patch.object(self.plugin,
                                  'get_agents'
                                  ) as get_agent_list:
            self.ovsvapp_monitor.monitor_agent_state()
            self.assertTrue(get_plugin.called)
            self.assertTrue(warn_log.called)
            self.assertFalse(get_agent_list.called)

    def test_monitor_agent_state_agent_ext_not_supported(self):
        self.ovsvapp_monitor.agent_ext_support = False
        with mock.patch.object(self.LOG, 'warning') as warn_log, \
                mock.patch.object(self.plugin,
                                  'get_agents'
                                  ) as get_agent_list:
            self.ovsvapp_monitor.monitor_agent_state()
            self.assertTrue(warn_log.called)
            self.assertFalse(get_agent_list.called)

    def test_monitor_agent_state_agent_exception_get_agents(self):
        with mock.patch.object(self.LOG, 'debug') as debug_log, \
                mock.patch.object(self.plugin,
                                  'get_agents',
                                  side_effect=Exception
                                  ) as get_agent_list, \
                mock.patch.object(self.LOG, 'exception') as exception_log:
            self.ovsvapp_monitor.monitor_agent_state()
            self.assertFalse(debug_log.called)
            self.assertTrue(get_agent_list.called)
            self.assertTrue(exception_log.called)
