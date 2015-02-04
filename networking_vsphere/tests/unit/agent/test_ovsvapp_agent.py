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

import time

import mock

import contextlib

from oslo.config import cfg

from networking_vsphere.agent import ovsvapp_agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.common import error
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.drivers import fake_manager

from neutron.plugins.common import constants as p_const

VNIC_ADDED = 'VNIC_ADDED'
FAKE_VM = 'fake_vm'
FAKE_HOST_1 = 'fake_host_1'
FAKE_HOST_2 = 'fake_host_2'
FAKE_CLUSTER = 'fake_cluster'
FAKE_PORT_1 = 'fake_port_1'
FAKE_PORT_2 = 'fake_port_2'
MAC_ADDRESS = '01:02:03:04:05:06'


class sampleEvent():
    def __init__(self, type, host, cluster, srcobj):
        self.event_type = type
        self.host_name = host
        self.cluster_id = cluster
        self.src_obj = srcobj


class VM():
    def __init__(self, uuid, vnics):
        self.uuid = uuid
        self.vnics = vnics


class samplePort():
    def __init__(self, port_uuid):
        self.port_uuid = port_uuid


class samplePortUIDMac():
    def __init__(self, port_uuid, mac_address):
        self.port_uuid = port_uuid
        self.mac_address = mac_address


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
                                         self.agent.agent_state,
                                         True)
            self.assertNotIn("start_flag", self.agent.agent_state)
            self.assertFalse(self.agent.use_call)
            self.assertEqual(cfg.CONF.host,
                             self.agent.agent_state["host"])

    def test_report_state_fail(self):
        with contextlib.nested(
            mock.patch.object(self.agent.state_rpc,
                              "report_state",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
        ) as (report_st, log_exception):
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state,
                                         True)
            self.assertTrue(log_exception.called)

    def test_process_event_ignore_event(self):
        vm = VM(FAKE_VM, [])
        event = sampleEvent(VNIC_ADDED, FAKE_HOST_1,
                            FAKE_CLUSTER, vm)
        with contextlib.nested(
            mock.patch.object(self.agent,
                              "_notify_device_added"),
            mock.patch.object(self.agent,
                              "_notify_device_updated"),
            mock.patch.object(self.agent,
                              "_notify_device_deleted"),
            mock.patch.object(self.LOG, 'debug')
        ) as (add_vm, update_vm, del_vm, log_debug):
            self.agent.process_event(event)
            self.assertFalse(add_vm.called)
            self.assertFalse(update_vm.called)
            self.assertFalse(del_vm.called)
            self.assertTrue(log_debug.called)

    def test_process_event_exception(self):
        vm = VM(FAKE_VM, [])
        event = sampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER, vm)
        with contextlib.nested(
            mock.patch.object(self.agent,
                              "_notify_device_added",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'error'),
        ) as (add_vm, log_exception, log_error):
            self.agent.process_event(event)
            self.assertTrue(add_vm.called)
            self.assertTrue(log_error.called)
            self.assertTrue(log_exception.called)

    def test_process_event_vm_create_nonics_non_host_non_cluster(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm = VM(FAKE_VM, [])
        self.agent.cluster_id = FAKE_CLUSTER
        event = sampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent,
                               "_notify_device_added") as device_added:
            self.agent.process_event(event)
            self.assertTrue(device_added.called)

    def test_process_event_vm_create_nonics_non_host(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm = VM(FAKE_VM, [])
        event = sampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent,
                               "_notify_device_added") as device_added:
            self.agent.process_event(event)
            self.assertTrue(device_added.called)

    def test_process_event_vm_create_nics_non_host(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm_port1 = samplePort(FAKE_PORT_1)
        vm_port2 = samplePort(FAKE_PORT_2)
        vm = VM(FAKE_VM, ([vm_port1, vm_port2]))
        event = sampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.process_event(event)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.devices_to_filter)
            self.assertIn(vnic.port_uuid, self.agent.cluster_other_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)

    def test_process_event_vm_create_nics_host(self):
        self.agent.esx_hostname = FAKE_HOST_1
        vm_port1 = samplePort(FAKE_PORT_1)
        vm_port2 = samplePort(FAKE_PORT_2)
        vm = VM(FAKE_VM, ([vm_port1, vm_port2]))
        event = sampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.process_event(event)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.devices_to_filter)
            self.assertIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_other_ports)

    def test_process_event_vm_updated_nonhost(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm_port1 = samplePort(FAKE_PORT_1)
        vm = VM(FAKE_VM, [vm_port1])
        event = sampleEvent(ovsvapp_const.VM_UPDATED,
                            FAKE_HOST_1, FAKE_CLUSTER, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.process_event(event)
        self.assertIn(FAKE_PORT_1, self.agent.cluster_other_ports)

    def _build_port(self):
        port = {'admin_state_up': False,
                'id': FAKE_PORT_1,
                'device': 'fake_device',
                'network_id': 'net_uuid',
                'physical_network': 'physnet1',
                'segmentation_id': '1001',
                'network_type': 'vlan',
                'fixed_ips': [{'subnet_id': 'subnet_uuid',
                               'ip_address': '1.1.1.1'}],
                'device_owner': 'compute:None',
                'security_groups': ['fake_sg'],
                'mac_address': MAC_ADDRESS,
                'device_id': 'fake_device_id',
                }
        return port

    def _build_port_info(self, port):
        return ovsvapp_agent.portInfo(
            port['segmentation_id'],
            port['mac_address'],
            port['security_groups'],
            port['fixed_ips'],
            port['admin_state_up'],
            port['network_id'],
            port['device_id'])

    def test_process_event_vm_delete_hosted_vm(self):
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        ovsvapp_agent.network_port_count['net_uuid'] = 1
        port = self._build_port()
        ovsvapp_agent.ports_dict[port['id']] = self._build_port_info(port)
        del_port = ovsvapp_agent.ports_dict[port['id']]
        vm_port = samplePortUIDMac(FAKE_PORT_1, MAC_ADDRESS)
        vm = VM(FAKE_VM, ([vm_port]))
        event = sampleEvent(ovsvapp_const.VM_DELETED,
                            FAKE_HOST_1, FAKE_CLUSTER, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.process_event(event)
        for vnic in vm.vnics:
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)
        self.assertNotIn(del_port.network_id,
                         ovsvapp_agent.network_port_count.keys())

    def test_process_event_vm_delete_non_hosted_vm(self):
        self.agent.esx_hostname = FAKE_HOST_2
        self.agent.cluster_other_ports.add(FAKE_PORT_1)
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        ovsvapp_agent.network_port_count['net_uuid'] = 1
        port = self._build_port()
        ovsvapp_agent.ports_dict[port['id']] = self._build_port_info(port)
        vm_port = samplePortUIDMac(FAKE_PORT_1, MAC_ADDRESS)
        vm = VM(FAKE_VM, ([vm_port]))
        event = sampleEvent(ovsvapp_const.VM_DELETED,
                            FAKE_HOST_1, FAKE_CLUSTER, vm)
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with contextlib.nested(
            mock.patch.object(self.agent.net_mgr.get_driver(),
                              "post_delete_vm",
                              return_value=True),
            mock.patch.object(self.agent.net_mgr.get_driver(),
                              "delete_network"),
        ) as (post_del_vm, del_net):
            self.agent.process_event(event)
            for vnic in vm.vnics:
                self.assertNotIn(vnic.port_uuid,
                                 self.agent.cluster_other_ports)
            self.assertTrue(post_del_vm.called)
            self.assertFalse(del_net.called)

    def test_notify_device_added_with_hosted_vm(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        cluster_id = FAKE_CLUSTER
        vm = VM(FAKE_VM, [])
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "get_ports_for_device",
                              return_value=True),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, "sleep"),
        ) as (get_ports, log_exception, time_sleep):
            self.agent._notify_device_added(vm, host, cluster_id)
            self.assertTrue(get_ports.called)
            self.assertFalse(time_sleep.called)
            self.assertFalse(log_exception.called)

    def test_notify_device_added_rpc_exception(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        cluster_id = FAKE_CLUSTER
        vm = VM(FAKE_VM, [])
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "get_ports_for_device",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, "sleep"),
        ) as (get_ports, log_exception, time_sleep):
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent._notify_device_added, vm, host, cluster_id)
            self.assertTrue(log_exception.called)
            self.assertTrue(get_ports.called)
            self.assertFalse(time_sleep.called)

    def test_notify_device_added_with_retry(self):
        cluster_id = FAKE_CLUSTER
        vm = VM(FAKE_VM, [])
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "get_ports_for_device",
                              return_value=False),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, "sleep"),
        ) as (get_ports, log_exception, time_sleep):
            self.agent._notify_device_added(vm, host, cluster_id)
            self.assertTrue(get_ports.called)
            self.assertTrue(time_sleep.called)
            self.assertFalse(log_exception.called)

    def test_notify_device_updated_host(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = samplePort(FAKE_PORT_1)
        vm = VM(FAKE_VM, [vm_port1])
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "update_port_binding"),
            mock.patch.object(self.LOG, 'exception'),
        ) as (update_port_binding, log_exception):
            self.agent._notify_device_updated(vm, host)
            self.assertTrue(update_port_binding.called)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertFalse(log_exception.called)

    def test_notify_device_updated_rpc_exception(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = samplePort(FAKE_PORT_1)
        vm = VM(FAKE_VM, [vm_port1])
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "update_port_binding",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
        ) as (update_port_binding, log_exception):
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent._notify_device_updated, vm, host)
            self.assertTrue(update_port_binding.called)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertTrue(log_exception.called)