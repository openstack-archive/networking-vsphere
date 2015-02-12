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
from neutron.agent.common import config
from neutron.agent.linux import ovs_lib

from oslo.config import cfg

from networking_vsphere.agent import ovsvapp_agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.common import error
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.drivers import fake_manager

from neutron.plugins.common import constants as p_const

VNIC_ADDED = 'VNIC_ADDED'
FAKE_DEVICE_ID = 'fake_device_id'
FAKE_VM = 'fake_vm'
FAKE_HOST_1 = 'fake_host_1'
FAKE_HOST_2 = 'fake_host_2'
FAKE_CLUSTER_1 = 'fake_cluster_1'
FAKE_CLUSTER_2 = 'fake_cluster_2'
FAKE_PORT_1 = 'fake_port_1'
FAKE_PORT_2 = 'fake_port_2'
MAC_ADDRESS = '01:02:03:04:05:06'
FAKE_CONTEXT = 'fake_context'
FAKE_SG = {'fake_sg': 'fake_sg_rule'}
FAKE_SG_RULES = {FAKE_DEVICE_ID: ['fake_rule_1',
                                  'fake_rule_2',
                                  'fake_rule_3']
                 }
DEVICE = {'id': FAKE_DEVICE_ID,
          'cluster_id': FAKE_CLUSTER_1,
          'host': FAKE_HOST_1}


class SampleEvent(object):
    def __init__(self, type, host, cluster, srcobj):
        self.event_type = type
        self.host_name = host
        self.cluster_id = cluster
        self.src_obj = srcobj


class VM(object):
    def __init__(self, uuid, vnics):
        self.uuid = uuid
        self.vnics = vnics


class SamplePort(object):
    def __init__(self, port_uuid):
        self.port_uuid = port_uuid


class SamplePortUIDMac(object):
    def __init__(self, port_uuid, mac_address):
        self.port_uuid = port_uuid
        self.mac_address = mac_address


class TestOVSvAppL2Agent(base.TestCase):

    def setUp(self):
        super(TestOVSvAppL2Agent, self).setUp()
        config.register_root_helper(cfg.CONF)
        cfg.CONF.set_override('security_bridge_mapping',
                              "br-fake:fake_if", 'SECURITYGROUP')
        cfg.CONF.set_default(
            'firewall_driver',
            'networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver',
            group='SECURITYGROUP')
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
                       'create_consumers'),
            mock.patch('neutron.plugins.openvswitch.agent.ovs_neutron_agent.'
                       'OVSNeutronAgent.setup_integration_br'),
            mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                       'OVSvAppL2Agent.initialize_physical_bridges'),
            mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                       'OVSvAppL2Agent.setup_security_br'),
            mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                       'OVSvAppL2Agent._init_ovs_flows'),
            mock.patch('networking_vsphere.drivers.'
                       'ovs_firewall.OVSFirewallDriver.'
                       'setup_base_flows'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'create'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'set_secure_mode'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'get_port_ofport',
                       return_value=5)):
            self.agent = ovsvapp_agent.OVSvAppL2Agent()
            self.agent.run_refresh_firewall_loop = False
        self.LOG = ovsvapp_agent.LOG

    def _build_port(self):
        port = {'admin_state_up': True,
                'id': FAKE_PORT_1,
                'device': DEVICE,
                'network_id': 'net_uuid',
                'physical_network': 'physnet1',
                'segmentation_id': '1001',
                'network_type': 'vlan',
                'fixed_ips': [{'subnet_id': 'subnet_uuid',
                               'ip_address': '1.1.1.1'}],
                'device_owner': 'compute:None',
                'security_groups': FAKE_SG,
                'mac_address': MAC_ADDRESS,
                'device_id': FAKE_DEVICE_ID,
                }
        return port

    def test_setup_security_br_none(self):
        cfg.CONF.set_override('security_bridge_mapping',
                              None, 'SECURITYGROUP')
        self.agent.sec_br = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.LOG, 'warn'),
            mock.patch.object(self.agent.sec_br, 'bridge_exists')
        ) as (logger_warn, ovs_bridge):
            self.agent.setup_security_br()
            self.assertTrue(logger_warn.called)
            self.assertFalse(ovs_bridge.called)

    def test_setup_security_br(self):
        cfg.CONF.set_override('security_bridge_mapping',
                              "br-fake:fake_if", 'SECURITYGROUP')
        self.agent.sec_br = mock.Mock()
        self.agent.int_br = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.LOG, 'info'),
            mock.patch.object(ovs_lib, "OVSBridge"),
            mock.patch.object(self.agent.sec_br,
                              "add_patch_port",
                              return_value=5),
            mock.patch.object(self.agent.int_br,
                              "add_patch_port",
                              return_value=6),
        )as (logger_info, ovs_br, sec_add_patch_port, int_add_patch_port):
            self.agent.setup_security_br()
            self.assertTrue(ovs_br.called)
            self.assertTrue(self.agent.sec_br.add_patch_port.called)
            self.assertTrue(logger_info.called)

    def test_recover_security_br_none(self):
        cfg.CONF.set_override('security_bridge_mapping',
                              None, 'SECURITYGROUP')
        self.agent.sec_br = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.LOG, 'warn'),
            mock.patch.object(self.agent.sec_br, 'bridge_exists')
        ) as (logger_warn, ovs_bridge):
            self.agent.recover_security_br()
            self.assertTrue(logger_warn.called)
            self.assertFalse(ovs_bridge.called)

    def test_update_port_bindings(self):
        self.agent.update_port_bindings = [FAKE_PORT_1]
        context = mock.Mock()
        self.agent.context = context
        self.agent.agent_id = "agent-id"
        self.agent.hostname = "esx-hostname"
        with mock.patch.object(self.agent.ovsvapp_rpc, "update_port_binding"
                               ) as mock_update_port_binding:
            self.agent._update_port_bindings()
            self.assertEqual(self.agent.update_port_bindings, [])
            mock_update_port_binding.assert_called_with(
                context, agent_id="agent-id",
                port_id=FAKE_PORT_1,
                host="esx-hostname")

    def test_initialize_physical_bridges(self):
        cfg.CONF.set_override('tenant_network_type',
                              "vlan", 'OVSVAPP')
        cfg.CONF.set_override('bridge_mappings',
                              ["physnet1:br-eth1"], 'OVSVAPP')
        with contextlib.nested(
            mock.patch.object(self.agent, 'setup_physical_bridges'),
            mock.patch.object(self.agent, '_init_ovs_flows')
        ) as (mock_phys_brs, mock_init_ovs_flows):
            self.agent.initialize_physical_bridges()
            mock_phys_brs.assert_called_with({'physnet1': 'br-eth1'})
            mock_init_ovs_flows.assert_called_with({'physnet1': 'br-eth1'})

    def test_initialize_physical_bridges_not_vlan(self):
        cfg.CONF.set_override('tenant_network_type',
                              "vxlan", 'OVSVAPP')
        cfg.CONF.set_override('bridge_mappings',
                              ["physnet1:br-tun"], 'OVSVAPP')
        with contextlib.nested(
            mock.patch.object(self.agent, 'setup_physical_bridges'),
            mock.patch.object(self.agent, '_init_ovs_flows')
        ) as (mock_phys_brs, mock_init_ovs_flows):
            self.agent.initialize_physical_bridges()
            self.assertFalse(mock_phys_brs.called)
            self.assertFalse(mock_init_ovs_flows.called)

    def test_mitigate_ovs_restart_vlan(self):
        self.agent.enable_tunneling = False
        self.agent.refresh_firewall_required = False
        self.agent.devices_to_filter = set(['1111'])
        self.agent.cluster_host_ports = set(['1111'])
        self.agent.cluster_other_ports = set(['2222'])
        with contextlib.nested(
            mock.patch.object(self.LOG, 'info'),
            mock.patch.object(self.agent, "setup_integration_br"),
            mock.patch.object(self.agent, "setup_physical_bridges"),
            mock.patch.object(self.agent, "setup_security_br"),
            mock.patch.object(self.agent.sg_agent, "init_firewall"),
            mock.patch.object(self.agent, "setup_tunnel_br"),
            mock.patch.object(self.agent, "_init_ovs_flows"),
        )as (logger_info, int_br, phys_brs, sec_br, init_fw, tun_br,
             init_flows):
            self.agent.mitigate_ovs_restart()
            self.assertTrue(int_br.called)
            self.assertTrue(phys_brs.called)
            self.assertTrue(sec_br.called)
            self.assertFalse(tun_br.called)
            self.assertTrue(init_fw.called)
            self.assertTrue(init_flows.called)
            self.assertTrue(logger_info.called)
            self.assertTrue(self.agent.refresh_firewall_required)
            self.assertEqual(len(self.agent.devices_to_filter), 2)

    def test_mitigate_ovs_restart_exception(self):
        self.agent.enable_tunneling = False
        self.agent.refresh_firewall_required = False
        self.agent.devices_to_filter = set()
        self.agent.cluster_host_ports = set(['1111'])
        self.agent.cluster_other_ports = set(['2222'])

        with contextlib.nested(
            mock.patch.object(self.LOG, "info"),
            mock.patch.object(self.agent, "setup_integration_br",
                              side_effect=Exception()),
            mock.patch.object(self.agent, "setup_physical_bridges"),
            mock.patch.object(self.agent, "setup_tunnel_br"),
            mock.patch.object(self.LOG, "exception"),
        )as (logger_info, int_br, phys_brs, tun_br, exception_log):
            self.agent.mitigate_ovs_restart()
            self.assertTrue(int_br.called)
            self.assertFalse(phys_brs.called)
            self.assertFalse(tun_br.called)
            self.assertFalse(logger_info.called)
            self.assertTrue(exception_log.called)
            self.assertFalse(self.agent.refresh_firewall_required)
            self.assertEqual(len(self.agent.devices_to_filter), 0)

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
        event = SampleEvent(VNIC_ADDED, FAKE_HOST_1,
                            FAKE_CLUSTER_1, vm)
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
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_1, vm)
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
        self.agent.cluster_id = FAKE_CLUSTER_1
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_1, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent,
                               "_notify_device_added") as device_added:
            self.agent.process_event(event)
            self.assertTrue(device_added.called)

    def test_process_event_vm_create_nonics_non_host(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm = VM(FAKE_VM, [])
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_1, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent,
                               "_notify_device_added") as device_added:
            self.agent.process_event(event)
            self.assertTrue(device_added.called)
            self.assertEqual(FAKE_CLUSTER_1, self.agent.cluster_id)

    def test_process_event_vm_create_nics_non_host(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm_port2 = SamplePort(FAKE_PORT_2)
        vm = VM(FAKE_VM, ([vm_port1, vm_port2]))
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_1, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.process_event(event)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.devices_to_filter)
            self.assertIn(vnic.port_uuid, self.agent.cluster_other_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)

    def test_process_event_vm_create_nics_host(self):
        self.agent.esx_hostname = FAKE_HOST_1
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm_port2 = SamplePort(FAKE_PORT_2)
        vm = VM(FAKE_VM, ([vm_port1, vm_port2]))
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_1, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.process_event(event)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.devices_to_filter)
            self.assertIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_other_ports)

    def test_process_event_vm_updated_nonhost(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm = VM(FAKE_VM, [vm_port1])
        event = SampleEvent(ovsvapp_const.VM_UPDATED,
                            FAKE_HOST_1, FAKE_CLUSTER_1, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.process_event(event)
        self.assertIn(FAKE_PORT_1, self.agent.cluster_other_ports)

    def test_process_event_vm_delete_hosted_vm(self):
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.network_port_count['net_uuid'] = 1
        port = self._build_port()
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        del_port = self.agent.ports_dict[port['id']]
        vm_port = SamplePortUIDMac(FAKE_PORT_1, MAC_ADDRESS)
        vm = VM(FAKE_VM, ([vm_port]))
        event = SampleEvent(ovsvapp_const.VM_DELETED,
                            FAKE_HOST_1, FAKE_CLUSTER_1, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with contextlib.nested(
            mock.patch.object(self.agent.net_mgr.get_driver(),
                              "post_delete_vm",
                              return_value=True),
            mock.patch.object(self.agent.net_mgr.get_driver(),
                              "delete_network"),
        ) as (post_del_vm, del_net):
            self.agent.process_event(event)
            for vnic in vm.vnics:
                self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertTrue(post_del_vm.called)
            self.assertTrue(del_net.called)
            self.assertNotIn(del_port.network_id,
                             self.agent.network_port_count.keys())

    def test_process_event_vm_delete_non_hosted_vm(self):
        self.agent.esx_hostname = FAKE_HOST_2
        self.agent.cluster_other_ports.add(FAKE_PORT_1)
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.network_port_count['net_uuid'] = 1
        port = self._build_port()
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        del_port = self.agent.ports_dict[port['id']]
        vm_port = SamplePortUIDMac(FAKE_PORT_1, MAC_ADDRESS)
        vm = VM(FAKE_VM, ([vm_port]))
        event = SampleEvent(ovsvapp_const.VM_DELETED,
                            FAKE_HOST_1, FAKE_CLUSTER_1, vm)
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
            self.assertNotIn(del_port.network_id,
                             self.agent.network_port_count.keys())

    def test_notify_device_added_with_hosted_vm(self):
        vm = VM(FAKE_VM, [])
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "get_ports_for_device",
                              return_value=True),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, "sleep"),
        ) as (get_ports, log_exception, time_sleep):
            self.agent._notify_device_added(vm, host)
            self.assertTrue(get_ports.called)
            self.assertFalse(time_sleep.called)
            self.assertFalse(log_exception.called)

    def test_notify_device_added_rpc_exception(self):
        vm = VM(FAKE_VM, [])
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
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
                self.agent._notify_device_added, vm, host)
            self.assertTrue(log_exception.called)
            self.assertTrue(get_ports.called)
            self.assertFalse(time_sleep.called)

    def test_notify_device_added_with_retry(self):
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
            self.agent._notify_device_added(vm, host)
            self.assertTrue(get_ports.called)
            self.assertTrue(time_sleep.called)
            self.assertFalse(log_exception.called)

    def test_notify_device_updated_host(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = SamplePort(FAKE_PORT_1)
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
        vm_port1 = SamplePort(FAKE_PORT_1)
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

    def test_map_port_to_common_model_vlan(self):
        exp_port = self._build_port()
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        network, port = self.agent._map_port_to_common_model(exp_port)
        self.assertEqual(exp_port['network_id'], network.name)
        self.assertEqual(exp_port['id'], port.uuid)

    def test_device_create_cluster_mismatch(self):
        self.agent.cluster_id = FAKE_CLUSTER_2
        with contextlib.nested(
            mock.patch.object(self.agent,
                              '_process_create_portgroup_vlan',
                              return_value=True),
            mock.patch.object(self.LOG, 'debug')
        ) as (create_pg_vlan, logger_debug):
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE)
            self.assertTrue(logger_debug.called)
            self.assertFalse(create_pg_vlan.called)

    def test_device_create_non_hosted_vm(self):
        ports = [self._build_port()]
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.esx_hostname = FAKE_HOST_2
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up',
                              return_value=True),
            mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'),
            mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'),
            mock.patch.object(self.LOG, 'debug')
        ) as (update_device_up, mock_add_devices_fn, mock_sg_update_fn,
              logger_debug):
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=FAKE_SG_RULES)
            self.assertTrue(logger_debug.called)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertFalse(mock_sg_update_fn.called)
            self.assertFalse(update_device_up.called)

    def test_device_create_hosted_vm_vlan(self):
        ports = [self._build_port()]
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up',
                              return_value=True),
            mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'),
            mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'),
            mock.patch.object(self.LOG, 'debug')
        ) as (update_device_up, mock_add_devices_fn, mock_sg_update_fn,
              logger_debug):
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=FAKE_SG_RULES)
            self.assertTrue(logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            mock_add_devices_fn.assert_called_with(ports)
            mock_sg_update_fn.assert_called_with(
                FAKE_SG_RULES.get(FAKE_DEVICE_ID))
            self.assertTrue(update_device_up.called)

    def test_device_create_hosted_vm_create_port_exception(self):
        ports = [self._build_port()]
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().create_port = mock.Mock(
            side_effect=Exception())
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up'),
            mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'),
            mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'),
            mock.patch.object(self.LOG, 'debug'),
            mock.patch.object(self.LOG, 'exception'),
        ) as (update_device, mock_add_devices_fn, mock_sg_update_fn,
              logger_debug, log_excep):
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent.device_create,
                FAKE_CONTEXT, device=DEVICE,
                ports=ports, sg_rules=FAKE_SG_RULES)
            self.assertTrue(logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertFalse(update_device.called)
            self.assertFalse(mock_sg_update_fn.called)
            self.assertTrue(log_excep.called)

    def test_device_create_hosted_vm_update_device_exception(self):
        ports = [self._build_port()]
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with contextlib.nested(
            mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'),
            mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'),
            mock.patch.object(self.agent.plugin_rpc, 'update_device_up',
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'debug'),
            mock.patch.object(self.LOG, 'exception'),
        ) as (mock_add_devices_fn, mock_sg_update_fn, update_device,
              logger_debug, log_excep):
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent.device_create,
                FAKE_CONTEXT, device=DEVICE,
                ports=ports, sg_rules=FAKE_SG_RULES)
            self.assertTrue(logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertFalse(mock_sg_update_fn.called)
            self.assertTrue(update_device.called)
            self.assertTrue(log_excep.called)

    def test_port_update_admin_state_up(self):
        port = self._build_port()
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        neutron_port = {'port': port}
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              "update_device_up"),
            mock.patch.object(self.agent.plugin_rpc,
                              "update_device_down"),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'debug')
        ) as (device_up, device_down,
              log_exception, log_debug):
            self.agent.port_update(FAKE_CONTEXT, **neutron_port)
            self.assertEqual(neutron_port['port']['admin_state_up'],
                             self.agent.ports_dict[port['id']].
                             admin_state_up)
            self.assertTrue(device_up.called)
            self.assertFalse(device_down.called)
            self.assertFalse(log_exception.called)

    def test_port_update_rpc_exception(self):
        port = self._build_port()
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        neutron_port = {'port': port}
        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              "update_device_up",
                              side_effect=Exception()),
            mock.patch.object(self.agent.plugin_rpc,
                              "update_device_down"),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'debug')
        ) as (device_up, device_down,
              log_exception, log_debug):
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent.port_update, FAKE_CONTEXT, **neutron_port)
            self.assertEqual(neutron_port['port']['admin_state_up'],
                             self.agent.ports_dict[port['id']].
                             admin_state_up)
            self.assertTrue(device_up.called)
            self.assertFalse(device_down.called)
            self.assertTrue(log_exception.called)
            self.assertTrue(device_up.called)
