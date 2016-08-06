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

import mock

import time

import logging
from oslo_config import cfg

from networking_vsphere.agent import ovsvapp_agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.common import error
from networking_vsphere.tests import base
from networking_vsphere.tests.unit.drivers import fake_manager
from networking_vsphere.utils import resource_util

from neutron.agent.common import ovs_lib
from neutron.common import utils as n_utils
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils as p_utils
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent as ovs_agent  # noqa

NETWORK_ID = 'fake_net_id'
VNIC_ADDED = 'VNIC_ADDED'
FAKE_DEVICE_ID = 'fake_device_id'
FAKE_VM = 'fake_vm'
FAKE_HOST_1 = 'fake_host_1'
FAKE_HOST_2 = 'fake_host_2'
FAKE_CLUSTER_MOID = 'fake_cluster_moid'
FAKE_CLUSTER_1 = 'fake_cluster_1'
FAKE_CLUSTER_2 = 'fake_cluster_2'
FAKE_VCENTER = 'fake_vcenter'
FAKE_PORT_1 = 'fake_port_1'
FAKE_PORT_2 = 'fake_port_2'
FAKE_PORT_3 = 'fake_port_3'
FAKE_PORT_4 = 'fake_port_4'
MAC_ADDRESS = '01:02:03:04:05:06'
FAKE_CONTEXT = 'fake_context'
FAKE_SG = {'fake_sg': 'fake_sg_rule'}

FAKE_SG_RULE = {'security_group_source_groups': ['fake_rule_1',
                                                 'fake_rule_2',
                                                 'fake_rule_3'],
                'security_group_rules': [
                {'ethertype': 'IPv4',
                 'direction': 'egress',
                 'security_group_id': 'fake_id'
                 }],
                'sg_provider_rules': [
                {'ethertype': 'IPv4',
                 'direction': 'egress',
                 'source_port_range_min': 67,
                 'source_port_range_max': 67,
                 'port_range_min': 68,
                 'port_range_max': 68
                 }]
                }

FAKE_SG_RULES = {FAKE_PORT_1: FAKE_SG_RULE}

FAKE_SG_RULES_MULTI_PORTS = {FAKE_PORT_1: FAKE_SG_RULE,
                             FAKE_PORT_2: FAKE_SG_RULE
                             }

FAKE_SG_RULES_MISSING = {FAKE_PORT_1: {'security_group_source_groups': [
                                       'fake_rule_1',
                                       'fake_rule_2',
                                       'fake_rule_3'],
                                       'sg_provider_rules': [],
                                       'security_group_rules': [
                                       {'ethertype': 'IPv4',
                                        'direction': 'egress'
                                        }]
                                       }
                         }

FAKE_SG_RULES_PARTIAL = {FAKE_PORT_1: {'security_group_source_groups': [
                                       'fake_rule_1',
                                       'fake_rule_2',
                                       'fake_rule_3'],
                                       'sg_provider_rules': [],
                                       'security_group_rules': [
                                       {'ethertype': 'IPv4',
                                        'direction': 'egress',
                                        'port_range_min': 22,
                                        'port_range_max': 22
                                        }]
                                       }
                         }


DEVICE = {'id': FAKE_DEVICE_ID,
          'cluster_id': FAKE_CLUSTER_1,
          'host': FAKE_HOST_1,
          'vcenter': FAKE_VCENTER}


class SampleEvent(object):
    def __init__(self, type, host, cluster, srcobj, host_changed=False):
        self.event_type = type
        self.host_name = host
        self.cluster_id = cluster
        self.src_obj = srcobj
        self.host_changed = host_changed


class VM(object):
    def __init__(self, uuid, vnics):
        self.uuid = uuid
        self.vnics = vnics


class SamplePort(object):
    def __init__(self, port_uuid, mac_address=None, pg_id=None):
        self.port_uuid = port_uuid
        self.mac_address = mac_address
        self.pg_id = pg_id


class SamplePortUIDMac(object):
    def __init__(self, port_uuid, mac_address):
        self.port_uuid = port_uuid
        self.mac_address = mac_address


class TestOVSvAppAgentRestart(base.TestCase):

    @mock.patch('neutron.common.config.init')
    @mock.patch('neutron.common.config.setup_logging')
    @mock.patch('neutron.agent.ovsdb.api.'
                'API.get')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.RpcPluginApi')
    @mock.patch('neutron.agent.securitygroups_rpc.SecurityGroupServerRpcApi')
    @mock.patch('neutron.agent.rpc.PluginReportStateAPI')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.OVSvAppPluginApi')
    @mock.patch('neutron.context.get_admin_context_without_session')
    @mock.patch('neutron.agent.rpc.create_consumers')
    @mock.patch('neutron.plugins.ml2.drivers.openvswitch.agent.'
                'ovs_neutron_agent.OVSNeutronAgent.setup_integration_br')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                'OVSvAppAgent.setup_ovs_bridges')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                'OVSvAppAgent.setup_security_br')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                'OVSvAppAgent._init_ovs_flows')
    @mock.patch('networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver.'
                'check_ovs_firewall_restart')
    @mock.patch('networking_vsphere.drivers.ovs_firewall.'
                'OVSFirewallDriver.setup_base_flows')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.create')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.set_secure_mode')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.get_port_ofport')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.OVSvAppAgent.__init__')
    def setUp(self, mock_ovs_init, mock_get_port_ofport,
              mock_set_secure_mode, mock_create_ovs_bridge,
              mock_setup_base_flows, mock_check_ovs_firewall_restart,
              mock_init_ovs_flows, mock_setup_security_br,
              mock_setup_ovs_bridges,
              mock_setup_integration_br, mock_create_consumers,
              mock_get_admin_context_without_session, mock_ovsvapp_pluginapi,
              mock_plugin_report_stateapi, mock_securitygroup_server_rpcapi,
              mock_rpc_pluginapi, mock_ovsdb_api, mock_setup_logging,
              mock_init):
        super(TestOVSvAppAgentRestart, self).setUp()
        cfg.CONF.set_override('security_bridge_mapping',
                              "fake_sec_br:fake_if", 'SECURITYGROUP')
        mock_get_port_ofport.return_value = 5
        mock_ovs_init.return_value = None
        self.agent = ovsvapp_agent.OVSvAppAgent()
        self.agent.run_refresh_firewall_loop = False
        self.LOG = ovsvapp_agent.LOG
        self.agent.monitor_log = logging.getLogger('monitor')

    def test_check_ovsvapp_agent_restart(self):
        self.agent.int_br = mock.Mock()
        with mock.patch.object(self.agent.int_br, 'bridge_exists',
                               return_value=True) as mock_br_exists, \
                mock.patch.object(self.agent.int_br, 'dump_flows_for_table',
                                  return_value='') as mock_dump_flows:
            self.assertFalse(self.agent.check_ovsvapp_agent_restart())
            self.assertTrue(mock_br_exists.called)
            self.assertTrue(mock_dump_flows.called)
            mock_dump_flows.return_value = 'cookie = 0x0'
            self.assertTrue(self.agent.check_ovsvapp_agent_restart())
            self.assertTrue(mock_br_exists.called)
            self.assertTrue(mock_dump_flows.called)


class TestOVSvAppAgent(base.TestCase):

    @mock.patch('neutron.common.config.init')
    @mock.patch('neutron.common.config.setup_logging')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.RpcPluginApi')
    @mock.patch('neutron.agent.securitygroups_rpc.SecurityGroupServerRpcApi')
    @mock.patch('neutron.agent.rpc.PluginReportStateAPI')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.OVSvAppPluginApi')
    @mock.patch('neutron.context.get_admin_context_without_session')
    @mock.patch('neutron.agent.rpc.create_consumers')
    @mock.patch('neutron.plugins.ml2.drivers.openvswitch.agent.'
                'ovs_neutron_agent.OVSNeutronAgent.setup_integration_br')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                'OVSvAppAgent.check_ovsvapp_agent_restart')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                'OVSvAppAgent.setup_ovs_bridges')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                'OVSvAppAgent.setup_security_br')
    @mock.patch('networking_vsphere.agent.ovsvapp_agent.'
                'OVSvAppAgent._init_ovs_flows')
    @mock.patch('networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver.'
                'check_ovs_firewall_restart')
    @mock.patch('networking_vsphere.drivers.ovs_firewall.'
                'OVSFirewallDriver.setup_base_flows')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.create')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.set_secure_mode')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.get_port_ofport')
    def setUp(self, mock_get_port_ofport,
              mock_set_secure_mode, mock_create_ovs_bridge,
              mock_setup_base_flows, mock_check_ovs_firewall_restart,
              mock_init_ovs_flows, mock_setup_security_br,
              mock_setup_ovs_bridges, mock_check_ovsvapp_agent_restart,
              mock_setup_integration_br, mock_create_consumers,
              mock_get_admin_context_without_session, mock_ovsvapp_pluginapi,
              mock_plugin_report_stateapi, mock_securitygroup_server_rpcapi,
              mock_rpc_pluginapi, mock_setup_logging, mock_init):
        super(TestOVSvAppAgent, self).setUp()
        cfg.CONF.set_override('security_bridge_mapping',
                              "fake_sec_br:fake_if", 'SECURITYGROUP')
        mock_check_ovsvapp_agent_restart.return_value = False
        mock_get_port_ofport.return_value = 5
        self.agent = ovsvapp_agent.OVSvAppAgent()
        self.agent.run_refresh_firewall_loop = False
        self.LOG = ovsvapp_agent.LOG
        self.agent.monitor_log = logging.getLogger('monitor')

    def _build_port(self, port):
        port = {'admin_state_up': False,
                'id': port,
                'device': DEVICE,
                'network_id': NETWORK_ID,
                'physical_network': 'physnet1',
                'segmentation_id': '1001',
                'lvid': 1,
                'network_type': 'vlan',
                'fixed_ips': [{'subnet_id': 'subnet_uuid',
                               'ip_address': '1.1.1.1'}],
                'device_owner': 'compute:None',
                'security_groups': FAKE_SG,
                'mac_address': MAC_ADDRESS,
                'device_id': FAKE_DEVICE_ID
                }
        return port

    def _build_update_port(self, port):
        port = {'admin_state_up': False,
                'id': port,
                'network_id': NETWORK_ID,
                'fixed_ips': [{'subnet_id': 'subnet_uuid',
                               'ip_address': '1.1.1.1'}],
                'device_owner': 'compute:None',
                'security_groups': FAKE_SG,
                'mac_address': MAC_ADDRESS,
                'device_id': FAKE_DEVICE_ID
                }
        return port

    def test_setup_security_br_none(self):
        cfg.CONF.set_override('security_bridge_mapping',
                              None, 'SECURITYGROUP')
        self.agent.sec_br = mock.Mock()
        with mock.patch.object(self.LOG, 'warning') as mock_logger_warn,\
                mock.patch.object(self.agent.sec_br, 'bridge_exists'
                                  ) as mock_ovs_bridge:
            self.assertRaises(SystemExit,
                              self.agent.setup_security_br)
            self.assertTrue(mock_logger_warn.called)
            self.assertFalse(mock_ovs_bridge.called)

    def test_setup_security_br(self):
        cfg.CONF.set_override('security_bridge_mapping',
                              "br-fake:fake_if", 'SECURITYGROUP')
        self.agent.sec_br = mock.Mock()
        self.agent.int_br = mock.Mock()
        with mock.patch.object(self.LOG, 'info') as mock_logger_info, \
                mock.patch.object(ovs_lib, "OVSBridge") as mock_ovs_br, \
                mock.patch.object(self.agent.sec_br,
                                  "add_patch_port",
                                  return_value=5), \
                mock.patch.object(self.agent.int_br,
                                  "add_patch_port",
                                  return_value=6):
            self.agent.setup_security_br()
            self.assertTrue(mock_ovs_br.called)
            self.assertTrue(self.agent.sec_br.add_patch_port.called)
            self.assertTrue(mock_logger_info.called)

    def test_recover_security_br_none(self):
        cfg.CONF.set_override('security_bridge_mapping',
                              None, 'SECURITYGROUP')
        self.agent.sec_br = mock.Mock()
        with mock.patch.object(self.LOG, 'warning') as mock_logger_warn, \
                mock.patch.object(self.agent.sec_br, 'bridge_exists'
                                  ) as mock_ovs_bridge:
            self.assertRaises(SystemExit,
                              self.agent.recover_security_br)
            self.assertTrue(mock_logger_warn.called)
            self.assertFalse(mock_ovs_bridge.called)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge')
    def test_recover_security_br(self, mock_ovs_bridge):
        cfg.CONF.set_override('security_bridge_mapping',
                              "br-sec:physnet1", 'SECURITYGROUP')
        self.agent.int_br = mock.Mock()
        self.agent.sec_br = mock.Mock()
        mock_br = mock_ovs_bridge.return_value
        with mock.patch.object(self.LOG, 'info') as mock_logger_info, \
                mock.patch.object(mock_br, 'bridge_exists'), \
                mock.patch.object(mock_br, 'add_patch_port') as mock_add_patch_port, \
                mock.patch.object(self.agent.int_br,
                                  "get_port_ofport",
                                  return_value=6), \
                mock.patch.object(mock_br,
                                  "get_port_ofport",
                                  return_value=6), \
                mock.patch.object(mock_br,
                                  "delete_port") as mock_delete_port:
            mock_br.get_bridge_for_iface.return_value = 'br-sec'
            self.agent.recover_security_br()
            self.assertTrue(mock_logger_info.called)
            self.assertFalse(mock_delete_port.called)
            self.assertFalse(mock_add_patch_port.called)
            mock_br.get_bridge_for_iface.return_value = 'br-fake'
            self.agent.recover_security_br()
            self.assertTrue(mock_logger_info.called)
            self.assertTrue(mock_delete_port.called)
            self.assertTrue(mock_add_patch_port.called)

    @mock.patch('neutron.agent.ovsdb.api.'
                'API.get')
    def test_recover_physical_bridges(self, mock_ovsdb_api):
        cfg.CONF.set_override('bridge_mappings',
                              ["physnet1:br-eth1"], 'OVSVAPP')
        self.agent.bridge_mappings = n_utils.parse_mappings(
            cfg.CONF.OVSVAPP.bridge_mappings)
        with mock.patch.object(self.LOG, 'info') as mock_logger_info, \
                mock.patch.object(self.LOG, 'error') as mock_logger_error, \
                mock.patch.object(self.agent, "br_phys_cls") as mock_ovs_br, \
                mock.patch.object(ovs_lib.BaseOVS,
                                  "get_bridges",
                                  return_value=['br-eth1']
                                  ), \
                mock.patch.object(p_utils, 'get_interface_name'
                                  ) as mock_int_name, \
                mock.patch.object(self.agent.int_br,
                                  "get_port_ofport",
                                  return_value=6) as mock_get_ofport:
            self.agent.recover_physical_bridges(self.agent.bridge_mappings)
            self.assertTrue(mock_logger_info.called)
            self.assertFalse(mock_logger_error.called)
            self.assertTrue(mock_ovs_br.called)
            self.assertTrue(mock_get_ofport.called)
            self.assertTrue(mock_int_name.called)
            self.assertEqual(self.agent.int_ofports['physnet1'], 6)

    def test_init_ovs_flows(self):
        cfg.CONF.set_override('bridge_mappings',
                              ["physnet1:br-eth1"], 'OVSVAPP')
        self.agent.bridge_mappings = n_utils.parse_mappings(
            cfg.CONF.OVSVAPP.bridge_mappings)
        self.agent.patch_sec_ofport = 5
        self.agent.int_ofports = {'physnet1': 'br-eth1'}
        self.agent.phys_ofports = {"physnet1": "br-eth1"}
        port = self._build_port(FAKE_PORT_1)
        br = self._build_phys_brs(port)
        self.agent.br = mock.Mock()
        with mock.patch.object(self.agent.int_br,
                               "delete_flows"
                               ) as mock_int_br_delete_flows, \
            mock.patch.object(self.agent,
                              "br_phys_cls") as mock_ovs_br, \
            mock.patch.object(self.agent.int_br,
                              "add_flow") as mock_int_br_add_flow:
            self.agent._init_ovs_flows(self.agent.bridge_mappings)
            self.assertTrue(mock_int_br_delete_flows.called)
            self.assertTrue(mock_ovs_br.called)
            self.assertTrue(br.delete_flows.called)
            self.assertTrue(br.add_flows.called)
            self.assertTrue(mock_int_br_add_flow.called)

    def test_update_port_bindings(self):
        self.agent.ports_to_bind.add("fake_port")
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_ports_binding",
                               return_value=set(["fake_port"])
                               ) as mock_update_ports_binding, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception:
            self.agent._update_port_bindings()
            self.assertTrue(mock_update_ports_binding.called)
            self.assertFalse(self.agent.ports_to_bind)
            self.assertFalse(mock_log_exception.called)

    def test_update_port_bindings_rpc_exception(self):
        self.agent.ports_to_bind.add("fake_port")
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_ports_binding",
                               side_effect=Exception()
                               ) as mock_update_port_binding, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception:
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent._update_port_bindings)
            self.assertTrue(mock_update_port_binding.called)
            self.assertTrue(mock_log_exception.called)
            self.assertEqual(set(['fake_port']),
                             self.agent.ports_to_bind)

    def test_update_port_bindings_partial(self):
        self.agent.ports_to_bind.add("fake_port1")
        self.agent.ports_to_bind.add("fake_port2")
        self.agent.ports_to_bind.add("fake_port3")
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_ports_binding",
                               return_value=set(["fake_port1",
                                                "fake_port2"])
                               ) as mock_update_port_binding, \
                mock.patch.object(self.LOG, 'exception'):
            self.agent._update_port_bindings()
            self.assertTrue(mock_update_port_binding.called)
            self.assertEqual(set(["fake_port3"]),
                             self.agent.ports_to_bind)

    def test_setup_ovs_bridges_vlan(self):
        cfg.CONF.set_override('tenant_network_types',
                              "vlan", 'OVSVAPP')
        cfg.CONF.set_override('bridge_mappings',
                              ["physnet1:br-eth1"], 'OVSVAPP')
        with mock.patch.object(self.agent, 'setup_physical_bridges'
                               ) as mock_phys_brs, \
                mock.patch.object(self.agent, '_init_ovs_flows'
                                  ) as mock_init_ovs_flows:
            self.agent.setup_ovs_bridges()
            mock_phys_brs.assert_called_with(self.agent.bridge_mappings)
            mock_init_ovs_flows.assert_called_with(self.agent.bridge_mappings)

    def test_setup_ovs_bridges_vxlan(self):
        self.agent.local_ip = "10.10.10.10"
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        with mock.patch.object(self.agent, 'setup_tunnel_br'
                               ) as mock_setup_tunnel_br, \
                mock.patch.object(self.agent, 'setup_tunnel_br_flows'
                                  ) as mock_setup_tunnel_br_flows:
            self.agent.setup_ovs_bridges()
            mock_setup_tunnel_br.assert_called_with("br-tun")
            self.assertTrue(mock_setup_tunnel_br_flows.called)

    def test_setup_ovs_bridges_vxlan_ofport(self):
        cfg.CONF.set_override('tenant_network_types',
                              "vxlan", 'OVSVAPP')
        cfg.CONF.set_override('local_ip',
                              "10.10.10.10", 'OVSVAPP')
        cfg.CONF.set_override('tunnel_bridge',
                              "br-tun", 'OVSVAPP')
        self.agent.tun_br = mock.Mock()
        self.agent.int_br = mock.Mock()
        self.agent.local_ip = "10.10.10.10"
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        with mock.patch.object(self.agent.tun_br,
                               "add_patch_port",
                               return_value=5), \
                mock.patch.object(self.agent.int_br,
                                  "add_patch_port",
                                  return_value=6), \
                mock.patch.object(self.agent, 'setup_tunnel_br_flows'
                                  ) as mock_setup_tunnel_br_flows:
            self.agent.setup_ovs_bridges()
            self.assertTrue(self.agent.tun_br.add_patch_port.called)
            self.assertEqual(self.agent.patch_tun_ofport, 6)
            self.assertEqual(self.agent.patch_int_ofport, 5)
            self.assertTrue(mock_setup_tunnel_br_flows.called)

    def test_mitigate_ovs_restart_vlan(self):
        self.agent.refresh_firewall_required = False
        self.agent.devices_to_filter = set(['1111'])
        self.agent.cluster_host_ports = set(['1111'])
        self.agent.cluster_other_ports = set(['2222'])
        with mock.patch.object(self.LOG, 'info') as mock_logger_info, \
                mock.patch.object(self.agent, "setup_integration_br"
                                  ) as mock_int_br, \
                mock.patch.object(self.agent, "setup_physical_bridges"
                                  ) as mock_phys_brs, \
                mock.patch.object(self.agent, "setup_security_br"
                                  ) as mock_sec_br, \
                mock.patch.object(self.agent.sg_agent, "init_firewall"
                                  ) as mock_init_fw, \
                mock.patch.object(self.agent, "setup_tunnel_br"
                                  ) as mock_setup_tunnel_br,\
                mock.patch.object(self.agent, 'setup_tunnel_br_flows'
                                  ) as mock_setup_tunnel_br_flows, \
                mock.patch.object(self.agent, "_init_ovs_flows"
                                  ) as mock_init_flows, \
                mock.patch.object(self.agent.monitor_log, "warning"
                                  ) as monitor_warning, \
                mock.patch.object(self.agent.monitor_log, "info"
                                  ) as monitor_info:
            self.agent.mitigate_ovs_restart()
            self.assertTrue(mock_int_br.called)
            self.assertTrue(mock_phys_brs.called)
            self.assertTrue(mock_sec_br.called)
            self.assertFalse(mock_setup_tunnel_br.called)
            self.assertFalse(mock_setup_tunnel_br_flows.called)
            self.assertTrue(mock_init_fw.called)
            self.assertTrue(mock_init_flows.called)
            self.assertTrue(self.agent.refresh_firewall_required)
            self.assertEqual(2, len(self.agent.devices_to_filter))
            monitor_warning.assert_called_with("ovs: broken")
            monitor_info.assert_called_with("ovs: ok")
            self.assertTrue(mock_logger_info.called)

    def test_mitigate_ovs_restart_vxlan(self):
        self.agent.enable_tunneling = True
        self.agent.refresh_firewall_required = False
        self.agent.devices_to_filter = set(['1111'])
        self.agent.cluster_host_ports = set(['1111'])
        self.agent.cluster_other_ports = set(['2222'])
        with mock.patch.object(self.LOG, 'info') as mock_logger_info, \
                mock.patch.object(self.agent, "setup_integration_br"), \
                mock.patch.object(self.agent, "setup_physical_bridges"
                                  ) as mock_phys_brs, \
                mock.patch.object(self.agent, "setup_security_br"), \
                mock.patch.object(self.agent.sg_agent, "init_firewall"
                                  ), \
                mock.patch.object(self.agent, "setup_tunnel_br"
                                  ) as mock_setup_tunnel_br,\
                mock.patch.object(self.agent, 'setup_tunnel_br_flows'
                                  ) as mock_setup_tunnel_br_flows, \
                mock.patch.object(self.agent, "tunnel_sync"
                                  ) as mock_tun_sync, \
                mock.patch.object(self.agent, "_init_ovs_flows"), \
                mock.patch.object(self.agent.monitor_log, "warning"
                                  ) as monitor_warning, \
                mock.patch.object(self.agent.monitor_log, "info"
                                  ) as monitor_info:
            self.agent.mitigate_ovs_restart()
            self.assertTrue(mock_setup_tunnel_br.called)
            self.assertTrue(mock_setup_tunnel_br_flows.called)
            self.assertFalse(mock_phys_brs.called)
            self.assertTrue(mock_tun_sync.called)
            self.assertTrue(self.agent.refresh_firewall_required)
            self.assertEqual(len(self.agent.devices_to_filter), 2)
            monitor_warning.assert_called_with("ovs: broken")
            monitor_info.assert_called_with("ovs: ok")
            self.assertTrue(mock_logger_info.called)

    def test_mitigate_ovs_restart_exception(self):
        self.agent.enable_tunneling = False
        self.agent.refresh_firewall_required = False
        self.agent.devices_to_filter = set()
        self.agent.cluster_host_ports = set(['1111'])
        self.agent.cluster_other_ports = set(['2222'])

        with mock.patch.object(self.LOG, "info") as mock_logger_info, \
                mock.patch.object(self.agent, "setup_integration_br",
                                  side_effect=Exception()) as mock_int_br, \
                mock.patch.object(self.agent, "setup_physical_bridges"
                                  ) as mock_phys_brs, \
                mock.patch.object(self.agent, "setup_tunnel_br"
                                  ) as mock_setup_tunnel_br,\
                mock.patch.object(self.agent, 'setup_tunnel_br_flows'
                                  ) as mock_setup_tunnel_br_flows, \
                mock.patch.object(self.LOG, "exception"
                                  ) as mock_exception_log, \
                mock.patch.object(self.agent.monitor_log, "warning"
                                  ) as monitor_warning, \
                mock.patch.object(self.agent.monitor_log, "info"
                                  ) as monitor_info:
            self.agent.mitigate_ovs_restart()
            self.assertTrue(mock_int_br.called)
            self.assertFalse(mock_phys_brs.called)
            self.assertFalse(mock_setup_tunnel_br.called)
            self.assertFalse(mock_setup_tunnel_br_flows.called)
            self.assertFalse(mock_logger_info.called)
            self.assertTrue(mock_exception_log.called)
            self.assertFalse(self.agent.refresh_firewall_required)
            self.assertEqual(0, len(self.agent.devices_to_filter))
            monitor_warning.assert_called_with("ovs: broken")
            self.assertFalse(monitor_info.called)

    def _get_fake_port(self, port_id):
        return {'id': port_id,
                'port_id': port_id,
                'mac_address': MAC_ADDRESS,
                'fixed_ips': [{'subnet_id': 'subnet_uuid',
                               'ip_address': '1.1.1.1'}],
                'security_groups': FAKE_SG,
                'segmentation_id': 1232,
                'lvid': 1,
                'network_id': 'fake_network',
                'device_id': FAKE_DEVICE_ID,
                'admin_state_up': True,
                'physical_network': 'physnet1',
                'network_type': 'vlan'}

    def _build_phys_brs(self, port):
        phys_net = port['physical_network']
        self.agent.phys_brs[phys_net] = {}
        self.agent.phys_brs[phys_net]['eth_ofport'] = 5
        br = self.agent.phys_brs[phys_net]['br'] = mock.Mock()
        br.add_flows(port['segmentation_id'],
                     port['mac_address'],
                     5)
        br.delete_flows(port['mac_address'],
                        port['segmentation_id'])
        return br

    def test_process_port(self):
        fakeport = self._get_fake_port(FAKE_PORT_1)
        self.agent.ports_dict = {}
        br = self._build_phys_brs(fakeport)
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.vnic_info[FAKE_PORT_1] = fakeport
        with mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                               ) as mock_add_devices, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan:
            status = self.agent._process_port(fakeport)
            self.assertIn(FAKE_PORT_1, self.agent.ports_dict)
            self.assertTrue(status)
            mock_add_devices.assert_called_with([fakeport])
            mock_prov_local_vlan.assert_called_with(fakeport)
            self.assertTrue(br.add_flows.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.vnic_info)

    def test_process_port_existing_network(self):
        fakeport = self._get_fake_port(FAKE_PORT_1)
        self.agent.ports_dict = {}
        br = self._build_phys_brs(fakeport)
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.vnic_info[FAKE_PORT_1] = {}
        net_id = fakeport['network_id']
        self.agent.local_vlan_map[net_id] = self._build_lvm(fakeport)
        with mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                               ) as mock_add_devices, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan:
            status = self.agent._process_port(fakeport)
            self.assertIn(FAKE_PORT_1, self.agent.ports_dict)
            self.assertTrue(status)
            mock_add_devices.assert_called_with([fakeport])
            self.assertFalse(mock_prov_local_vlan.called)
            self.assertTrue(br.add_flows.called)

    def test_process_uncached_devices_with_few_devices(self):
        devices = set(['123', '234', '345', '456', '567', '678',
                       '1123', '1234', '1345', '1456', '1567', '1678'])
        with mock.patch('eventlet.GreenPool.spawn_n') as mock_spawn_thread, \
                mock.patch.object(self.LOG, 'exception') as mock_log_exception:
            self.agent._process_uncached_devices(devices)
            self.assertTrue(mock_spawn_thread.called)
            self.assertEqual(1, mock_spawn_thread.call_count)
            self.assertFalse(mock_log_exception.called)

    def test_process_uncached_devices_with_more_devices(self):
        devices = set(['123', '234', '345', '456', '567', '678',
                       '1123', '1234', '1345', '1456', '1567', '1678',
                       '2123', '2234', '2345', '2456', '2567', '2678',
                       '3123', '3234', '3345', '3456', '3567', '3678',
                       '4123', '4234', '4345', '4456', '4567', '4678',
                       '5123', '5234', '5345', '5456', '5567', '5678',
                       '6123', '6234', '6345', '6456', '6567', '6678'])
        with mock.patch('eventlet.GreenPool.spawn_n') as mock_spawn_thread, \
                mock.patch.object(self.LOG, 'exception') as mock_log_exception:
            self.agent._process_uncached_devices(devices)
            self.assertTrue(mock_spawn_thread.called)
            self.assertEqual(2, mock_spawn_thread.call_count)
            self.assertFalse(mock_log_exception.called)

    def test_process_uncached_devices_sublist_single_port_vlan(self):
        fakeport_1 = self._get_fake_port(FAKE_PORT_1)
        self.agent.ports_dict = {}
        br = self._build_phys_brs(fakeport_1)
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.vnic_info[FAKE_PORT_1] = fakeport_1
        devices = [FAKE_PORT_1]
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               'get_ports_details_list',
                               return_value=[fakeport_1]
                               ) as mock_get_ports_details_list, \
                mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                                  ) as mock_add_devices_to_filter, \
                mock.patch.object(self.agent.sg_agent, 'refresh_firewall'
                                  )as mock_refresh_firewall, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_provision_local_vlan, \
                mock.patch.object(self.LOG, 'exception') as mock_log_exception:
            self.agent._process_uncached_devices_sublist(devices)
            self.assertTrue(mock_get_ports_details_list.called)
            self.assertEqual(1, mock_add_devices_to_filter.call_count)
            self.assertTrue(mock_refresh_firewall.called)
            self.assertTrue(mock_provision_local_vlan.called)
            self.assertFalse(mock_log_exception.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.vnic_info)
            self.assertTrue(br.add_flows.called)

    def test_process_uncached_devices_sublist_multiple_port_vlan(self):
        fakeport_1 = self._get_fake_port(FAKE_PORT_1)
        fakeport_2 = self._get_fake_port(FAKE_PORT_2)
        self.agent.ports_dict = {}
        br = self._build_phys_brs(fakeport_1)
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.cluster_host_ports.add(FAKE_PORT_2)
        self.agent.vnic_info[FAKE_PORT_1] = fakeport_1
        self.agent.vnic_info[FAKE_PORT_2] = fakeport_2
        devices = [FAKE_PORT_1, FAKE_PORT_2]
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               'get_ports_details_list',
                               return_value=[fakeport_1, fakeport_2]
                               ) as mock_get_ports_details_list, \
                mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                                  ) as mock_add_devices_to_filter, \
                mock.patch.object(self.agent.sg_agent, 'refresh_firewall'
                                  )as mock_refresh_firewall, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.LOG, 'exception') as mock_log_exception:
            self.agent._process_uncached_devices_sublist(devices)
            self.assertTrue(mock_get_ports_details_list.called)
            self.assertEqual(2, mock_add_devices_to_filter.call_count)
            self.assertTrue(mock_refresh_firewall.called)
            self.assertTrue(mock_prov_local_vlan.called)
            self.assertFalse(mock_log_exception.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.vnic_info)
            self.assertNotIn(FAKE_PORT_2, self.agent.vnic_info)
            self.assertTrue(br.add_flows.called)

    def test_process_uncached_devices_sublist_single_port_vxlan(self):
        fakeport_1 = self._get_fake_port(FAKE_PORT_1)
        fakeport_1["network_type"] = p_const.TYPE_VXLAN
        self.agent.ports_dict = {}
        self.agent.local_vlan_map = {}
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.vnic_info[FAKE_PORT_1] = fakeport_1
        devices = [FAKE_PORT_1]
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               'get_ports_details_list',
                               return_value=[fakeport_1]
                               ) as mock_get_ports_details_list, \
                mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                                  ) as mock_add_devices_to_filter, \
                mock.patch.object(self.agent.sg_agent, 'refresh_firewall'
                                  )as mock_refresh_firewall, \
                mock.patch.object(self.agent, '_populate_lvm'), \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.LOG, 'exception') as mock_log_exception:
            self.agent._process_uncached_devices_sublist(devices)
            self.assertTrue(mock_get_ports_details_list.called)
            self.assertTrue(mock_prov_local_vlan.called)
            self.assertEqual(1, mock_add_devices_to_filter.call_count)
            self.assertTrue(mock_refresh_firewall.called)
            self.assertFalse(mock_log_exception.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.vnic_info)

    def test_process_uncached_devices_sublist_multiple_port_vxlan(self):
        fakeport_1 = self._get_fake_port(FAKE_PORT_1)
        fakeport_2 = self._get_fake_port(FAKE_PORT_2)
        fakeport_1["network_type"] = p_const.TYPE_VXLAN
        fakeport_2["network_type"] = p_const.TYPE_VXLAN
        self.agent.ports_dict = {}
        self.agent.local_vlan_map = {}
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.cluster_host_ports.add(FAKE_PORT_2)
        self.agent.vnic_info[FAKE_PORT_1] = fakeport_1
        self.agent.vnic_info[FAKE_PORT_2] = fakeport_2
        devices = [FAKE_PORT_1, FAKE_PORT_2]
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               'get_ports_details_list',
                               return_value=[fakeport_1, fakeport_2]
                               ) as mock_get_ports_details_list, \
                mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                                  ) as mock_add_devices_to_filter, \
                mock.patch.object(self.agent.sg_agent, 'refresh_firewall'
                                  )as mock_refresh_firewall, \
                mock.patch.object(self.agent, '_populate_lvm'), \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.LOG, 'exception') as mock_log_exception:
            self.agent._process_uncached_devices_sublist(devices)
            self.assertTrue(mock_get_ports_details_list.called)
            self.assertTrue(mock_prov_local_vlan.called)
            self.assertEqual(2, mock_add_devices_to_filter.call_count)
            self.assertTrue(mock_refresh_firewall.called)
            self.assertFalse(mock_log_exception.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.vnic_info)
            self.assertNotIn(FAKE_PORT_2, self.agent.vnic_info)

    def test_process_uncached_devices_sublist_stale_vm_port(self):
        fakeport_1 = self._get_fake_port(FAKE_PORT_1)
        fakeport_2 = self._get_fake_port(FAKE_PORT_2)
        fakeport_3 = self._get_fake_port(FAKE_PORT_3)
        self.agent.ports_dict = {}
        self._build_phys_brs(fakeport_1)
        self._build_phys_brs(fakeport_2)
        self._build_phys_brs(fakeport_3)
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.cluster_host_ports.add(FAKE_PORT_2)
        self.agent.ports_to_bind = set([FAKE_PORT_3, FAKE_PORT_4])
        self.agent.vnic_info[FAKE_PORT_1] = fakeport_1
        self.agent.vnic_info[FAKE_PORT_2] = fakeport_2
        self.agent.vnic_info[FAKE_PORT_3] = fakeport_3
        devices = [FAKE_PORT_1, FAKE_PORT_2, FAKE_PORT_3]
        self.agent.sg_agent.remove_devices_filter = mock.Mock()
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               'get_ports_details_list',
                               return_value=[fakeport_1, fakeport_2]
                               ) as mock_get_ports_details_list, \
                mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                                  ) as mock_add_devices_to_filter, \
                mock.patch.object(self.agent.sg_agent, 'refresh_firewall'
                                  )as mock_refresh_firewall, \
                mock.patch.object(self.agent.sg_agent,
                                  'remove_devices_filter'
                                  )as mock_remove_device_filter, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.agent, '_remove_stale_ports_flows'), \
                mock.patch.object(self.agent, '_block_stale_ports'), \
                mock.patch.object(self.LOG, 'exception') as mock_log_exception:
            self.agent._process_uncached_devices_sublist(devices)
            self.assertTrue(mock_get_ports_details_list.called)
            self.assertEqual(2, mock_add_devices_to_filter.call_count)
            self.assertTrue(mock_refresh_firewall.called)
            self.assertTrue(mock_prov_local_vlan.called)
            self.assertFalse(mock_log_exception.called)
            self.assertNotIn(FAKE_PORT_3, self.agent.ports_to_bind)
            self.assertIn(FAKE_PORT_4, self.agent.ports_to_bind)
            self.assertNotIn(FAKE_PORT_1, self.agent.vnic_info)
            self.assertNotIn(FAKE_PORT_2, self.agent.vnic_info)
            self.assertNotIn(FAKE_PORT_3, self.agent.vnic_info)
            mock_remove_device_filter.assert_called_with(FAKE_PORT_3)

    def test_update_firewall(self):
        fakeport_1 = self._get_fake_port(FAKE_PORT_1)
        fakeport_2 = self._get_fake_port(FAKE_PORT_2)
        self._build_phys_brs(fakeport_1)
        self._build_phys_brs(fakeport_2)
        self.agent.devices_to_filter = set([FAKE_PORT_1,
                                            FAKE_PORT_2])
        self.agent.ports_dict = {FAKE_PORT_1: fakeport_1}
        self.agent.vnic_info[FAKE_PORT_1] = {}
        self.agent.vnic_info[FAKE_PORT_2] = {}
        self.agent.refresh_firewall_required = True
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               'get_ports_details_list',
                               return_value=[fakeport_1, fakeport_2]
                               ) as mock_get_ports_details_list, \
                mock.patch.object(self.agent.sg_agent, 'refresh_firewall'
                                  ) as mock_refresh_firewall, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ), \
                mock.patch.object(self.agent, '_remove_stale_ports_flows'), \
                mock.patch.object(self.agent, '_block_stale_ports'), \
                mock.patch.object(self.agent.monitor_log, "warning"
                                  ) as monitor_warning, \
                mock.patch.object(self.agent.monitor_log, "info"
                                  ) as monitor_info:
            self.agent._update_firewall()
            self.assertFalse(self.agent.refresh_firewall_required)
            self.assertFalse(self.agent.devices_to_filter)
            self.assertIn(FAKE_PORT_2, self.agent.ports_dict)
            mock_get_ports_details_list.assert_called_with(
                self.agent.context,
                [FAKE_PORT_2],
                self.agent.agent_id,
                self.agent.vcenter_id,
                self.agent.cluster_id)
            mock_refresh_firewall.assert_called_with(set([FAKE_PORT_1,
                                                          FAKE_PORT_2]))
            self.assertEqual(2, monitor_warning.call_count)
            self.assertEqual(2, monitor_info.call_count)

    def test_update_firewall_get_ports_exception(self):
        fakeport_1 = self._get_fake_port(FAKE_PORT_1)
        self.agent.devices_to_filter = set([FAKE_PORT_1,
                                            FAKE_PORT_2])
        self.agent.ports_dict = {FAKE_PORT_1: fakeport_1}
        self.agent.refresh_firewall_required = True
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               'get_ports_details_list',
                               side_effect=Exception()
                               ) as mock_get_ports_details_list, \
                mock.patch.object(self.agent.sg_agent, 'refresh_firewall'
                                  ) as mock_refresh_firewall, \
                mock.patch.object(self.agent.monitor_log, "warning"
                                  ) as monitor_warning, \
                mock.patch.object(self.agent.monitor_log, "info"
                                  ) as monitor_info:
            self.agent._update_firewall()
            self.assertTrue(self.agent.refresh_firewall_required)
            self.assertEqual(set([FAKE_PORT_2]), self.agent.devices_to_filter)
            self.assertNotIn(FAKE_PORT_2, self.agent.ports_dict)
            mock_get_ports_details_list.assert_called_with(
                self.agent.context,
                [FAKE_PORT_2],
                self.agent.agent_id,
                self.agent.vcenter_id,
                self.agent.cluster_id)
            mock_refresh_firewall.assert_called_with(set([FAKE_PORT_1]))
            self.assertEqual(2, monitor_warning.call_count)
            self.assertEqual(1, monitor_info.call_count)

    def test_check_for_updates_no_updates(self):
        self.agent.refresh_firewall_required = False
        self.agent.ports_to_bind = None
        with mock.patch.object(self.agent, 'check_ovs_status',
                               return_value=4) as mock_check_ovs, \
                mock.patch.object(self.agent, '_update_firewall'
                                  ) as mock_update_firewall, \
                mock.patch.object(self.agent.sg_agent,
                                  'firewall_refresh_needed',
                                  return_value=False
                                  ) as mock_firewall_refresh, \
                mock.patch.object(self.agent.sg_agent, 'refresh_port_filters'
                                  ) as mock_refresh_port_filters, \
                mock.patch.object(self.agent, '_update_port_bindings'
                                  ) as mock_update_port_bindings:
            self.agent._check_for_updates()
            self.assertTrue(mock_check_ovs.called)
            self.assertFalse(mock_update_firewall.called)
            self.assertTrue(mock_firewall_refresh.called)
            self.assertFalse(mock_refresh_port_filters.called)
            self.assertFalse(mock_update_port_bindings.called)

    def test_check_for_updates_ovs_restarted(self):
        self.agent.refresh_firewall_required = False
        self.agent.ports_to_bind = None
        with mock.patch.object(self.agent, 'check_ovs_status',
                               return_value=0) as mock_check_ovs, \
                mock.patch.object(self.agent, 'mitigate_ovs_restart'
                                  ) as mock_mitigate, \
                mock.patch.object(self.agent, '_update_firewall'
                                  ) as mock_update_firewall, \
                mock.patch.object(self.agent.sg_agent,
                                  'firewall_refresh_needed',
                                  return_value=False
                                  ) as mock_firewall_refresh, \
                mock.patch.object(self.agent, '_update_port_bindings'
                                  ) as mock_update_port_bindings:
            self.agent._check_for_updates()
            self.assertTrue(mock_check_ovs.called)
            self.assertTrue(mock_mitigate.called)
            self.assertFalse(mock_update_firewall.called)
            self.assertTrue(mock_firewall_refresh.called)
            self.assertFalse(mock_update_port_bindings.called)

    @mock.patch.object(ovsvapp_agent.OVSvAppAgent, 'check_ovs_status')
    def test_check_for_updates_ovs_dead(self, check_ovs_status):
        check_ovs_status.return_value = 2
        self.agent.refresh_firewall_required = False
        self.agent.ports_to_bind = None
        with mock.patch.object(self.agent, 'mitigate_ovs_restart'
                               ) as mock_mitigate, \
                mock.patch.object(self.agent, '_update_firewall'
                                  ) as mock_update_firewall, \
                mock.patch.object(self.agent.sg_agent,
                                  'firewall_refresh_needed',
                                  return_value=False
                                  ) as mock_firewall_refresh, \
                mock.patch.object(self.agent, '_update_port_bindings'
                                  ) as mock_update_port_bindings:
            self.agent._check_for_updates()
            self.assertTrue(self.agent.ovsvapp_mitigation_required)
            self.assertTrue(check_ovs_status.called)
            self.assertFalse(mock_mitigate.called)
            self.assertTrue(mock_firewall_refresh.called)
            self.assertFalse(mock_update_port_bindings.called)
            check_ovs_status.return_value = 1
            self.agent._check_for_updates()
            self.assertTrue(check_ovs_status.called)
            self.assertTrue(mock_mitigate.called)
            self.assertFalse(mock_update_firewall.called)
            self.assertTrue(mock_firewall_refresh.called)
            self.assertFalse(mock_update_port_bindings.called)
            self.assertFalse(self.agent.ovsvapp_mitigation_required)

    def test_check_for_updates_devices_to_filter(self):
        self.agent.refresh_firewall_required = True
        self.agent.ports_to_bind = None
        with mock.patch.object(self.agent, 'check_ovs_status',
                               return_value=4) as mock_check_ovs, \
                mock.patch.object(self.agent, 'mitigate_ovs_restart'
                                  ) as mock_mitigate, \
                mock.patch.object(self.agent, '_update_firewall'
                                  ) as mock_update_firewall,\
                mock.patch.object(self.agent.sg_agent,
                                  'firewall_refresh_needed',
                                  return_value=False
                                  ) as mock_firewall_refresh, \
                mock.patch.object(self.agent, '_update_port_bindings'
                                  ) as mock_update_port_bindings:
            self.agent._check_for_updates()
            self.assertTrue(mock_check_ovs.called)
            self.assertFalse(mock_mitigate.called)
            self.assertTrue(mock_update_firewall.called)
            self.assertTrue(mock_firewall_refresh.called)
            self.assertFalse(mock_update_port_bindings.called)

    def test_check_for_updates_firewall_refresh(self):
        self.agent.refresh_firewall_required = False
        self.agent.ports_to_bind = None
        with mock.patch.object(self.agent, 'check_ovs_status',
                               return_value=4) as mock_check_ovs, \
                mock.patch.object(self.agent, '_update_firewall'
                                  ) as mock_update_firewall, \
                mock.patch.object(self.agent.sg_agent,
                                  'firewall_refresh_needed',
                                  return_value=True
                                  ) as mock_firewall_refresh,\
                mock.patch.object(self.agent.sg_agent, 'refresh_port_filters'
                                  ) as mock_refresh_port_filters, \
                mock.patch.object(self.agent, '_update_port_bindings'
                                  ) as mock_update_port_bindings:
            self.agent._check_for_updates()
            self.assertTrue(mock_check_ovs.called)
            self.assertFalse(mock_update_firewall.called)
            self.assertTrue(mock_firewall_refresh.called)
            self.assertTrue(mock_refresh_port_filters.called)
            self.assertFalse(mock_update_port_bindings.called)

    def test_check_for_updates_port_bindings(self):
        self.agent.refresh_firewall_required = False
        self.agent.ports_to_bind.add("fake_port")
        with mock.patch.object(self.agent, 'check_ovs_status',
                               return_value=4) as mock_check_ovs, \
                mock.patch.object(self.agent, '_update_firewall'
                                  ) as mock_update_firewall, \
                mock.patch.object(self.agent.sg_agent,
                                  'firewall_refresh_needed',
                                  return_value=False
                                  ) as mock_firewall_refresh, \
                mock.patch.object(self.agent, '_update_port_bindings'
                                  ) as mock_update_port_bindings:
            self.agent._check_for_updates()
            self.assertTrue(mock_check_ovs.called)
            self.assertFalse(mock_update_firewall.called)
            self.assertTrue(mock_firewall_refresh.called)
            self.assertTrue(mock_update_port_bindings.called)

    def test_update_devices_up(self):
        self.agent.devices_up_list.append(FAKE_PORT_1)
        ret_value = {'devices_up': [FAKE_PORT_1],
                     'failed_devices_up': []}
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_devices_up",
                               return_value=ret_value
                               ) as update_devices_up, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as log_exception:
            self.agent._update_devices_up()
            self.assertTrue(update_devices_up.called)
            self.assertFalse(self.agent.devices_up_list)
            self.assertFalse(log_exception.called)

    def test_update_devices_up_rpc_exception(self):
        self.agent.devices_up_list.append(FAKE_PORT_1)
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_devices_up",
                               side_effect=Exception()
                               ) as update_devices_up, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as log_exception:
            self.agent._update_devices_up()
            self.assertTrue(update_devices_up.called)
            self.assertEqual([FAKE_PORT_1], self.agent.devices_up_list)
            self.assertTrue(log_exception.called)

    def test_update_devices_up_partial(self):
        self.agent.devices_up_list = [FAKE_PORT_1, FAKE_PORT_2, FAKE_PORT_3]
        ret_value = {'devices_up': [FAKE_PORT_1, FAKE_PORT_2],
                     'failed_devices_up': [FAKE_PORT_3]}
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_devices_up",
                               return_value=ret_value
                               ) as update_devices_up, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as log_exception:
            self.agent._update_devices_up()
            self.assertTrue(update_devices_up.called)
            self.assertEqual([FAKE_PORT_3], self.agent.devices_up_list)
            self.assertFalse(log_exception.called)

    def test_update_devices_down(self):
        self.agent.devices_down_list.append(FAKE_PORT_1)
        ret_value = {'devices_down': [FAKE_PORT_1],
                     'failed_devices_down': []}
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_devices_down",
                               return_value=ret_value
                               ) as update_devices_down, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as log_exception:
            self.agent._update_devices_down()
            self.assertTrue(update_devices_down.called)
            self.assertFalse(self.agent.devices_down_list)
            self.assertFalse(log_exception.called)

    def test_update_devices_down_rpc_exception(self):
        self.agent.devices_down_list.append(FAKE_PORT_1)
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_devices_down",
                               side_effect=Exception()
                               ) as update_devices_down, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as log_exception:
            self.agent._update_devices_down()
            self.assertTrue(update_devices_down.called)
            self.assertEqual([FAKE_PORT_1], self.agent.devices_down_list)
            self.assertTrue(log_exception.called)

    def test_update_devices_down_partial(self):
        self.agent.devices_down_list = [FAKE_PORT_1, FAKE_PORT_2, FAKE_PORT_3]
        ret_value = {'devices_down': [FAKE_PORT_1, FAKE_PORT_2],
                     'failed_devices_down': [FAKE_PORT_3]}
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_devices_down",
                               return_value=ret_value
                               ) as update_devices_down, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as log_exception:
            self.agent._update_devices_down()
            self.assertTrue(update_devices_down.called)
            self.assertEqual([FAKE_PORT_3], self.agent.devices_down_list)
            self.assertFalse(log_exception.called)

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
        with mock.patch.object(self.agent.state_rpc,
                               "report_state",
                               side_effect=Exception()) as mock_report_st, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception:
            self.agent._report_state()
            mock_report_st.assert_called_with(self.agent.context,
                                              self.agent.agent_state,
                                              True)
            self.assertTrue(mock_log_exception.called)

    def test_process_event_ignore_event(self):
        vm = VM(FAKE_VM, [])
        event = SampleEvent(VNIC_ADDED, FAKE_HOST_1,
                            FAKE_CLUSTER_MOID, vm)
        with mock.patch.object(self.agent,
                               "_notify_device_added") as mock_add_vm, \
                mock.patch.object(self.agent,
                                  "_notify_device_updated") as mock_update_vm, \
                mock.patch.object(self.agent,
                                  "_notify_device_deleted") as mock_del_vm, \
                mock.patch.object(self.LOG, 'debug') as mock_log_debug:
            self.agent.process_event(event)
            self.assertFalse(mock_add_vm.called)
            self.assertFalse(mock_update_vm.called)
            self.assertFalse(mock_del_vm.called)
            self.assertTrue(mock_log_debug.called)

    def test_process_event_exception(self):
        vm = VM(FAKE_VM, [])
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm)
        with mock.patch.object(self.agent,
                               "_notify_device_added",
                               side_effect=Exception()) as mock_add_vm, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception, \
                mock.patch.object(self.LOG, 'error') as mock_log_error:
            self.agent.process_event(event)
            self.assertTrue(mock_add_vm.called)
            self.assertTrue(mock_log_error.called)
            self.assertTrue(mock_log_exception.called)

    def test_process_event_vm_create_nonics_non_host_non_cluster(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm = VM(FAKE_VM, [])
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent,
                               "_notify_device_added") as device_added:
            self.agent.process_event(event)
            self.assertTrue(device_added.called)

    def test_process_event_vm_create_nonics_non_host(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm = VM(FAKE_VM, [])
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent,
                               "_notify_device_added") as device_added:
            self.agent.process_event(event)
            self.assertTrue(device_added.called)
            self.assertEqual(FAKE_CLUSTER_MOID, self.agent.cluster_moid)

    def test_process_event_vm_create_nics_non_host(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm_port2 = SamplePort(FAKE_PORT_2)
        vm = VM(FAKE_VM, ([vm_port1, vm_port2]))
        event = SampleEvent(ovsvapp_const.VM_CREATED,
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm)
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
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.process_event(event)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.devices_to_filter)
            self.assertIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_other_ports)

    def test_process_event_vm_updated_nonhost(self):
        self.agent.esx_hostname = FAKE_HOST_2
        vm_port1 = SamplePort(FAKE_PORT_1)
        port = self._build_port(FAKE_PORT_1)
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        vm = VM(FAKE_VM, [vm_port1])
        event = SampleEvent(ovsvapp_const.VM_UPDATED,
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm, True)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.process_event(event)
        self.assertIn(FAKE_PORT_1, self.agent.cluster_other_ports)

    def test_process_event_vm_delete_hosted_vm_vlan(self):
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        port = self._build_port(FAKE_PORT_1)
        br = self._build_phys_brs(port)
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        vm_port = SamplePortUIDMac(FAKE_PORT_1, MAC_ADDRESS)
        vm = VM(FAKE_VM, ([vm_port]))
        event = SampleEvent(ovsvapp_const.VM_DELETED,
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self._build_lvm(port)
        self.agent.net_mgr.initialize_driver()
        with mock.patch.object(self.agent.net_mgr.get_driver(),
                               "post_delete_vm",
                               ) as mock_post_del_vm, \
                mock.patch.object(self.LOG, 'debug'), \
                mock.patch.object(self.agent.net_mgr.get_driver(),
                                  "delete_network") as mock_del_net:
            self.agent.process_event(event)
            for vnic in vm.vnics:
                self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertTrue(mock_post_del_vm.called)
            self.assertFalse(mock_del_net.called)
            self.assertTrue(br.delete_flows.called)

    def test_process_event_vm_delete_hosted_vm_vxlan(self):
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.cluster_host_ports.add(FAKE_PORT_1)
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        port = self._build_port(FAKE_PORT_1)
        port['network_type'] = p_const.TYPE_VXLAN
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        vm_port = SamplePortUIDMac(FAKE_PORT_1, MAC_ADDRESS)
        vm = VM(FAKE_VM, ([vm_port]))
        event = SampleEvent(ovsvapp_const.VM_DELETED,
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with mock.patch.object(self.agent.net_mgr.get_driver(),
                               "post_delete_vm",
                               return_value=True) as (post_del_vm):
            self.agent.process_event(event)
            for vnic in vm.vnics:
                self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertTrue(post_del_vm.called)

    def test_process_event_vm_delete_non_hosted_vm(self):
        self.agent.esx_hostname = FAKE_HOST_2
        self.agent.cluster_other_ports.add(FAKE_PORT_1)
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        port = self._build_port(FAKE_PORT_1)
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        vm_port = SamplePortUIDMac(FAKE_PORT_1, MAC_ADDRESS)
        vm = VM(FAKE_VM, ([vm_port]))
        event = SampleEvent(ovsvapp_const.VM_DELETED,
                            FAKE_HOST_1, FAKE_CLUSTER_MOID, vm)
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent.net_mgr.get_driver(),
                               "post_delete_vm",
                               return_value=True) as mock_post_del_vm, \
                mock.patch.object(self.agent.net_mgr.get_driver(),
                                  "delete_network") as mock_del_net:
            self.agent.process_event(event)
            for vnic in vm.vnics:
                self.assertNotIn(vnic.port_uuid,
                                 self.agent.cluster_other_ports)
            self.assertTrue(mock_post_del_vm.called)
            self.assertFalse(mock_del_net.called)

    def test_notify_device_added_with_hosted_vm(self):
        vm = VM(FAKE_VM, [])
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "get_ports_for_device",
                               return_value=True) as mock_get_ports, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception, \
                mock.patch.object(time, "sleep") as mock_time_sleep:
            self.agent._notify_device_added(vm, host)
            self.assertTrue(mock_get_ports.called)
            self.assertFalse(mock_time_sleep.called)
            self.assertFalse(mock_log_exception.called)

    def test_notify_device_added_rpc_exception(self):
        vm = VM(FAKE_VM, [])
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "get_ports_for_device",
                               side_effect=Exception()) as mock_get_ports, \
                mock.patch.object(self.LOG, 'exception'
                                  )as mock_log_exception, \
                mock.patch.object(time, "sleep") as mock_time_sleep:
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent._notify_device_added, vm, host)
            self.assertTrue(mock_log_exception.called)
            self.assertTrue(mock_get_ports.called)
            self.assertFalse(mock_time_sleep.called)

    def test_notify_device_added_with_retry(self):
        vm = VM(FAKE_VM, [])
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "get_ports_for_device",
                               return_value=False) as mock_get_ports, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception, \
                mock.patch.object(time, "sleep") as mock_time_sleep:
            self.agent._notify_device_added(vm, host)
            self.assertTrue(mock_get_ports.called)
            self.assertTrue(mock_time_sleep.called)
            self.assertFalse(mock_log_exception.called)

    def test_notify_device_updated_migration_vlan(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm = VM(FAKE_VM, [vm_port1])
        port = self._build_port(FAKE_PORT_1)
        self._build_phys_brs(port)
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(port)
        self._build_lvm(port)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent._add_ports_to_host_ports([FAKE_PORT_1])
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_device_binding"
                               ) as mock_update_device_binding, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception:
            self.agent._notify_device_updated(vm, FAKE_HOST_2, True)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertFalse(mock_update_device_binding.called)
            self.assertFalse(mock_log_exception.called)

    def test_notify_device_updated_host_vlan(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm = VM(FAKE_VM, [vm_port1])
        port = self._build_port(FAKE_PORT_1)
        self._build_phys_brs(port)
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(port)
        self._build_lvm(port)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        br = self.agent.phys_brs[port['physical_network']]['br']
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_device_binding"
                               ) as mock_update_device_binding:
            self.agent._notify_device_updated(vm, host, True)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertTrue(mock_update_device_binding.called)
            self.assertTrue(br.add_flows.called)

    def test_notify_device_updated_vlan_rpc_exception(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm = VM(FAKE_VM, [vm_port1])
        port = self._build_port(FAKE_PORT_1)
        br = self._build_phys_brs(port)
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(port)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_device_binding",
                               side_effect=Exception()
                               ) as mock_update_device_binding, \
            mock.patch.object(self.LOG, 'exception'
                              ) as mock_log_exception:
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent._notify_device_updated, vm, host, True)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertTrue(br.add_flows.called)
            self.assertTrue(mock_update_device_binding.called)
            self.assertTrue(mock_log_exception.called)

    def test_notify_device_updated_host_vlan_multiple_nic(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm_port2 = SamplePort(FAKE_PORT_2)
        vm = VM(FAKE_VM, ([vm_port1, vm_port2]))
        port1 = self._build_port(FAKE_PORT_1)
        port2 = self._build_port(FAKE_PORT_2)
        br1 = self._build_phys_brs(port1)
        br2 = self._build_phys_brs(port2)
        self.agent.ports_dict[port1['id']] = self.agent._build_port_info(port1)
        self.agent.ports_dict[port2['id']] = self.agent._build_port_info(port2)
        self._build_lvm(port1)
        self._build_lvm(port2)
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_device_binding"
                               ) as mock_update_device_binding, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception:
            self.agent._notify_device_updated(vm, host, True)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertTrue(mock_update_device_binding.called)
            self.assertFalse(mock_log_exception.called)
            self.assertEqual(1, mock_update_device_binding.call_count)
            self.assertTrue(br1.add_flows.called)
            self.assertTrue(br2.add_flows.called)

    def _build_lvm(self, port):
        net_id = port['network_id']
        self.agent.local_vlan_map[net_id] = ovs_agent.LocalVLANMapping(
            port['lvid'], port['network_type'],
            port['physical_network'],
            '1234')

    def test_notify_device_updated_host_vxlan(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = SamplePort(FAKE_PORT_1)
        port1 = self._build_port(FAKE_PORT_1)
        port1['network_type'] = p_const.TYPE_VXLAN
        self.agent.ports_dict[port1['id']] = self.agent._build_port_info(port1)
        vm = VM(FAKE_VM, [vm_port1])
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_device_binding"
                               ) as mock_update_device_binding, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception:
            self.agent._notify_device_updated(vm, host, True)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertTrue(mock_update_device_binding.called)
            self.assertFalse(mock_log_exception.called)

    def test_notify_device_updated_vxlan_rpc_exception(self):
        host = FAKE_HOST_1
        self.agent.esx_hostname = host
        vm_port1 = SamplePort(FAKE_PORT_1)
        vm = VM(FAKE_VM, [vm_port1])
        self.agent.state = ovsvapp_const.AGENT_RUNNING
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        with mock.patch.object(self.agent.ovsvapp_rpc,
                               "update_device_binding",
                               side_effect=Exception()
                               ) as mock_update_device_binding, \
                mock.patch.object(self.LOG, 'exception'
                                  ) as mock_log_exception:
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent._notify_device_updated, vm, host, True)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertTrue(mock_update_device_binding.called)
            self.assertTrue(mock_log_exception.called)

    def test_map_port_to_common_model_vlan(self):
        expected_port = self._build_port(FAKE_PORT_1)
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        network, port = self.agent._map_port_to_common_model(expected_port)
        expected_name = expected_port['network_id'] + "-" + FAKE_CLUSTER_MOID
        self.assertEqual(expected_name, network.name)
        self.assertEqual(expected_port['id'], port.uuid)

    def test_map_port_to_common_model_vxlan(self):
        expected_port = self._build_port(FAKE_PORT_1)
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        network, port = self.agent._map_port_to_common_model(expected_port, 1)
        expected_name = expected_port['network_id'] + "-" + FAKE_CLUSTER_MOID
        self.assertEqual(expected_name, network.name)
        self.assertEqual(expected_port['id'], port.uuid)

    def test_device_create_cluster_mismatch(self):
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_2
        with mock.patch.object(self.agent,
                               '_process_create_ports',
                               return_value=True) as mock_create_ports, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE)
            self.assertTrue(mock_logger_debug.called)
            self.assertFalse(mock_create_ports.called)

    def test_device_create_non_hosted_vm(self):
        ports = [self._build_port(FAKE_PORT_1)]
        self._build_phys_brs(ports[0])
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.esx_hostname = FAKE_HOST_2
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.devices_up_list = []
        with mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                               ) as mock_add_devices_fn, \
                mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'
                                  ) as mock_sg_update_fn, \
                mock.patch.object(self.agent.sg_agent, 'expand_sg_rules',
                                  return_value=FAKE_SG_RULES
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=mock.MagicMock())
            self.assertTrue(mock_logger_debug.called)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertFalse(self.agent.devices_up_list)
            self.assertTrue(mock_sg_update_fn.called)
            self.assertTrue(mock_expand_sg_rules.called)
            self.assertTrue(mock_prov_local_vlan.called)

    def test_device_create_hosted_vm_vlan(self):
        ports = [self._build_port(FAKE_PORT_1)]
        self._build_phys_brs(ports[0])
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.devices_up_list = []
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                               ) as mock_add_devices_fn, \
                mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'
                                  ) as mock_sg_update_fn, \
                mock.patch.object(self.agent.sg_agent, 'expand_sg_rules',
                                  return_value=FAKE_SG_RULES
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=mock.MagicMock())
            self.assertTrue(mock_logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertEqual([FAKE_PORT_1], self.agent.devices_up_list)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertTrue(mock_sg_update_fn.called)
            self.assertTrue(mock_expand_sg_rules.called)
            self.assertTrue(mock_prov_local_vlan.called)

    def test_device_create_hosted_vm_vlan_sg_rule_missing(self):
        ports = [self._build_port(FAKE_PORT_1)]
        self._build_phys_brs(ports[0])
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.devices_up_list = []
        self.agent.devices_to_filter = set()
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                               ) as mock_add_devices_fn, \
                mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'
                                  ) as mock_sg_update_fn, \
                mock.patch.object(self.agent.sg_agent, 'expand_sg_rules',
                                  return_value=FAKE_SG_RULES_MISSING
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=mock.MagicMock())
            self.assertTrue(mock_logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertEqual([FAKE_PORT_1], self.agent.devices_up_list)
            self.assertIn(FAKE_PORT_1, self.agent.devices_to_filter)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertFalse(mock_sg_update_fn.called)
            self.assertTrue(mock_expand_sg_rules.called)
            self.assertTrue(mock_prov_local_vlan.called)

    def test_device_create_hosted_vm_vlan_sg_rule_partial_missing(self):
        ports = [self._build_port(FAKE_PORT_1)]
        self._build_phys_brs(ports[0])
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.devices_up_list = []
        self.agent.devices_to_filter = set()
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                               ) as mock_add_devices_fn, \
                mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'
                                  ) as mock_sg_update_fn, \
                mock.patch.object(self.agent.sg_agent, 'expand_sg_rules',
                                  return_value=FAKE_SG_RULES_PARTIAL
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=mock.MagicMock())
            self.assertTrue(mock_logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertEqual([FAKE_PORT_1], self.agent.devices_up_list)
            self.assertIn(FAKE_PORT_1, self.agent.devices_to_filter)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertFalse(mock_sg_update_fn.called)
            self.assertTrue(mock_expand_sg_rules.called)
            self.assertTrue(mock_prov_local_vlan.called)

    def test_device_create_hosted_vm_vxlan(self):
        port = self._build_port(FAKE_PORT_1)
        port['network_type'] = p_const.TYPE_VXLAN
        ports = [port]
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        self.agent.local_vlan_map = {}
        self.agent.devices_to_filter = set()
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with mock.patch.object(self.agent, '_provision_local_vlan'
                               ) as mock_prov_local_vlan, \
                mock.patch.object(self.agent.sg_agent,
                                  'add_devices_to_filter'
                                  ) as mock_add_devices_fn, \
                mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'
                                  ) as mock_sg_update_fn, \
                mock.patch.object(self.agent.sg_agent, 'expand_sg_rules',
                                  return_value=FAKE_SG_RULES
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.agent.plugin_rpc, 'update_device_up'
                                  ) as mock_update_device_up, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=mock.MagicMock())
            self.assertTrue(mock_prov_local_vlan.called)
            self.assertTrue(mock_logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertNotIn(FAKE_PORT_1, self.agent.devices_to_filter)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertTrue(mock_sg_update_fn.called)
            self.assertTrue(mock_expand_sg_rules.called)
            self.assertTrue(mock_update_device_up.called)

    def test_device_create_hosted_vm_vxlan_sg_rule_missing(self):
        port = self._build_port(FAKE_PORT_1)
        port['network_type'] = p_const.TYPE_VXLAN
        ports = [port]
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_types = [p_const.TYPE_VXLAN]
        self.agent.local_vlan_map = {}
        self.agent.devices_to_filter = set()
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with mock.patch.object(self.agent, '_provision_local_vlan'
                               ) as mock_prov_local_vlan, \
                mock.patch.object(self.agent.sg_agent,
                                  'add_devices_to_filter'
                                  ) as mock_add_devices_fn, \
                mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'
                                  ) as mock_sg_update_fn, \
                mock.patch.object(self.agent.sg_agent, 'expand_sg_rules',
                                  return_value=FAKE_SG_RULES_MISSING
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.agent.plugin_rpc, 'update_device_up'
                                  ) as mock_update_device_up, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=mock.MagicMock())
            self.assertTrue(mock_prov_local_vlan.called)
            self.assertTrue(mock_logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertIn(FAKE_PORT_1, self.agent.devices_to_filter)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertFalse(mock_sg_update_fn.called)
            self.assertTrue(mock_expand_sg_rules.called)
            self.assertTrue(mock_update_device_up.called)

    def test_device_create_hosted_vm_create_port_exception(self):
        ports = [self._build_port(FAKE_PORT_1)]
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().create_port = mock.Mock(
            side_effect=Exception())
        with mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                               ), \
                mock.patch.object(self.agent, '_provision_local_vlan'
                                  ), \
                mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'
                                  ) as mock_sg_update_fn, \
                mock.patch.object(self.agent.sg_agent, 'expand_sg_rules',
                                  return_value=FAKE_SG_RULES
                                  ) as mock_expand_sg_rules, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug, \
                mock.patch.object(self.LOG, 'exception') as mock_log_excep:
            self.assertRaises(
                error.OVSvAppNeutronAgentError,
                self.agent.device_create,
                FAKE_CONTEXT, device=DEVICE,
                ports=ports, sg_rules=mock.MagicMock())
            self.assertTrue(mock_logger_debug.called)
            self.assertNotIn(FAKE_PORT_1, self.agent.cluster_other_ports)
            self.assertIn(FAKE_PORT_1, self.agent.cluster_host_ports)
            self.assertFalse(mock_sg_update_fn.called)
            self.assertTrue(mock_expand_sg_rules.called)
            self.assertTrue(mock_log_excep.called)

    def test_port_update_admin_state_up(self):
        port = self._build_port(FAKE_PORT_1)
        self.agent.ports_dict[port['id']] = self.agent._build_port_info(
            port)
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.cluster_host_ports = set([port['id']])
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        updated_port = self._build_update_port(FAKE_PORT_1)
        updated_port['admin_state_up'] = True
        self.devices_up_list = []
        neutron_port = {'port': updated_port,
                        'segmentation_id': port['segmentation_id']}
        with mock.patch.object(self.LOG, 'exception'
                               ) as mock_log_exception, \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.port_update(FAKE_CONTEXT, **neutron_port)
            self.assertEqual(neutron_port['port']['admin_state_up'],
                             self.agent.ports_dict[port['id']].
                             admin_state_up)
            self.assertEqual([FAKE_PORT_1], self.agent.devices_up_list)
            self.assertFalse(mock_log_exception.called)
            self.assertTrue(mock_logger_debug.called)

    def test_device_update_maintenance_mode(self):
        kwargs = {'device_data': {'ovsvapp_agent': 'fake_agent_host_1',
                                  'esx_host_name': FAKE_HOST_1,
                                  'assigned_agent_host': FAKE_HOST_2}}
        self.agent.hostname = FAKE_HOST_2
        self.agent.esx_maintenance_mode = True
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().session = "fake_session"
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.vcenter_id = FAKE_VCENTER
        with mock.patch.object(resource_util,
                               "get_vm_mor_by_name",
                               return_value="vm_mor") as vm_mor_by_name, \
                mock.patch.object(resource_util,
                                  "get_host_mor_by_name",
                                  return_value="host_mor"
                                  ) as host_mor_by_name, \
                mock.patch.object(resource_util,
                                  "set_vm_poweroff") as power_off, \
                mock.patch.object(resource_util,
                                  "set_host_into_maintenance_mode"
                                  ) as maintenance_mode, \
                mock.patch.object(resource_util,
                                  "set_host_into_shutdown_mode"
                                  ) as shutdown_mode, \
                mock.patch.object(self.agent.ovsvapp_rpc,
                                  "update_cluster_lock") as cluster_lock, \
                mock.patch.object(self.LOG, 'exception') as log_exception, \
                mock.patch.object(time, 'sleep'):
            self.agent.device_update(FAKE_CONTEXT, **kwargs)
            self.assertTrue(vm_mor_by_name.called)
            self.assertTrue(host_mor_by_name.called)
            self.assertTrue(power_off.called)
            self.assertTrue(maintenance_mode.called)
            self.assertFalse(shutdown_mode.called)
            self.assertTrue(cluster_lock.called)
            cluster_lock.assert_called_with(self.agent.context,
                                            cluster_id=self.agent.cluster_id,
                                            vcenter_id=self.agent.vcenter_id,
                                            success=True)
            self.assertFalse(log_exception.called)

    def test_device_update_shutdown_mode(self):
        kwargs = {'device_data': {'ovsvapp_agent': 'fake_agent_host_1',
                                  'esx_host_name': FAKE_HOST_1,
                                  'assigned_agent_host': FAKE_HOST_2}}
        self.agent.hostname = FAKE_HOST_2
        self.agent.esx_maintenance_mode = False
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().session = "fake_session"
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.vcenter_id = FAKE_VCENTER
        with mock.patch.object(resource_util,
                               "get_vm_mor_by_name",
                               return_value="vm_mor") as vm_mor_by_name, \
                mock.patch.object(resource_util,
                                  "get_host_mor_by_name",
                                  return_value="host_mor"
                                  ) as host_mor_by_name, \
                mock.patch.object(resource_util,
                                  "set_vm_poweroff") as power_off, \
                mock.patch.object(resource_util,
                                  "set_host_into_maintenance_mode"
                                  ) as maintenance_mode, \
                mock.patch.object(resource_util,
                                  "set_host_into_shutdown_mode"
                                  ) as shutdown_mode, \
                mock.patch.object(self.agent.ovsvapp_rpc,
                                  "update_cluster_lock") as cluster_lock, \
                mock.patch.object(self.LOG, 'exception') as log_exception, \
                mock.patch.object(time, 'sleep'):
            self.agent.device_update(FAKE_CONTEXT, **kwargs)
            self.assertTrue(vm_mor_by_name.called)
            self.assertTrue(host_mor_by_name.called)
            self.assertFalse(power_off.called)
            self.assertFalse(maintenance_mode.called)
            self.assertTrue(shutdown_mode.called)
            self.assertTrue(cluster_lock.called)
            cluster_lock.assert_called_with(self.agent.context,
                                            cluster_id=self.agent.cluster_id,
                                            vcenter_id=self.agent.vcenter_id,
                                            success=True)
            self.assertFalse(log_exception.called)

    def test_device_update_ovsvapp_alreadly_powered_off(self):
        kwargs = {'device_data': {'ovsvapp_agent': 'fake_agent_host_1',
                                  'esx_host_name': FAKE_HOST_1,
                                  'assigned_agent_host': FAKE_HOST_2}}
        self.agent.hostname = FAKE_HOST_2
        self.agent.esx_maintenance_mode = True
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().session = "fake_session"
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.vcenter_id = FAKE_VCENTER
        with mock.patch.object(resource_util,
                               "get_vm_mor_by_name",
                               return_value="vm_mor") as vm_mor_by_name, \
                mock.patch.object(resource_util,
                                  "get_host_mor_by_name",
                                  return_value="host_mor"
                                  ) as host_mor_by_name, \
                mock.patch.object(resource_util,
                                  "set_vm_poweroff",
                                  side_effect=Exception()) as power_off, \
                mock.patch.object(resource_util,
                                  "set_host_into_maintenance_mode"
                                  ) as maintenance_mode, \
                mock.patch.object(resource_util,
                                  "set_host_into_shutdown_mode"
                                  ) as shutdown_mode, \
                mock.patch.object(self.agent.ovsvapp_rpc,
                                  "update_cluster_lock") as cluster_lock, \
                mock.patch.object(self.LOG, 'exception') as log_exception, \
                mock.patch.object(time, 'sleep'):
            self.agent.device_update(FAKE_CONTEXT, **kwargs)
            self.assertTrue(vm_mor_by_name.called)
            self.assertTrue(host_mor_by_name.called)
            self.assertTrue(power_off.called)
            self.assertTrue(maintenance_mode.called)
            self.assertFalse(shutdown_mode.called)
            self.assertTrue(cluster_lock.called)
            cluster_lock.assert_called_with(self.agent.context,
                                            cluster_id=self.agent.cluster_id,
                                            vcenter_id=self.agent.vcenter_id,
                                            success=True)
            self.assertTrue(log_exception.called)

    def test_device_update_maintenance_mode_exception(self):
        kwargs = {'device_data': {'ovsvapp_agent': 'fake_agent_host_1',
                                  'esx_host_name': FAKE_HOST_1,
                                  'assigned_agent_host': FAKE_HOST_2}}
        self.agent.hostname = FAKE_HOST_2
        self.agent.esx_maintenance_mode = True
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().session = "fake_session"
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.vcenter_id = FAKE_VCENTER
        with mock.patch.object(resource_util,
                               "get_vm_mor_by_name",
                               return_value="vm_mor") as vm_mor_by_name, \
                mock.patch.object(resource_util,
                                  "get_host_mor_by_name",
                                  return_value="host_mor"
                                  ) as host_mor_by_name, \
                mock.patch.object(resource_util,
                                  "set_vm_poweroff",
                                  side_effect=Exception()) as power_off, \
                mock.patch.object(resource_util,
                                  "set_host_into_maintenance_mode",
                                  side_effect=Exception()
                                  ) as maintenance_mode, \
                mock.patch.object(resource_util,
                                  "set_host_into_shutdown_mode"
                                  ) as shutdown_mode, \
                mock.patch.object(self.agent.ovsvapp_rpc,
                                  "update_cluster_lock") as cluster_lock, \
                mock.patch.object(self.LOG, 'exception') as log_exception, \
                mock.patch.object(time, 'sleep') as time_sleep:
            self.agent.device_update(FAKE_CONTEXT, **kwargs)
            self.assertTrue(vm_mor_by_name.called)
            self.assertTrue(host_mor_by_name.called)
            self.assertTrue(power_off.called)
            self.assertTrue(maintenance_mode.called)
            self.assertFalse(shutdown_mode.called)
            self.assertTrue(cluster_lock.called)
            cluster_lock.assert_called_with(self.agent.context,
                                            cluster_id=self.agent.cluster_id,
                                            vcenter_id=self.agent.vcenter_id,
                                            success=False)
            self.assertTrue(log_exception.called)
            self.assertTrue(time_sleep.called)

    def test_enhanced_sg_provider_updated(self):
        kwargs = {'network_id': NETWORK_ID}
        with mock.patch.object(self.LOG, 'info') as log_info, \
                mock.patch.object(self.agent.sg_agent, "sg_provider_updated"
                                  ) as mock_sg_provider_updated:
            self.agent.enhanced_sg_provider_updated(FAKE_CONTEXT, **kwargs)
            self.assertTrue(log_info.called)
            mock_sg_provider_updated.assert_called_with(NETWORK_ID)

    def test_device_create_hosted_vm_vlan_multiple_physnet(self):
        port1 = self._build_port(FAKE_PORT_1)
        port2 = self._build_port(FAKE_PORT_2)
        port2['physical_network'] = "physnet2"
        port2['segmentation_id'] = "2005"
        port2['network_id'] = "fake_net2"
        ports = [port1, port2]
        self._build_phys_brs(port1)
        self._build_phys_brs(port2)
        self.agent.phys_ofports = {}
        self.agent.phys_ofports[port1['physical_network']] = 4
        self.agent.phys_ofports[port2['physical_network']] = 5
        self.agent.vcenter_id = FAKE_VCENTER
        self.agent.cluster_id = FAKE_CLUSTER_1
        self.agent.cluster_moid = FAKE_CLUSTER_MOID
        self.agent.esx_hostname = FAKE_HOST_1
        self.agent.tenant_network_types = [p_const.TYPE_VLAN]
        self.agent.devices_up_list = []
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.int_br = mock.Mock()
        self.agent.patch_sec_ofport = 1
        self.agent.int_ofports = {'physnet1': 2, 'physnet2': 3}
        with mock.patch.object(self.agent.sg_agent, 'add_devices_to_filter'
                               ) as mock_add_devices_fn, \
                mock.patch.object(self.agent.sg_agent, 'ovsvapp_sg_update'
                                  ), \
                mock.patch.object(self.agent.int_br, 'provision_local_vlan'
                                  ) as mock_prov_local_vlan, \
                mock.patch.object(self.agent.sg_agent, 'expand_sg_rules',
                                  return_value=FAKE_SG_RULES_MULTI_PORTS
                                  ), \
                mock.patch.object(self.LOG, 'debug') as mock_logger_debug:
            self.agent.device_create(FAKE_CONTEXT,
                                     device=DEVICE,
                                     ports=ports,
                                     sg_rules=mock.MagicMock())
            self.assertTrue(mock_logger_debug.called)
            self.assertEqual([FAKE_PORT_1, FAKE_PORT_2],
                             self.agent.devices_up_list)
            mock_add_devices_fn.assert_called_with(ports)
            self.assertTrue(mock_prov_local_vlan.called)
            mock_prov_local_vlan.assert_any_call(
                port1['network_type'],
                port1['lvid'],
                port1['segmentation_id'],
                self.agent.patch_sec_ofport,
                self.agent.int_ofports['physnet1'], None)
            mock_prov_local_vlan.assert_any_call(
                port2['network_type'],
                port2['lvid'],
                port2['segmentation_id'],
                self.agent.patch_sec_ofport,
                self.agent.int_ofports['physnet2'], None)
