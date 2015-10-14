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
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_dvr_neutron_agent
from neutron.plugins.ml2.drivers.openvswitch.agent.ovs_neutron_agent\
    import LocalVLANMapping

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


class VifPort(object):
    def __init__(self, port_name, ofport, vif_id, vif_mac, switch):
        self.port_name = port_name
        self.ofport = ofport
        self.vif_id = vif_id
        self.vif_mac = vif_mac
        self.switch = switch

    def __str__(self):
        return ("iface-id=" + self.vif_id + ", vif_mac=" +
                self.vif_mac + ", port_name=" + self.port_name +
                ", ofport=" + str(self.ofport) + ", bridge_name=" +
                self.switch.br_name)


class SamplePort(object):
    def __init__(self, port_uuid, mac_address=None, pg_id=None):
        self.port_uuid = port_uuid
        self.mac_address = mac_address
        self.pg_id = pg_id


class SamplePortUIDMac(object):
    def __init__(self, port_uuid, mac_address):
        self.port_uuid = port_uuid
        self.mac_address = mac_address


class TestOVSvAppDvrAgent(base.TestCase):

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
                'OVSvAppAgent._init_ovs_flows')
    @mock.patch('networking_vsphere.drivers.ovs_firewall.OVSFirewallDriver.'
                'check_ovs_firewall_restart')
    @mock.patch('networking_vsphere.drivers.ovs_firewall.'
                'OVSFirewallDriver.setup_base_flows')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.create')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.set_secure_mode')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.get_port_ofport')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.bridge_exists')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.remove_all_flows')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.delete_port')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.add_patch_port')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.add_flow')
    @mock.patch('neutron.agent.common.ovs_lib.BaseOVS.get_bridges')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.get_vif_ports')
    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.get_ports_attributes')
    @mock.patch('neutron.plugins.ml2.drivers.openvswitch.agent.'
                'ovs_neutron_agent.OVSNeutronAgent.setup_ancillary_bridges')
    def setUp(self,
              mock_setup_ancillary_bridges,
              mock_get_port_attributes,
              mock_get_vif_ports,
              mock_get_bridges,
              mock_add_flow,
              mock_add_patch_port,
              mock_delete_port,
              mock_remove_all_flows,
              mock_bridge_exists,
              mock_get_port_ofport,
              mock_set_secure_mode, mock_create_ovs_bridge,
              mock_setup_base_flows, mock_check_ovs_firewall_restart,
              mock_init_ovs_flows,
              mock_check_ovsvapp_agent_restart,
              mock_setup_integration_br, mock_create_consumers,
              mock_get_admin_context_without_session, mock_ovsvapp_pluginapi,
              mock_plugin_report_stateapi, mock_securitygroup_server_rpcapi,
              mock_rpc_pluginapi, mock_setup_logging, mock_init):
        super(TestOVSvAppDvrAgent, self).setUp()
        cfg.CONF.set_override('security_bridge_mapping',
                              "fake_sec_br:fake_if", 'SECURITYGROUP')
        mock_check_ovsvapp_agent_restart.return_value = False
        mock_get_port_ofport.return_value = 5
        mock_bridge_exists.return_value = True
        mock_add_patch_port.return_value = mock.MagicMock()
        mock_get_bridges.return_value = mock.MagicMock()
        self.agent = ovsvapp_agent.OVSvAppAgent()
        self.agent.run_refresh_firewall_loop = False
        self.LOG = ovsvapp_agent.LOG
        self.agent.monitor_log = logging.getLogger('monitor')

        self.agent.phys_brs = mock.MagicMock()

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
                'device_id': FAKE_DEVICE_ID,
                'port_name': port
                }
        port.port_name = port
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

    def test__add_to_untagged_devices(self):
        port = VifPort(FAKE_PORT_1, mock.Mock(), mock.Mock(),
                       mock.Mock(), 'br-int')
        self.agent._add_to_untagged_devices(port, NETWORK_ID)
        self.assertIn(port.port_name,
                      self.agent.list_of_untagged_devices.keys())

    @mock.patch('networking_vsphere.agent.ovsvapp_dvr_agent.'
                'OVSvAppDvrAgent.process_port_info')
    def test__collect_port_info(self, mocked_function_call):
        start = mock.Mock()
        polling_manager = mock.Mock()
        ovs_restarted = mock.Mock()
        updated_ports_copy = mock.Mock()
        self.agent.current_ports = mock.Mock()
        self.agent.current_ancillary_ports = mock.Mock()
        _consecutive_resyncs = mock.Mock()
        self.agent.consecutive_resyncs = _consecutive_resyncs
        _ports_not_ready_yet = mock.Mock()
        self.agent.ports_not_ready_yet = _ports_not_ready_yet
        self.agent.failed_devices = mock.Mock()
        self.agent.failed_ancillary_devices = mock.Mock()
        _port_info = mock.Mock()
        _ancillary_port_info = mock.Mock()
        mocked_function_call.return_value = (_port_info, _ancillary_port_info,
                                             mock.Mock(), mock.Mock())
        self.agent._collect_port_info(start, polling_manager,
                                      ovs_restarted, updated_ports_copy)
        mocked_function_call.assert_called_once_with(
            start,
            polling_manager,
            self.agent.sync,
            ovs_restarted,
            self.agent.current_ports,
            self.agent.current_ancillary_ports,
            updated_ports_copy,
            _consecutive_resyncs,
            _ports_not_ready_yet,
            self.agent.failed_devices,
            self.agent.failed_ancillary_devices)

    @mock.patch('neutron.agent.common.ovs_lib.OVSBridge.get_vif_port_by_id')
    @mock.patch('neutron.plugins.ml2.drivers.openvswitch.agent.'
                'ovs_neutron_agent.OVSNeutronAgent._clean_network_ports')
    @mock.patch('neutron.agent.l2.extensions.manager.AgentExtensionsManager.'
                'delete_port')
    @mock.patch('neutron.plugins.ml2.drivers.openvswitch.agent.'
                'ovs_neutron_agent.OVSNeutronAgent.port_dead')
    @mock.patch('networking_vsphere.agent.ovsvapp_dvr_agent.'
                'OVSvAppDvrAgent.port_unbound')
    def test__delete_and_unbind_vif_port(self, mocke_port_unbound,
                                         mocked_port_dead,
                                         mocked_delete_port,
                                         mocked_clean_network_ports,
                                         mocked_get_vif_ports_by_id,):
        mocked_of_port = mock.Mock()
        mocked_vif_id = mock.Mock()
        mocked_switch = mock.Mock()
        mocked_vif_mac = mock.Mock()
        mocked_port_id = mock.Mock()
        port = VifPort(FAKE_PORT_1, mocked_of_port, mocked_vif_id,
                       mocked_vif_mac, mocked_switch)
        mocked_get_vif_ports_by_id.return_value = port

        self.agent._add_to_untagged_devices(port, NETWORK_ID)
        self.assertIn(port.port_name,
                      self.agent.list_of_untagged_devices.keys())

        self.agent._delete_and_unbind_vif_port(mocked_port_id)

        mocked_get_vif_ports_by_id.assert_called_once_with(mocked_port_id)
        self.assertNotIn(port.port_name,
                         self.agent.list_of_untagged_devices.keys())
        mocked_clean_network_ports.assert_called_once_with(mocked_port_id)
        mocked_delete_port.has_calls()
        mocked_port_dead.called_once_with(port)
        mocke_port_unbound.assert_called_once_with(mocked_port_id)

    @ mock.patch('neutron.plugins.ml2.drivers.openvswitch.agent.'
                 'ovs_dvr_neutron_agent.OVSDVRNeutronAgent.bind_port_to_dvr')
    def test_port_bound(self, mocked_bind_port_to_dvr):
        mocked_of_port = mock.Mock()
        mocked_vif_id = mock.Mock()
        mocked_switch = mock.Mock()
        mocked_vif_mac = mock.Mock()
        mocked_port_id = mock.Mock()
        mocked_vlan = mock.Mock()
        mocked_network_type = mock.Mock()
        mocked_physical_network = mock.Mock()
        mocked_segmentation_id = mock.Mock()
        mocked_fixed_ips = mock.Mock()
        mocked_device_owner = mock.Mock()
        port = VifPort(FAKE_PORT_1, mocked_of_port, mocked_vif_id,
                       mocked_vif_mac, mocked_switch)
        lvm = LocalVLANMapping(mocked_vlan, mocked_network_type,
                               mocked_physical_network,
                               mocked_segmentation_id,
                               {})
        self.agent._add_to_untagged_devices(port, NETWORK_ID)
        self.agent.local_vlan_map[NETWORK_ID] = lvm
        self.agent.port_bound(port, NETWORK_ID, mocked_network_type,
                              mocked_physical_network, mocked_segmentation_id,
                              mocked_fixed_ips, mocked_device_owner, False)

        self.assertNotIn(port.port_name,
                         self.agent.list_of_untagged_devices.keys())
        mocked_bind_port_to_dvr.assert_called_once_with(port, lvm,
                                                        mocked_fixed_ips,
                                                        mocked_device_owner)

    @mock.patch('neutron.plugins.ml2.drivers.openvswitch.agent.'
                'ovs_dvr_neutron_agent.OVSDVRNeutronAgent.'
                'unbind_port_from_dvr')
    def test_port_unbound(self, mocked_unbind_port_from_dvr):
        mocked_of_port = mock.Mock()
        mocked_vif_id = mock.Mock()
        mocked_switch = mock.Mock()
        mocked_vif_mac = mock.Mock()
        mocked_vlan = mock.Mock()
        mocked_network_type = mock.Mock()
        mocked_physical_network = mock.Mock()
        mocked_segmentation_id = mock.Mock()
        port = VifPort(FAKE_PORT_1, mocked_of_port, mocked_vif_id,
                       mocked_vif_mac, mocked_switch)
        lvm = LocalVLANMapping(mocked_vlan, mocked_network_type,
                               mocked_physical_network,
                               mocked_segmentation_id,
                               {mocked_vif_id: port})
        self.assertIn(mocked_vif_id, lvm.vif_ports)
        self.agent.local_vlan_map[NETWORK_ID] = lvm
        self.agent.port_unbound(mocked_vif_id, NETWORK_ID)
        mocked_unbind_port_from_dvr.assert_called_once_with(port, lvm)
        new_lvm = self.agent.local_vlan_map[NETWORK_ID]
        self.assertNotIn(mocked_vif_id, new_lvm.vif_ports)





