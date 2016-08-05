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

import logging
import threading
import time
import uuid

import eventlet
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_service import loopingcall
import six

from neutron.agent.common import ovs_lib
from neutron.agent import rpc as agent_rpc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron import context
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils as p_utils
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants as ovs_const  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent as ovs_agent  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent import vlanmanager

from networking_vsphere._i18n import _, _LE, _LI, _LW
from networking_vsphere.agent import agent
from networking_vsphere.agent import ovsvapp_sg_agent as sgagent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.common import error
from networking_vsphere.common import model
from networking_vsphere.common import utils
from networking_vsphere.monitor import monitor
from networking_vsphere.utils import ovs_bridge_util as ovsvapp_br
from networking_vsphere.utils import resource_util

LOG = log.getLogger(__name__)
CONF = cfg.CONF
UINT64_BITMASK = (1 << 64) - 1
MAX_RETRY_COUNT = 3
RETRY_DELAY = 2

# To ensure thread safety for the shared variables
# ports_dict, devices_to_filter,
# we use this per-thread recursive lock i.e., ovsvapplock
ovsvapplock = threading.RLock()
ovsvapp_l2pop_lock = threading.RLock()


class PortInfo(object):
    def __init__(self, port_id, vlanid, mac_addr, sec_gps,
                 admin_state_up, network_id, vm_uuid,
                 phys_net, network_type):
        self.port_id = port_id
        self.vlanid = vlanid
        self.mac_addr = mac_addr
        self.sec_gps = sec_gps
        self.admin_state_up = admin_state_up
        self.network_id = network_id
        self.vm_uuid = vm_uuid
        self.phys_net = phys_net
        self.network_type = network_type


class OVSvAppAgent(agent.Agent, ovs_agent.OVSNeutronAgent):

    """OVSvApp Agent."""

    def __init__(self):
        agent.Agent.__init__(self)
        self.conf = cfg.CONF
        self.esx_hostname = CONF.VMWARE.esx_hostname
        self.vcenter_id = CONF.VMWARE.vcenter_id
        self.monitoring_ip = CONF.OVSVAPP.monitoring_ip
        self.esx_maintenance_mode = CONF.VMWARE.esx_maintenance_mode
        if not self.vcenter_id:
            self.vcenter_id = CONF.VMWARE.vcenter_ip
        self.cluster_moid = None  # Cluster domain ID.
        self.cluster_dvs_info = (CONF.VMWARE.cluster_dvs_mapping)[0].split(":")
        self.cluster_id = self.cluster_dvs_info[0]  # Datacenter/host/cluster.
        self.ports_dict = {}
        self.vlan_manager = vlanmanager.LocalVlanManager()
        self.vnic_info = {}
        self.phys_brs = {}
        self.devices_to_filter = set()
        self.cluster_host_ports = set()
        self.cluster_other_ports = set()
        self.ports_to_bind = set()
        self.devices_up_list = list()
        self.devices_down_list = list()
        self.run_update_devices_loop = True
        self.ovsvapp_mitigation_required = False
        self.refresh_firewall_required = False
        self._pool = None
        self.run_check_for_updates = True
        self.use_call = True
        self.hostname = cfg.CONF.host
        self.tenant_network_types = CONF.OVSVAPP.tenant_network_types
        self.l2_pop = False
        self.arp_responder_enabled = False
        self.tun_br_ofports = {p_const.TYPE_VXLAN: {}}
        self.polling_interval = CONF.OVSVAPP.polling_interval
        self.vxlan_udp_port = CONF.OVSVAPP.vxlan_udp_port
        self.dont_fragment = CONF.OVSVAPP.dont_fragment
        self.local_ip = CONF.OVSVAPP.local_ip
        self.patch_tun_ofport = ovs_const.OFPORT_INVALID
        self.patch_int_ofport = ovs_const.OFPORT_INVALID
        # TODO(romilg): Add a config check for all configurable options.
        # Examples: bridge_mappings, tunnel_types, tenant_network_type,
        # cluster_dvs_ampping.
        try:
            self.bridge_mappings = n_utils.parse_mappings(
                CONF.OVSVAPP.bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)
        self.tunnel_types = CONF.OVSVAPP.tunnel_types
        self.agent_state = {
            'binary': 'ovsvapp-agent',
            'host': self.hostname,
            'topic': topics.AGENT,
            'configurations': {'bridge_mappings': self.bridge_mappings,
                               'tunnel_types': self.tunnel_types,
                               'cluster_id': self.cluster_id,
                               'vcenter_id': self.vcenter_id,
                               'esx_host_name': self.esx_hostname,
                               'monitoring_ip': self.monitoring_ip},
            'agent_type': ovsvapp_const.AGENT_TYPE_OVSVAPP,
            'start_flag': True}
        self.veth_mtu = CONF.OVSVAPP.veth_mtu
        self.use_veth_interconnection = False
        self.enable_tunneling = False
        self.tun_br = None
        self.tunnel_csum = CONF.OVSVAPP.tunnel_csum
        bridge_classes = {'br_int': ovsvapp_br.OVSvAppIntegrationBridge,
                          'br_phys': ovsvapp_br.OVSvAppPhysicalBridge,
                          'br_tun': ovsvapp_br.OVSvAppTunnelBridge}
        self.br_int_cls = bridge_classes['br_int']
        self.br_phys_cls = bridge_classes['br_phys']
        self.br_tun_cls = bridge_classes['br_tun']
        self.int_br = self.br_int_cls(CONF.OVSVAPP.integration_bridge)
        self.firewall_driver = CONF.SECURITYGROUP.ovsvapp_firewall_driver
        self.agent_uuid_stamp = uuid.uuid4().int & UINT64_BITMASK
        self.ovsvapp_agent_restarted = False
        if not self.check_ovsvapp_agent_restart():
            self.setup_integration_br()
            LOG.info(_LI("Integration bridge successfully setup."))
            if "OVSFirewallDriver" in self.firewall_driver:
                self.setup_security_br()
        else:
            LOG.info(_LI("Agent has undergone some maintenance - "
                         "Attempting to recover the state of OVS bridges."))
            self.check_integration_br()
            if "OVSFirewallDriver" in self.firewall_driver:
                self.recover_security_br()
            self.ovsvapp_agent_restarted = True
        self.setup_ovs_bridges()
        self.setup_rpc()
        defer_apply = CONF.SECURITYGROUP.defer_apply
        self.monitor_log = self.initiate_monitor_log()
        if self.monitor_log:
            self.monitor_log.warning(_LW("ovs: pending"))
        self.sg_agent = sgagent.OVSvAppSecurityGroupAgent(self.context,
                                                          self.ovsvapp_sg_rpc,
                                                          defer_apply)
        if self.monitor_log:
            self.monitor_log.info(_LI("ovs: ok"))

    def initiate_monitor_log(self):
        try:
            logger = logging.getLogger('monitor')
            logger.addHandler(logging.FileHandler(monitor.LOG_FILE_PATH))
            return logger
        except Exception:
            LOG.error(_LE("Could not get handle for %s."),
                      monitor.LOG_FILE_PATH)

    def check_ovsvapp_agent_restart(self):
        # Check for the canary flow OVS Neutron Agent adds a canary table flow
        # at the start. we can use this to check if OVSvApp Agent restarted.
        if not self.int_br.bridge_exists(CONF.OVSVAPP.integration_bridge):
            return False
        canary_flow = self.int_br.dump_flows_for_table(ovs_const.CANARY_TABLE)
        retval = False
        if canary_flow:
            canary_flow = '\n'.join(item for item in canary_flow.splitlines()
                                    if 'OFPST_FLOW' not in item)
        if canary_flow != '':
            retval = True
        return retval

    def check_flows_for_mac(self, mac):
        if self.sec_br is not None:
            flows = self.sec_br.dump_flows_for(
                table=0, dl_dst=mac, tp_src=67, tp_dst=68)
            if flows:
                return True
        return False

    def check_integration_br(self):
        """Check if the integration bridge is still existing."""
        if not self.int_br.bridge_exists(CONF.OVSVAPP.integration_bridge):
            LOG.error(_LE("Integration bridge %(bridge)s does not exist. "
                          "Terminating the agent!"),
                      {'bridge': CONF.OVSVAPP.integration_bridge})
            raise SystemExit(1)

    # TODO(sudhakar-gariganti): Refactor setup/recover security bridges
    # by merging into one method with internal if blocks.
    def setup_security_br(self):
        """Setup the security bridge.

        Create the required patch ports and remove all existing flows.
        """
        if not CONF.SECURITYGROUP.security_bridge_mapping:
            LOG.warning(_LW("Security bridge mappings not configured."))
            raise SystemExit(1)
        secbr_list = (CONF.SECURITYGROUP.security_bridge_mapping).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]
        self.sec_br = ovs_lib.OVSBridge(secbr_name)
        if not self.sec_br.bridge_exists(secbr_name):
            LOG.error(_LE("Security bridge does not exist. Terminating the "
                          "agent!"))
            raise SystemExit(1)
        self.sec_br.remove_all_flows()
        self.int_br.delete_port(ovsvapp_const.INT_TO_SEC_PATCH)
        self.sec_br.delete_port(ovsvapp_const.SEC_TO_INT_PATCH)
        self.phy_ofport = self.sec_br.get_port_ofport(secbr_phyname)
        if not self.phy_ofport:
            LOG.error(_LE("Physical bridge patch port not available on "
                          "Security bridge %s. Terminating the "
                          "agent!"), secbr_name)
            raise SystemExit(1)
        # br-sec patch port to br-int.
        patch_sec_int_ofport = self.sec_br.add_patch_port(
            ovsvapp_const.SEC_TO_INT_PATCH, ovsvapp_const.INT_TO_SEC_PATCH)
        # br-int patch port to br-sec.
        self.patch_sec_ofport = self.int_br.add_patch_port(
            ovsvapp_const.INT_TO_SEC_PATCH, ovsvapp_const.SEC_TO_INT_PATCH)
        if int(patch_sec_int_ofport) < 0 or int(self.patch_sec_ofport) < 0:
            LOG.error(_LE("Failed to create OVS patch port. Neutron port "
                          "security cannot be enabled on this agent. "
                          "Terminating the agent!"))
            raise SystemExit(1)

        self.sec_br.add_flow(priority=0, actions="drop")
        LOG.info(_LI("Security bridge successfully setup."))

    def recover_security_br(self):
        """Recover the security bridge.

        This method is helpful to retain the flow rules during agent
        restarts, there by avoiding datapath traffic loss.
        We just populate the agent cache back after the restart and let
        the flows remain.
        """
        if not CONF.SECURITYGROUP.security_bridge_mapping:
            LOG.warning(_LW("Security bridge mappings not configured."))
            raise SystemExit(1)
        secbr_list = (CONF.SECURITYGROUP.security_bridge_mapping).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]
        self.sec_br = ovs_lib.OVSBridge(secbr_name)
        if not self.sec_br.bridge_exists(secbr_name):
            LOG.error(_LE("Security bridge does not exist. Terminating the "
                          "agent!"))
            raise SystemExit(1)
        self.phy_ofport = self.sec_br.get_port_ofport(secbr_phyname)
        if not self.phy_ofport:
            LOG.error(_LE("Physical bridge patch port not available on "
                          "Security bridge %s. Terminating the "
                          "agent!"), secbr_name)
            raise SystemExit(1)
        br_name = self.sec_br.get_bridge_for_iface(
            ovsvapp_const.SEC_TO_INT_PATCH)
        if br_name is not None:
            if br_name != secbr_name:
                br = ovs_lib.OVSBridge(br_name)
                br.delete_port(ovsvapp_const.SEC_TO_INT_PATCH)
                self.sec_br.add_patch_port(
                    ovsvapp_const.SEC_TO_INT_PATCH,
                    ovsvapp_const.INT_TO_SEC_PATCH)
        # br-sec patch port to br-int.
        patch_sec_int_ofport = self.sec_br.get_port_ofport(
            ovsvapp_const.SEC_TO_INT_PATCH)
        # br-int patch port to br-sec.
        self.patch_sec_ofport = self.int_br.get_port_ofport(
            ovsvapp_const.INT_TO_SEC_PATCH)
        if int(patch_sec_int_ofport) < 0 or int(self.patch_sec_ofport) < 0:
            LOG.error(_LE("Failed to find OVS patch port. Cannot have "
                          "Security enabled on this agent. "
                          "Terminating the agent!"))
            raise SystemExit(1)
        LOG.info(_LI("Security bridge successfully recovered."))

    def recover_tunnel_bridge(self):
        """Recover the tunnel bridge."""
        self.patch_tun_ofport = self.int_br.get_port_ofport(
            cfg.CONF.OVS.int_peer_patch_port)
        self.patch_int_ofport = self.tun_br.get_port_ofport(
            cfg.CONF.OVS.tun_peer_patch_port)
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error(_LE("Failed to find OVS tunnel patch port(s). Cannot "
                          "have tunneling enabled on this agent, since this "
                          "version of OVS does not support tunnels or "
                          "patch ports. Agent terminated!"))
            raise SystemExit(1)
        LOG.info(_LI("Tunnel bridge successfully recovered."))

    def recover_physical_bridges(self, bridge_mappings):
        """Recover data from the physical network bridges.

        :param bridge_mappings: map physical network names to bridge names.
        """
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ovs_bridges = (ovs_lib.BaseOVS()).get_bridges()
        for phys_net, bridge in six.iteritems(bridge_mappings):
            LOG.info(_LI("Mapping physical network %(phys_net)s to "
                         "bridge %(bridge)s."), {'phys_net': phys_net,
                                                 'bridge': bridge})
            # setup physical bridge.
            if bridge not in ovs_bridges:
                LOG.error(_LE("Bridge %(bridge)s for physical network "
                              "%(phys_net)s does not exist. Terminating "
                              "the agent!"), {'phys_net': phys_net,
                                              'bridge': bridge})
                raise SystemExit(1)
            br = self.br_phys_cls(bridge)
            # Interconnect physical and integration bridges using veth/patch
            # ports.
            int_if_name = p_utils.get_interface_name(
                bridge, prefix=ovs_const.PEER_INTEGRATION_PREFIX)
            phys_if_name = p_utils.get_interface_name(
                bridge, prefix=ovs_const.PEER_PHYSICAL_PREFIX)
            int_ofport = self.int_br.get_port_ofport(int_if_name)
            phys_ofport = br.get_port_ofport(phys_if_name)
            if int(phys_ofport) < 0 or int(int_ofport) < 0:
                LOG.error(_LE("Patch ports missing for bridge %(bridge)s for "
                              "physical network %(phys_net)s. Agent "
                              "terminated!"), {'phys_net': phys_net,
                                               'bridge': bridge})
                raise SystemExit(1)
            self.int_ofports[phys_net] = int_ofport
            self.phys_ofports[phys_net] = phys_ofport
            eth_name = bridge.split('-').pop()
            eth_ofport = br.get_port_ofport(eth_name)
            self.phys_brs[phys_net] = {}
            self.phys_brs[phys_net]['br'] = br
            self.phys_brs[phys_net]['eth_ofport'] = eth_ofport
        LOG.info(_LI("Physical bridges successfully recovered."))

    def _init_ovs_flows(self, bridge_mappings):
        """Add the integration and physical bridge base flows."""

        self.int_br.delete_flows(in_port=self.patch_sec_ofport)
        for phys_net, bridge in six.iteritems(bridge_mappings):
            self.int_br.delete_flows(
                in_port=self.int_ofports[phys_net])
            br = self.br_phys_cls(bridge)
            eth_name = bridge.split('-').pop()
            eth_ofport = br.get_port_ofport(eth_name)
            br.delete_flows(in_port=self.phys_ofports[phys_net])
            br.delete_flows(in_port=eth_ofport)
            br.add_flow(priority=2,
                        in_port=self.phys_ofports[phys_net],
                        actions="normal")
            br.add_flow(priority=10,
                        proto="rarp",
                        in_port=self.phys_ofports[phys_net],
                        actions="normal")
            # Ingress FLOWs.
            br.add_flow(priority=2,
                        in_port=eth_ofport,
                        actions="normal")
            self.int_br.add_flow(priority=2,
                                 in_port=self.int_ofports[phys_net],
                                 actions="output:%s" % self.patch_sec_ofport)
            self.phys_brs[phys_net] = {}
            self.phys_brs[phys_net]['br'] = br
            self.phys_brs[phys_net]['eth_ofport'] = eth_ofport
        LOG.info(_LI("OVS flows set on physical bridges."))

    def setup_ovs_bridges(self):
        LOG.info(_LI("Network type supported by agent: %s."),
                 self.tenant_network_types)
        if p_const.TYPE_VLAN in self.tenant_network_types:
            if not self.ovsvapp_agent_restarted:
                self.setup_physical_bridges(self.bridge_mappings)
                LOG.info(_LI("Physical bridges successfully setup."))
                self._init_ovs_flows(self.bridge_mappings)
            else:
                self.recover_physical_bridges(self.bridge_mappings)

        if p_const.TYPE_VXLAN in self.tenant_network_types:
            self.enable_tunneling = True
            if not self.local_ip:
                LOG.error(_LE("Tunneling cannot be enabled without a valid "
                              "local_ip."))
                raise SystemExit(1)
            if not self.tun_br:
                self.tun_br = self.br_tun_cls(CONF.OVSVAPP.tunnel_bridge)
            self.agent_state['configurations']['tunneling_ip'] = self.local_ip
            self.agent_state['configurations']['l2_population'] = self.l2_pop
            if not self.ovsvapp_agent_restarted:
                self.setup_tunnel_br(CONF.OVSVAPP.tunnel_bridge)
                self.setup_tunnel_br_flows()
                LOG.info(_LI("Tunnel bridge successfully set."))
            else:
                self.recover_tunnel_bridge()

    def _ofport_set_to_str(self, ofport_set):
        return ",".join(map(str, ofport_set))

    def _get_port_vlan_mapping(self, network_id):
        try:
            obj = self.vlan_manager.get(network_id)
            return obj
        except vlanmanager.MappingNotFound:
            return None

    def _provision_local_vlan(self, port):
        if port['network_type'] == p_const.TYPE_VLAN:
            phys_net = port['physical_network']
            int_ofport = self.int_ofports[phys_net]
            br = self.phys_brs[phys_net]['br']
            eth_ofport = self.phys_brs[phys_net]['eth_ofport']
            self.int_br.provision_local_vlan(port['network_type'],
                                             port['lvid'],
                                             port['segmentation_id'],
                                             self.patch_sec_ofport,
                                             int_ofport, None)
            br.provision_local_vlan(port['lvid'],
                                    port['segmentation_id'],
                                    self.phys_ofports[phys_net],
                                    eth_ofport)
        else:
            ofports = self._ofport_set_to_str(self.tun_br_ofports[
                port['network_type']].values())
            self.int_br.provision_local_vlan(port['network_type'],
                                             port['lvid'],
                                             port['segmentation_id'],
                                             self.patch_sec_ofport,
                                             None,
                                             self.patch_tun_ofport)
            self.tun_br.provision_local_vlan(port['lvid'],
                                             port['segmentation_id'],
                                             ofports)

    def _reclaim_local_vlan(self, lvm):
        if lvm.network_type == p_const.TYPE_VLAN:
            phys_net = lvm.physical_network
            int_ofport = self.int_ofports[phys_net]
            self.int_br.reclaim_local_vlan(lvm.network_type,
                                           lvm.segmentation_id,
                                           lvm.vlan,
                                           int_ofport,
                                           self.patch_sec_ofport)
            br = self.phys_brs[lvm.physical_network]['br']
            br.reclaim_local_vlan(lvm.vlan)
        else:
            self.int_br.reclaim_local_vlan(lvm.network_type,
                                           lvm.segmentation_id,
                                           lvm.vlan,
                                           None,
                                           self.patch_sec_ofport)
            self.tun_br.reclaim_local_vlan(lvm.segmentation_id,
                                           lvm.vlan)

    def _populate_lvm(self, port):
        try:
            self.vlan_manager.add(port['network_id'], port['lvid'],
                                  port['network_type'],
                                  port['physical_network'],
                                  port['segmentation_id'])
        except vlanmanager.MappingAlreadyExists:
            LOG.error(_LE("Mapping already exists for network: %s"),
                      port['network_id'])

    def _process_port(self, port):
        ovsvapplock.acquire()
        try:
            self.ports_dict[port['id']] = PortInfo(port['id'],
                                                   port['lvid'],
                                                   port['mac_address'],
                                                   port['security_groups'],
                                                   port['admin_state_up'],
                                                   port['network_id'],
                                                   port['device_id'],
                                                   port['physical_network'],
                                                   port['network_type'])
            self.sg_agent.add_devices_to_filter([port])
            if not self._get_port_vlan_mapping(port['network_id']):
                self._populate_lvm(port)
                self._provision_local_vlan(port)
            if (port['id'] in self.cluster_host_ports and
                    port['network_type'] == p_const.TYPE_VLAN):
                phys_net = port['physical_network']
                br = self.phys_brs[phys_net]['br']
                eth_ofport = self.phys_brs[phys_net]['eth_ofport']
                br.add_drop_flows(port['segmentation_id'],
                                  port['mac_address'],
                                  eth_ofport)
            # Remove this port from vnic_info.
            if port['id'] in self.vnic_info:
                self.vnic_info.pop(port['id'])
            return True
        finally:
            ovsvapplock.release()

    def _update_port_bindings(self):
        ovsvapplock.acquire()
        ports_to_update = self.ports_to_bind
        LOG.info(_LI("update_ports_binding RPC called for %s ports."),
                 len(ports_to_update))
        self.ports_to_bind = set()
        ovsvapplock.release()
        try:
            # Update port binding with the host set as OVSvApp
            # VM's hostname.
            LOG.info(_LI("Invoking update_ports_binding RPC for %s ports:"),
                     ports_to_update)
            success_ports = self.ovsvapp_rpc.update_ports_binding(
                self.context,
                agent_id=self.agent_id,
                ports=ports_to_update,
                host=self.hostname)
            if len(success_ports) == len(ports_to_update):
                LOG.debug("Port binding updates finished successfully.")
            else:
                failed_ports = ports_to_update - set(success_ports)
                LOG.info(_LI("Port binding updates failed for %s ports."
                             "Will be retried in the next cycle."),
                         len(failed_ports))
                ovsvapplock.acquire()
                self.ports_to_bind |= failed_ports
                ovsvapplock.release()
        except Exception as e:
            LOG.exception(_LE("RPC update_ports_binding failed. All ports "
                              "will be retried in the next iteration."))
            ovsvapplock.acquire()
            self.ports_to_bind |= ports_to_update
            ovsvapplock.release()
            raise error.OVSvAppNeutronAgentError(e)

    @property
    def threadpool(self):
        if self._pool is None:
            self._pool = eventlet.GreenPool(ovsvapp_const.THREAD_POOL_SIZE)
        return self._pool

    def _remove_stale_ports_flows(self, stale_ports):
        for port_id in stale_ports:
            if port_id not in self.vnic_info:
                continue
            vnic = self.vnic_info[port_id]
            # Get the vlan id from port group key.
            pg_id = vnic['pg_id']
            mac_addr = vnic['mac_addr']
            vlan = self.net_mgr.get_driver().get_vlanid_for_portgroup_key(
                pg_id)
            if vlan:
                # Delete flows from security bridge.
                self.sg_agent.firewall.remove_stale_port_flows(
                    port_id, mac_addr, vlan)
                # Delete flows on physical bridge.
                # Ports_dict does not have the information about this port.
                # Looping through all physnets is better than collecting
                # this information from vCenter and mapping to physical
                # network. OpenvSwitch does not complain about deleting
                # non existent flows.
                for phys_net in self.phys_brs:
                    br = self.phys_brs[phys_net]['br']
                    br.delete_drop_flows(mac_addr, vlan)
            else:
                LOG.info(_LI("Could not obtain VLAN for port %(port_id)s "
                             "belonging to port group key %(pg_key)s for "
                             "VM %(vm_id)s."), {'port_id': port_id,
                                                'pg_key': pg_id,
                                                'vm_id': vnic['vm_id']})

    def _block_stale_ports(self, stale_ports):
        # Create Common Model Port Object.
        for port_id in stale_ports:
            if port_id not in self.vnic_info:
                continue
            vnic = self.vnic_info[port_id]
            port_model = model.Port(uuid=port_id,
                                    mac_address=vnic['mac_addr'],
                                    vm_id=vnic['vm_id'],
                                    port_status=ovsvapp_const.PORT_STATUS_DOWN)
            self._port_update_status_change(None, port_model)

    def _process_uncached_devices_sublist(self, devices):
        device_list = set()
        try:
            LOG.info(_LI("RPC get_ports_details_list is called with "
                         "port_ids: %s."), devices)
            if self.monitor_log:
                self.monitor_log.warning(_("ovs: pending"))
            ports = self.ovsvapp_rpc.get_ports_details_list(
                self.context, devices, self.agent_id, self.vcenter_id,
                self.cluster_id)
            for port in ports:
                if port and 'port_id' in port.keys():
                    port['id'] = port['port_id']
                    status = self._process_port(port)
                    if status:
                        device_list.add(port['id'])
            if device_list:
                LOG.info(_LI("Going to update firewall for ports: "
                             "%s."), device_list)
                self.sg_agent.refresh_firewall(device_list)
            # Stale VM's ports handling.
            if len(ports) != len(devices):
                # Remove the stale ports from update port bindings list.
                port_ids = set([port['port_id'] for port in ports])
                stale_ports = set(devices) - port_ids
                LOG.debug("Stale ports: %s.", stale_ports)
                self.ports_to_bind = self.ports_to_bind - stale_ports
                # Remove the flows for the port.
                self._remove_stale_ports_flows(stale_ports)
                # Set the port state to "Blocked".
                self._block_stale_ports(stale_ports)
                # Remove entries from vnic_info and firewall.
                with ovsvapplock:
                    for port_id in stale_ports:
                        if port_id in self.vnic_info:
                            self.vnic_info.pop(port_id)
                        self.sg_agent.remove_devices_filter(port_id)
            if self.monitor_log:
                self.monitor_log.info(_LI("ovs: ok"))
        except Exception as e:
            LOG.exception(_LE("RPC get_ports_details_list failed %s."), e)
            # Process the ports again in the next iteration.
            self.devices_to_filter |= set(devices)
            self.refresh_firewall_required = True

    def _process_uncached_devices(self, devices):
        dev_list = list(devices)
        if len(dev_list) > ovsvapp_const.RPC_BATCH_SIZE:
            sublists = ([dev_list[x:x + ovsvapp_const.RPC_BATCH_SIZE]
                        for x in six.moves.range(0, len(dev_list),
                        ovsvapp_const.RPC_BATCH_SIZE)])
        else:
            sublists = [dev_list]
        for dev_ids in sublists:
            LOG.debug("Spawning a thread to process ports - %s.", dev_ids)
            try:
                self.threadpool.spawn_n(self._process_uncached_devices_sublist,
                                        dev_ids)
                eventlet.sleep(0)
            except Exception:
                LOG.exception(_LE("Exception occured while spawning thread "
                                  "to process ports."))

    def _update_firewall(self):
        """Helper method to monitor devices added.

        If devices_to_filter is not empty, we update the OVS firewall
        for those devices.
        """
        try:
            ovsvapplock.acquire()
            devices_to_filter = self.devices_to_filter
            self.devices_to_filter = set()
            self.refresh_firewall_required = False
            device_list = set()
            for device in devices_to_filter:
                if device in self.ports_dict:
                    device_list.add(device)
            uncached_devices = set()
            uncached_devices = devices_to_filter - device_list
        finally:
            ovsvapplock.release()
        if device_list:
            LOG.info(_LI("Going to update firewall for ports: "
                         "%s."), device_list)
            if self.monitor_log:
                self.monitor_log.warning(_("ovs: pending"))
            self.sg_agent.refresh_firewall(device_list)
            if self.monitor_log:
                self.monitor_log.info(_("ovs: ok"))
        if uncached_devices:
            self._process_uncached_devices(uncached_devices)

    def mitigate_ovs_restart(self):
        """Mitigates OpenvSwitch process restarts.

        Method to reset the flows which are lost due to an openvswitch
        process restart. After resetting up all the bridges, we set the
        SG agent's global_refresh_firewall flag to True to bring back all
        the flows related to Tenant VMs.
        """
        try:
            if self.monitor_log:
                self.monitor_log.warning(_LW("ovs: broken"))
            self.setup_integration_br()
            self.setup_security_br()
            if self.enable_tunneling:
                self.setup_tunnel_br(CONF.OVSVAPP.tunnel_bridge)
                self.setup_tunnel_br_flows()
                self.tunnel_sync()
            else:
                self.setup_physical_bridges(self.bridge_mappings)
                self._init_ovs_flows(self.bridge_mappings)
            # TODO(garigant): We need to add the DVR related resets
            # once it is enabled for vApp, similar to what is being
            # done in ovs_neutron_agent.
            ovsvapplock.acquire()
            try:
                self.sg_agent.init_firewall(True)
                self.ports_dict = {}
                self.devices_to_filter |= self.cluster_host_ports
                self.devices_to_filter |= self.cluster_other_ports
                self.refresh_firewall_required = True
            finally:
                ovsvapplock.release()
            if self.monitor_log:
                self.monitor_log.info(_LI("ovs: ok"))
            LOG.info(_LI("Finished resetting the bridges post ovs restart."))
        except Exception:
            LOG.exception(_LE("Exception encountered while mitigating the ovs "
                              "restart."))

    def _check_for_updates(self):
        """Method to handle any updates related to the agent.

        This method is forked as an eventlet thread. The thread will be
        alive as long as run_check_for_updates flag is True.

        Basic purpose of this thread is to handle the cases where
        devices_to_filter, devices_to_refilter and global_refresh_firewall
        are not empty, which inturn mandate a firewall update.

        We also check if there are any port bindings to be updated.

        OpenvSwitch process restart is also handled through this thread.
        """
        ovs_restarted = self.check_ovs_status()
        if ovs_restarted == ovs_const.OVS_DEAD:
            self.ovsvapp_mitigation_required = True
        if ovs_restarted == ovs_const.OVS_RESTARTED or  \
           (self.ovsvapp_mitigation_required and
                ovs_restarted == ovs_const.OVS_NORMAL):
            self.vlan_manager.mapping = {}
            self.ovsvapp_mitigation_required = False
            self.mitigate_ovs_restart()
        # Case where devices_to_filter is having some entries.
        if self.refresh_firewall_required:
            self._update_firewall()
        # Case where sgagent's devices_to_refilter is having some
        # entries or global_refresh_firewall flag is set to True.
        if self.sg_agent.firewall_refresh_needed():
            if self.monitor_log:
                self.monitor_log.warning(_("ovs: pending"))
            LOG.info(_LI("Starting refresh_port_filters."))
            self.sg_agent.refresh_port_filters(
                self.cluster_host_ports, self.cluster_other_ports)
            LOG.info(_LI("Finished refresh_port_filters."))
            if self.monitor_log:
                self.monitor_log.info(_LI("ovs: ok"))
        # Check if there are any pending port bindings to be made.
        if self.ports_to_bind:
            self._update_port_bindings()

    def check_for_updates(self):
        while self.run_check_for_updates:
            self._check_for_updates()
            # TODO(romilg): Use polling_interval like in ovs_neutron_agent.
            time.sleep(2)

    def _update_devices_up(self):
        ovsvapplock.acquire()
        devices_up = self.devices_up_list
        LOG.info(_LI("update_devices_up RPC called for %s ports: "),
                 len(devices_up))
        self.devices_up_list = list()
        ovsvapplock.release()
        if len(devices_up) > ovsvapp_const.RPC_BATCH_SIZE:
            sublists = ([devices_up[x:x + ovsvapp_const.RPC_BATCH_SIZE]
                        for x in six.moves.range(0, len(devices_up),
                        ovsvapp_const.RPC_BATCH_SIZE)])
        else:
            sublists = [devices_up]
        for devices in sublists:
            try:
                LOG.info(_LI("Invoking update_devices_up RPC for %s ports."),
                         devices)
                result = self.ovsvapp_rpc.update_devices_up(
                    self.context,
                    agent_id=self.agent_id,
                    devices=devices,
                    host=self.hostname)
                success_devices = result['devices_up']
                if len(success_devices) == len(devices):
                    LOG.info(_LI("RPC update_devices_up finished"
                                 "successfully."))
                else:
                    failed_devices = result['failed_devices_up']
                    LOG.info(_LI("RPC update_devices_up failed for %s ports."
                                 "Will be retried in the next cycle."),
                             len(failed_devices))
                    ovsvapplock.acquire()
                    self.devices_up_list.extend(failed_devices)
                    ovsvapplock.release()
            except Exception:
                LOG.exception(_LE("RPC update_devices_up failed. All ports "
                                  "will be retried in the next iteration."))
                ovsvapplock.acquire()
                self.devices_up_list.extend(devices)
                ovsvapplock.release()

    def _update_devices_down(self):
        ovsvapplock.acquire()
        devices_down = self.devices_down_list
        LOG.info(_LI("update_devices_down RPC called for %s ports: "),
                 len(devices_down))
        self.devices_down_list = list()
        ovsvapplock.release()
        if len(devices_down) > ovsvapp_const.RPC_BATCH_SIZE:
            sublists = ([devices_down[x:x + ovsvapp_const.RPC_BATCH_SIZE]
                        for x in six.moves.range(0, len(devices_down),
                        ovsvapp_const.RPC_BATCH_SIZE)])
        else:
            sublists = [devices_down]
        for devices in sublists:
            try:
                LOG.info(_LI("Invoking update_devices_down RPC for %s ports."),
                         devices)
                result = self.ovsvapp_rpc.update_devices_down(
                    self.context,
                    agent_id=self.agent_id,
                    devices=devices,
                    host=self.hostname)
                success_devices = result['devices_down']
                if len(success_devices) == len(devices):
                    LOG.info(_LI("RPC update_devices_down finished "
                                 "successfully."))
                else:
                    failed_devices = result['failed_devices_down']
                    LOG.info(_LI("RPC update_devices_down failed for %s ports."
                                 "Will be retried in the next cycle."),
                             len(failed_devices))
                    ovsvapplock.acquire()
                    self.devices_down_list.extend(failed_devices)
                    ovsvapplock.release()
            except Exception:
                LOG.exception(_LE("RPC update_devices_down failed. All ports "
                                  "will be retried in the next iteration."))
                ovsvapplock.acquire()
                self.devices_down_list.extend(devices_down)
                ovsvapplock.release()

    def update_devices_loop(self):
        while self.run_update_devices_loop:
            if self.devices_up_list:
                self._update_devices_up()
            if self.devices_down_list:
                self._update_devices_down()
            time.sleep(5)

    def tunnel_sync_rpc_loop(self):
        """Establishes VXLAN tunnels between tunnel end points."""

        tunnel_sync = True
        while tunnel_sync:
            try:
                start = time.time()
                # Notify the plugin of tunnel IP.
                if self.enable_tunneling and tunnel_sync:
                    LOG.info(_LI("OVSvApp Agent tunnel out of sync with "
                                 "plugin!"))
                    tunnel_sync = self.tunnel_sync()
            except Exception:
                LOG.exception(_LE("Error while synchronizing tunnels."))
                tunnel_sync = True

            # sleep till end of polling interval.
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(("Loop iteration exceeded interval "
                           "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})

    def start(self):
        LOG.info(_LI("Starting OVSvApp Agent."))
        self.set_node_state(True)
        self.setup_report_states()
        t = eventlet.spawn(self.check_for_updates)
        t1 = eventlet.spawn(self.update_devices_loop)
        if p_const.TYPE_VXLAN in self.tenant_network_types:
            # A daemon loop which invokes tunnel_sync_rpc_loop
            # to sync up the tunnels.
            t2 = eventlet.spawn(self.tunnel_sync_rpc_loop)
        t.wait()
        t1.wait()
        if p_const.TYPE_VXLAN in self.tenant_network_types:
            t2.wait()

    def stop(self):
        LOG.info(_LI("Stopping OVSvApp Agent."))
        self.set_node_state(False)
        self.run_check_for_updates = False
        self.run_update_devices_loop = False
        if self.connection:
            self.connection.close()

    def setup_rpc(self):
        # Ensure that the control exchange is set correctly.
        LOG.info(_LI("Started setting up RPC topics and endpoints."))
        self.agent_id = "ovsvapp-agent %s" % self.hostname
        self.topic = topics.AGENT
        self.plugin_rpc = RpcPluginApi()
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.ovsvapp_rpc = OVSvAppPluginApi(ovsvapp_const.OVSVAPP)
        self.ovsvapp_sg_rpc = sgagent.OVSvAppSecurityGroupServerRpcApi(
            ovsvapp_const.OVSVAPP)

        # RPC network init.
        self.context = context.get_admin_context_without_session()
        # Handle updates from service.
        self.endpoints = [self]
        cluster_device_topic = utils.get_cluster_based_topic(
            self.cluster_id, ovsvapp_const.DEVICE)
        # Define the listening consumers for the agent.
        consumers = [
            [topics.PORT, topics.UPDATE],
            [cluster_device_topic, topics.CREATE],
            [cluster_device_topic, topics.UPDATE],
            [cluster_device_topic, topics.DELETE],
            [ovs_const.TUNNEL, topics.UPDATE],
            [topics.SECURITY_GROUP, topics.UPDATE],
            [ovsvapp_const.OVSVAPP + '_' + topics.SECURITY_GROUP,
             topics.UPDATE]
        ]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        LOG.info(_LI("Finished setting up RPC."))

    def _report_state(self):
        """Reporting agent state to neutron server."""

        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        self.use_call)
            self.use_call = False
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Heartbeat failure - Failed reporting state!"))

    def setup_report_states(self):
        """Method to send heartbeats to the neutron server."""

        report_interval = CONF.OVSVAPP.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)
        else:
            LOG.warning(_LW("Report interval is not initialized."
                            "Unable to send heartbeats to Neutron Server."))

    def process_event(self, event):
        """Handles vCenter based events

         VM creation, VM deletion and VM updation.
         """

        try:
            vm = event.src_obj
            host = event.host_name
            if event.event_type == ovsvapp_const.VM_CREATED:
                LOG.info(_LI("Handling event %(event_type)s for %(src_obj)s."),
                         {'event_type': event.event_type,
                          'src_obj': event.src_obj.uuid})
                if not self.cluster_moid:
                    self.cluster_moid = event.cluster_id
                    LOG.info(_LI("Setting the cluster moid: %s."),
                             self.cluster_moid)
                self._notify_device_added(vm, host)
            elif event.event_type == ovsvapp_const.VM_UPDATED:
                LOG.info(_LI("Handling event %(event_type)s for %(src_obj)s."),
                         {'event_type': event.event_type,
                          'src_obj': event.src_obj.uuid})
                self._notify_device_updated(vm, host, event.host_changed)
            elif event.event_type == ovsvapp_const.VM_DELETED:
                LOG.info(_LI("Handling event %(event_type)s for %(src_obj)s."),
                         {'event_type': event.event_type,
                          'src_obj': event.src_obj.uuid})
                self._notify_device_deleted(vm, host)
            else:
                LOG.debug("Ignoring event: %s.", event)
        except Exception as e:
            LOG.error(_LE("This may result in failure of network "
                          "provisioning for %(name)s %(uuid)s."),
                      {'name': event.src_obj.__class__.__name__,
                       'uuid': event.src_obj.uuid})
            LOG.exception(_LE("Cause of failure: %s."), str(e))

    def _add_ports_to_host_ports(self, ports, hosting=True):
        for port_id in ports:
            if hosting:
                if port_id in self.cluster_other_ports:
                    self.cluster_other_ports.remove(port_id)
                self.cluster_host_ports.add(port_id)
            else:
                if port_id in self.cluster_host_ports:
                    self.cluster_host_ports.remove(port_id)
                self.cluster_other_ports.add(port_id)

    def invoke_get_ports_for_device_rpc(self, device):
        retry = True
        iteration = 1
        LOG.info(_LI("Invoking get_ports_for_device RPC for device: "
                     "%s."), device['id'])
        while retry:
            try:
                # Make RPC call to plugin to get port details.
                status = self.ovsvapp_rpc.get_ports_for_device(
                    self.context, device, self.agent_id, self.hostname)
                if status:
                    LOG.info(_LI("Successfully obtained ports details "
                                 "for device %s."), device['id'])
                    retry = False
                else:
                    time.sleep(2)
                    iteration += 1
                    # Stop if we reached 3 iterations.
                    if iteration > 3:
                        retry = False
            except Exception as e:
                LOG.exception(_LE("RPC get_ports_for_device failed "
                                  "for device: %s."), device['id'])
                raise error.OVSvAppNeutronAgentError(e)

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_added(self, vm, host):
        """Handle VM created event."""
        if len(vm.vnics) > 0:
            LOG.debug("Processing for an existing VM %s.", vm.uuid)
            ovsvapplock.acquire()
            for vnic in vm.vnics:
                if not self.check_flows_for_mac(vnic.mac_address):
                    if host == self.esx_hostname:
                        device = {'id': vm.uuid,
                                  'host': host,
                                  'cluster_id': self.cluster_id,
                                  'vcenter': self.vcenter_id}
                        self.invoke_get_ports_for_device_rpc(device)
                else:
                    self.devices_to_filter.add(vnic.port_uuid)
                    self._add_ports_to_host_ports([vnic.port_uuid],
                                                  host == self.esx_hostname)
                    if host == self.esx_hostname:
                        self.ports_to_bind.add(vnic.port_uuid)
                    vnic_info = {'mac_addr': vnic.mac_address,
                                 'pg_id': vnic.pg_id,
                                 'vm_id': vm.uuid}
                    self.vnic_info[vnic.port_uuid] = vnic_info
                    self.refresh_firewall_required = True
            ovsvapplock.release()
        else:
            if host == self.esx_hostname:
                device = {'id': vm.uuid,
                          'host': host,
                          'cluster_id': self.cluster_id,
                          'vcenter': self.vcenter_id}
                self.invoke_get_ports_for_device_rpc(device)

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_updated(self, vm, host, host_changed):
        """Handle VM updated event."""
        try:
            if host == self.esx_hostname:
                self._add_ports_to_host_ports(
                    [vnic.port_uuid for vnic in vm.vnics])
                # host_changed flag being True indicates, that
                # this VM_UPDATED event is because of a vMotion.
                if host_changed:
                    # Bulk migrations result in racing for
                    # update_port_postcommit in the controller-side
                    # default l2pop mech driver. This results in the l2pop
                    # mech driver generating incorrect fdb entries and
                    # it ships them to all other L2Pop enabled nodes
                    # creating havoc with tunnel port allocations/releases
                    # of them.
                    ovsvapp_l2pop_lock.acquire()
                    try:
                        LOG.info(_LI("Invoking update_device_binding RPC for "
                                     "device %s."), vm.uuid)
                        self.ovsvapp_rpc.update_device_binding(
                            self.context,
                            agent_id=self.agent_id,
                            device=vm.uuid,
                            host=self.hostname)
                    except Exception as e:
                        LOG.exception(_LE("Failed to handle VM migration "
                                          "for device: %s."), vm.uuid)
                        raise error.OVSvAppNeutronAgentError(e)
                    finally:
                        ovsvapp_l2pop_lock.release()
                    for vnic in vm.vnics:
                        updated_port = self.ports_dict.get(vnic.port_uuid)
                        if (updated_port and
                           updated_port.network_type == p_const.TYPE_VLAN):
                            # Update the physical bridge drop flows.
                            network_id = updated_port.network_id
                            lvm = self._get_port_vlan_mapping(network_id)
                            segmentation_id = lvm.segmentation_id
                            phys_net = updated_port.phys_net
                            br = self.phys_brs[phys_net]['br']
                            eth_ofport = self.phys_brs[phys_net]['eth_ofport']
                            br.add_drop_flows(segmentation_id,
                                              updated_port.mac_addr,
                                              eth_ofport)
            else:
                for vnic in vm.vnics:
                    if host_changed:
                        updated_port = self.ports_dict.get(vnic.port_uuid)
                        if updated_port:
                            net_type = updated_port.network_type
                            if net_type == p_const.TYPE_VLAN:
                                if vnic.port_uuid in self.cluster_host_ports:
                                    # Delete the physical bridge flows.
                                    network_id = updated_port.network_id
                                    lvm = self._get_port_vlan_mapping(
                                        network_id)
                                    seg_id = lvm.segmentation_id
                                    phys_net = updated_port.phys_net
                                    br = self.phys_brs[phys_net]['br']
                                    br.delete_drop_flows(updated_port.mac_addr,
                                                         seg_id)
                    self._add_ports_to_host_ports([vnic.port_uuid], False)
                    if vnic.port_uuid in self.ports_to_bind:
                        ovsvapplock.acquire()
                        self.ports_to_bind.remove(vnic.port_uuid)
                        ovsvapplock.release()
        except Exception as e:
            LOG.exception(_LE("Failed to handle VM_UPDATED event for VM: "
                              " %s."), vm.uuid)
            raise error.OVSvAppNeutronAgentError(e)

    def _delete_portgroup(self, network_id, network_type):
        network_id = str(network_id) + "-" + self.cluster_moid
        network = model.Network(name=network_id,
                                network_type=network_type)
        retry_count = MAX_RETRY_COUNT
        while retry_count > 0:
            try:
                LOG.debug("Deleting port group from vCenter: %s.", network_id)
                self.net_mgr.get_driver().delete_network(network)
                break
            except Exception as e:
                LOG.exception(_LE("Failed to delete network %s."), network_id)
                retry_count -= 1
                if retry_count == 0:
                    raise error.OVSvAppNeutronAgentError(e)
                time.sleep(RETRY_DELAY)

    def _process_delete_pg_novnic(self, host, vm):
        """Deletes the VLAN port group for a VM without nic."""

        LOG.debug("Deletion of VM with no vnics: %s.", vm.uuid)
        ovsvapplock.acquire()
        try:
            for port_id in self.ports_dict.keys():
                if self.ports_dict[port_id].vm_uuid == vm.uuid:
                    self._process_delete_port(port_id, host)
            self.net_mgr.get_driver().post_delete_vm(vm)
        finally:
            ovsvapplock.release()

    def _process_delete_port(self, port_id, host):
        with ovsvapplock:
            if port_id in self.ports_to_bind:
                self.ports_to_bind.remove(port_id)
            if port_id in self.ports_dict.keys():
                if port_id in self.cluster_host_ports:
                    self.cluster_host_ports.remove(port_id)
                elif port_id in self.cluster_other_ports:
                    self.cluster_other_ports.remove(port_id)
                self.sg_agent.remove_devices_filter(port_id)
                if host == self.esx_hostname:
                    # Delete the physical bridge flows related to this port.
                    del_port = self.ports_dict[port_id]
                    if del_port.network_type == p_const.TYPE_VLAN:
                        phys_net = del_port.phys_net
                        net_id = del_port.network_id
                        vmap = self._get_port_vlan_mapping(net_id)
                        seg_id = None
                        if vmap:
                            seg_id = vmap.segmentation_id
                        br = self.phys_brs[phys_net]['br']
                        br.delete_drop_flows(del_port.mac_addr,
                                             seg_id)
                # Clean up ports_dict for the deleted port.
                self.ports_dict.pop(port_id)
                LOG.debug("Deleted port: %s from ports_dict.", port_id)
            else:
                LOG.warning(_LW("Port id %s is not available in "
                                "ports_dict."), port_id)

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_deleted(self, vm, host):
        """Handle VM deleted event."""
        # When a last VM associated with a given network is deleted
        # then portgroup associated with the network is deleted and hence
        # network_delete RPC call is not consumed by the OVSvApp agent.
        if not vm.vnics:
            LOG.info(_LI("Deletion of VM with no vnics %s."), vm.uuid)
            self._process_delete_pg_novnic(host, vm)
            return

        for vnic in vm.vnics:
            LOG.info(_LI("Deleting port %(port)s with mac address %(mac)s."),
                     {'port': vnic.port_uuid, 'mac': vnic.mac_address})
            if not vnic.port_uuid:
                LOG.warning(_LW("Port id for VM %s not present."), vm.uuid)
            else:
                self._process_delete_port(vnic.port_uuid, host)
                self.net_mgr.get_driver().post_delete_vm(vm)

    @staticmethod
    def _build_port_info(port):
        return PortInfo(port['id'],
                        port['lvid'],
                        port['mac_address'],
                        port['security_groups'],
                        port['admin_state_up'],
                        port['network_id'],
                        port['device_id'],
                        port['physical_network'],
                        port['network_type'])

    def _map_port_to_common_model(self, port_info, local_vlan_id=None):
        """Map the port and network objects to vCenter objects."""

        port_id = port_info.get('id')
        network_id = (str(port_info.get('network_id')) + "-"
                      + self.cluster_moid)
        device_id = port_info.get('device_id')
        mac_address = port_info.get('mac_address')
        port_status = (ovsvapp_const.PORT_STATUS_UP
                       if port_info.get('admin_state_up')
                       else ovsvapp_const.PORT_STATUS_DOWN)

        # Create Common Model Network Object.
        vlan = model.Vlan(vlan_ids=[local_vlan_id])
        network = model.Network(name=network_id,
                                network_type=port_info.get('network_type'),
                                config=model.NetworkConfig(vlan))

        # Create Common Model Port Object.
        port = model.Port(uuid=port_id,
                          name=None,
                          mac_address=mac_address,
                          vm_id=device_id,
                          network_uuid=network_id,
                          port_status=port_status)
        return network, port

    def _create_portgroup(self, port_info, host, local_vlan_id):
        """Create port group based on port information."""
        if host == self.esx_hostname:
            net_id = port_info['network_id']
            pg_name = str(net_id) + "-" + self.cluster_moid
            network, port = self._map_port_to_common_model(port_info,
                                                           local_vlan_id)
            retry_count = MAX_RETRY_COUNT
            LOG.info(_LI("Trying to create port group for network %s."),
                     network.name)
            while retry_count > 0:
                try:
                    self.net_mgr.get_driver().create_port(network, port, None)
                    break
                except Exception as e:
                    exception_str = str(e)
                    if ("The name" and "already exists" in exception_str):
                        pg_vlan_id = (self.net_mgr.get_driver().
                                      get_vlanid_for_port_group(
                                      self.cluster_dvs_info[1],
                                      pg_name))
                        if local_vlan_id != pg_vlan_id:
                            LOG.error(_LE("Local vlan id mismatch."
                                          "Expected local_vlan_id %(lvid)s. "
                                          "Retrieved pg_vlan_id %(pg_vid)s "
                                          "for network %(net_id)s for port "
                                          "%(port_id)s."),
                                      {'pg_vid': pg_vlan_id,
                                       'lvid': local_vlan_id,
                                       'net_id': net_id,
                                       'port_id': port_info['id']})

                        break
                    else:
                        LOG.exception(_LE("Retrying to create portgroup for "
                                      "network: %s."), network.name)
                        retry_count -= 1
                        if retry_count == 0:
                            LOG.exception(_LE("Failed to create port group "
                                              "for network %s after retrying "
                                              "thrice."), network.name)
                            raise error.OVSvAppNeutronAgentError(e)
                        time.sleep(RETRY_DELAY)
            LOG.info(_LI("Finished creating port group for network %s."),
                     network.name)
            return local_vlan_id

    def _check_sg_provider_rule(self, port_rules):
        flag = True
        keys = ['source_port_range_min', 'port_range_max',
                'source_port_range_max', 'port_range_min']
        sg_rules = port_rules['sg_provider_rules']
        for rule in sg_rules:
            for key in keys:
                if key not in rule:
                    flag = False
                    break
            if flag:
                if (rule['source_port_range_min'] == 67 and
                    rule['source_port_range_max'] == 67 and
                    rule['port_range_min'] == 68 and
                        rule['port_range_max'] == 68):
                    return True
        return False

    def _process_create_ports(self, context, ports_list, host,
                              ports_sg_rules):
        try:
            ovsvapplock.acquire()
            valid_ports = []
            missed_provider_rule_ports = set()
            for port in ports_list:
                local_vlan_id = port['lvid']
                net_id = port['network_id']
                self.ports_dict[port['id']] = self._build_port_info(port)
                if not self._get_port_vlan_mapping(net_id):
                    self._populate_lvm(port)
                    # Add to missed provider rule ports list
                    # if sg provider rule is missing in ports_sg_rules.
                    if not self._check_sg_provider_rule(
                        ports_sg_rules[port['id']]):
                        missed_provider_rule_ports.add(port['id'])
                    self._create_portgroup(port, host, local_vlan_id)
                    self._provision_local_vlan(port)
                if (port['id'] in self.cluster_host_ports and
                        port['network_type'] == p_const.TYPE_VLAN):
                    phys_net = port['physical_network']
                    br = self.phys_brs[phys_net]['br']
                    eth_ofport = self.phys_brs[phys_net]['eth_ofport']
                    br.add_drop_flows(port['segmentation_id'],
                                      port['mac_address'],
                                      eth_ofport)
                port['security_group_source_groups'] = (
                    ports_sg_rules[port['id']]['security_group_source_groups'])
                valid_ports.append(port)
        finally:
            ovsvapplock.release()
        if valid_ports:
            self.sg_agent.add_devices_to_filter(valid_ports)
            for port in valid_ports:
                port_id = port['id']
                if port_id in ports_sg_rules:
                    if port_id in missed_provider_rule_ports:
                        LOG.info(_LI("Missing Provider rule for port %s. "
                                     "Will be tried during firewall "
                                     "refresh."), port_id)
                        with ovsvapplock:
                            self.devices_to_filter.add(port_id)
                            self.refresh_firewall_required = True
                    else:
                        self.sg_agent.ovsvapp_sg_update(
                            {port_id: ports_sg_rules[port_id]})
                self._update_device_status(context, port, host)

    def _update_device_status(self, context, port, host):
        if (port['network_type'] == p_const.TYPE_VLAN and
                host == self.esx_hostname):
            with ovsvapplock:
                self.devices_up_list.append(port['id'])
        elif host == self.esx_hostname:
            # All update device calls from the same
            # OVSvApp agent, to be serialized for VXLAN case
            # in order to workaround races that arise in default
            # l2pop mech driver.
            with ovsvapp_l2pop_lock:
                try:
                    self.plugin_rpc.update_device_up(
                        context, agent_id=self.agent_id,
                        device=port['id'], host=self.hostname)
                except Exception:
                    LOG.exception(_LE("Exception during update_device_up "
                                      "RPC for port %s."), port['id'])

    def device_create(self, context, **kwargs):
        """Gets the port details from plugin using RPC call."""
        device = kwargs.get('device')
        LOG.info(_LI("RPC device_create received for device: %s."), device)
        device_id = device['id']
        cluster_id = device['cluster_id']
        vcenter_id = device['vcenter']
        if cluster_id != self.cluster_id or vcenter_id != self.vcenter_id:
            LOG.debug('Cluster/vCenter mismatch..ignoring device_create rpc.')
            return
        ports_list = kwargs.get('ports')
        sg_info = kwargs.get("sg_rules")
        host = device['host']
        LOG.debug("Received Port list: %s.", ports_list)
        LOG.debug('Trying to expand the sg_rule_info for device %s: ',
                  device_id)
        sg_rules = self.sg_agent.expand_sg_rules(sg_info[device_id])
        LOG.debug('Finished expanding the sg_rule_info for device %s: ',
                  device_id)
        port_ids = [port['id'] for port in ports_list]
        if host == self.esx_hostname:
            self._add_ports_to_host_ports(port_ids)
        else:
            self._add_ports_to_host_ports(port_ids, False)
        self._process_create_ports(context, ports_list, host, sg_rules)
        LOG.info(_LI("device_create processed for VM: %s."), device_id)

    def _port_update_status_change(self, network_model, port_model):
        retry_count = MAX_RETRY_COUNT
        LOG.info(_LI("Updating port state at vCenter for port %s."),
                 port_model.uuid)
        while retry_count > 0:
            try:
                self.net_mgr.get_driver().update_port(network_model,
                                                      port_model,
                                                      None)
                LOG.info(_LI("Successfully updated port state at vCenter for "
                             "port %s."), port_model.uuid)
                break
            except Exception as e:
                LOG.exception(_LE("Failed to update port at vCenter for "
                                  "port: %s even after trying thrice."),
                              port_model.uuid)
                retry_count -= 1
                if retry_count == 0:
                    raise error.OVSvAppNeutronAgentError(e)
                time.sleep(RETRY_DELAY)

    def port_update(self, context, **kwargs):
        """Update the port details from plugin using RPC call."""
        new_port = kwargs.get('port')
        LOG.info(_LI("RPC port_update received for port: %s."), new_port)
        local_vlan_id = kwargs.get('segmentation_id')
        ovsvapplock.acquire()
        old_port_object = None
        new_port_object = None
        try:
            if new_port['id'] in self.ports_dict.keys():
                old_port_object = self.ports_dict[new_port['id']]
                local_vlan_id = old_port_object.vlanid
                self.ports_dict[new_port['id']] = PortInfo(
                    new_port['id'],
                    local_vlan_id,
                    new_port['mac_address'],
                    new_port['security_groups'],
                    new_port['admin_state_up'],
                    new_port['network_id'],
                    new_port['device_id'],
                    old_port_object.phys_net,
                    old_port_object.network_type)
                new_port_object = self.ports_dict[new_port['id']]
        finally:
            ovsvapplock.release()

        if old_port_object and new_port_object:
            self.sg_agent.devices_to_refilter.add(new_port['id'])
            # We have to update the port state in vCenter and to the
            # controller only from the agent who is owning this port.
            cluster_host_port = new_port['id'] in self.cluster_host_ports
            if not cluster_host_port:
                LOG.info(_LI("RPC port_update for port %s exited "
                             "as agent does not own it."), new_port['id'])
                return
            if cmp(old_port_object.admin_state_up,
                   new_port_object.admin_state_up) != 0:
                LOG.debug("Updating admin_state_up status for %s.",
                          new_port['id'])
                network, port = self._map_port_to_common_model(new_port,
                                                               local_vlan_id)
                self._port_update_status_change(network, port)
                with ovsvapplock:
                    if new_port['admin_state_up']:
                        self.devices_up_list.append(new_port['id'])
                    else:
                        self.devices_down_list.append(new_port['id'])
        else:
            LOG.info(_LI("Old and/or New port objects not available for port "
                         "%s."), new_port['id'])
        LOG.info(_LI("RPC port_update for port %s finished!"),
                 new_port['id'])

    def device_delete(self, context, **kwargs):
        """Delete the portgroup, flows and reclaim lvid for a VXLAN network."""
        host = kwargs.get('host')
        network_info = kwargs.get('network_info')
        network_id = network_info['network_id']
        network_type = network_info['network_type']
        supported_network_types = [p_const.TYPE_VLAN, p_const.TYPE_VXLAN]
        LOG.info(_LI("RPC device_delete received for network: %s."),
                 network_info)
        if host == self.hostname:
            if network_type not in supported_network_types:
                LOG.warning(_LW("Received device_delete RPC for "
                                "unsupported network_type %s."),
                            network_type)
            try:
                self._delete_portgroup(network_id, network_type)
                LOG.info(_LI("Invoking update_lvid_assignment RPC for "
                             "network %s."), network_info)
                self.ovsvapp_rpc.update_lvid_assignment(self.context,
                                                        network_info)
                LOG.info(_LI("lvid assignment done successfully for "
                             "network %s."), network_info)
            except Exception:
                LOG.error(_LE("Exception occurred while processing "
                              "device_delete RPC."))

        ovsvapplock.acquire()
        try:
            # Delete FLOWs which match entries:
            # network_id - local_vlan_id - segmentation_id.
            LOG.debug("Reclaiming local vlan associated with the network: %s.",
                      network_id)
            lvm = self.vlan_manager.pop(network_id)
            if lvm:
                self._reclaim_local_vlan(lvm)
            else:
                LOG.debug("Network %s not used on this agent.", network_id)
        except Exception as e:
            LOG.exception(_LE("Failed to remove tunnel flows associated with "
                              "network %s."), network_id)
            raise error.OVSvAppNeutronAgentError(e)
        finally:
            ovsvapplock.release()

    def device_update(self, context, **kwargs):
        device_data = kwargs.get('device_data')
        LOG.info(_LI("RPC device_update received with data %(data)s."),
                 {'data': device_data})
        status = True
        if device_data:
            ovsvapp_vm = device_data.get('ovsvapp_agent')
            src_esx_host = device_data.get('esx_host_name')
            assigned_host = device_data.get('assigned_agent_host')
            if assigned_host == self.hostname:
                retry_count = MAX_RETRY_COUNT
                while retry_count > 0:
                    try:
                        vm_mor = resource_util.get_vm_mor_by_name(
                            self.net_mgr.get_driver().session, ovsvapp_vm)
                        host_mor = resource_util.get_host_mor_by_name(
                            self.net_mgr.get_driver().session, src_esx_host)
                        if self.esx_maintenance_mode:
                            try:
                                LOG.info(_LI("Setting OVSvApp VM %s to "
                                             "poweroff state."), ovsvapp_vm)
                                resource_util.set_vm_poweroff(
                                    self.net_mgr.get_driver().session, vm_mor)
                            except Exception:
                                LOG.exception(_LE("Unable to poweroff %s "
                                                  "OVSvApp VM."), ovsvapp_vm)
                                status = False
                            LOG.info(_LI("Setting host %s to maintenance "
                                         "mode."), src_esx_host)
                            resource_util.set_host_into_maintenance_mode(
                                self.net_mgr.get_driver().session, host_mor)
                            status = True
                        else:
                            LOG.info(_LI("Setting host %s to shutdown mode."),
                                     src_esx_host)
                            resource_util.set_host_into_shutdown_mode(
                                self.net_mgr.get_driver().session, host_mor)
                        break
                    except Exception:
                        LOG.exception(_LE("Exception occurred while setting "
                                          "host to maintenance mode or "
                                          "shutdown mode."))
                        retry_count -= 1
                    if retry_count == 0:
                        LOG.warning(_LW("Could not set %s to maintenance "
                                        "mode or shutdown mode even after "
                                        "retrying thrice."),
                                    src_esx_host)
                        status = False
                    time.sleep(RETRY_DELAY)
                self.ovsvapp_rpc.update_cluster_lock(
                    self.context, vcenter_id=self.vcenter_id,
                    cluster_id=self.cluster_id, success=status)
            else:
                LOG.debug("Ignoring the device_update RPC as it is for "
                          "a different host")

    def enhanced_sg_provider_updated(self, context, **kwargs):
        """Callback for security group provider update."""
        net_id = kwargs.get('network_id', [])
        LOG.info(_LI("Received enhanced_sg_provider_updated RPC for"
                     "network %s"),
                 net_id)
        self.sg_agent.sg_provider_updated(net_id)


class RpcPluginApi(agent_rpc.PluginApi):

    def __init__(self):
        super(RpcPluginApi, self).__init__(topic=topics.PLUGIN)


class OVSvAppPluginApi(object):

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_ports_for_device(self, context, device, agent_id, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_ports_for_device', device=device,
                          agent_id=agent_id, host=host)

    def update_device_binding(self, context, agent_id, device, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_device_binding', agent_id=agent_id,
                          device=device, host=host)

    def update_ports_binding(self, context, agent_id, ports, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_ports_binding', agent_id=agent_id,
                          ports=ports, host=host)

    def get_ports_details_list(self, context, port_ids, agent_id,
                               vcenter_id, cluster_id):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_ports_details_list', port_ids=port_ids,
                          agent_id=agent_id, vcenter_id=vcenter_id,
                          cluster_id=cluster_id)

    def update_lvid_assignment(self, context, net_info):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_lvid_assignment', net_info=net_info)

    def update_devices_up(self, context, agent_id, devices, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_devices_up', agent_id=agent_id,
                          devices=devices, host=host)

    def update_devices_down(self, context, agent_id, devices, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_devices_down', agent_id=agent_id,
                          devices=devices, host=host)

    def update_cluster_lock(self, context, vcenter_id, cluster_id, success):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_cluster_lock',
                          vcenter_id=vcenter_id,
                          cluster_id=cluster_id,
                          success=success)
