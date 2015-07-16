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

import threading
import time

import eventlet
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_service import loopingcall
import six

from neutron.agent.common import ovs_lib
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron import context
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants as ovs_const  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import br_int  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import br_phys  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import br_tun  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent as ovs_agent  # noqa

from networking_vsphere.agent import agent
from networking_vsphere.agent import ovsvapp_sg_agent as sgagent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.common import error
from networking_vsphere.common import model
from networking_vsphere.common import utils

LOG = log.getLogger(__name__)
CONF = cfg.CONF

# To ensure thread safety for the shared variables
# ports_dict, network_port_count, devices_to_filter,
# we use this per-thread recursive lock i.e., ovsvapplock
ovsvapplock = threading.RLock()
ovsvapp_l2pop_lock = threading.RLock()
THREAD_POOL_SIZE = 5
RESTART_BATCH_SIZE = 30


class LocalVLANMapping(object):
    """Maps Global VNI to local VLAN Id."""
    def __init__(self, vlan, network_type, segmentation_id):
        self.vlan = vlan
        self.network_type = network_type
        self.segmentation_id = segmentation_id


class PortInfo(object):
    def __init__(self, port_id, vlanid, mac_addr, sec_gps, fixed_ips,
                 admin_state_up, network_id, vm_uuid):
        self.port_id = port_id
        self.vlanid = vlanid
        self.mac_addr = mac_addr
        self.sec_gps = sec_gps
        self.fixed_ips = fixed_ips
        self.admin_state_up = admin_state_up
        self.network_id = network_id
        self.vm_uuid = vm_uuid


class OVSvAppL2Agent(agent.Agent, ovs_agent.OVSNeutronAgent):

    """OVSvApp L2 Agent."""

    def __init__(self):
        agent.Agent.__init__(self)
        self.conf = cfg.CONF
        self.esx_hostname = CONF.VMWARE.esx_hostname
        self.vcenter_id = CONF.VMWARE.vcenter_id
        if not self.vcenter_id:
            self.vcenter_id = CONF.VMWARE.vcenter_ip
        self.cluster_moid = None  # Cluster domain ID.
        self.cluster_dvs_info = (CONF.VMWARE.cluster_dvs_mapping)[0].split(":")
        self.cluster_id = self.cluster_dvs_info[0]  # Datacenter/host/cluster.
        self.ports_dict = {}
        self.network_port_count = {}
        self.devices_to_filter = set()
        self.cluster_host_ports = set()
        self.cluster_other_ports = set()
        self.ports_to_bind = set()
        self.refresh_firewall_required = False
        self._pool = None
        self.run_check_for_updates = True
        self.use_call = True
        self.hostname = cfg.CONF.host
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
                               'vcenter_id': self.vcenter_id},
            'agent_type': ovsvapp_const.AGENT_TYPE_OVSVAPP,
            'start_flag': True}
        self.veth_mtu = CONF.OVSVAPP.veth_mtu
        self.use_veth_interconnection = False
        self.agent_under_maintenance = CONF.OVSVAPP.agent_maintenance
        self.enable_tunneling = False
        self.tun_br = None
        bridge_classes = {'br_int': br_int.OVSIntegrationBridge,
                          'br_phys': br_phys.OVSPhysicalBridge,
                          'br_tun': br_tun.OVSTunnelBridge}
        self.br_int_cls = bridge_classes['br_int']
        self.br_phys_cls = bridge_classes['br_phys']
        self.br_tun_cls = bridge_classes['br_tun']
        self.int_br = self.br_int_cls(CONF.OVSVAPP.integration_bridge)
        self.firewall_driver = CONF.SECURITYGROUP.ovsvapp_firewall_driver
        if not self.agent_under_maintenance:
            self.setup_integration_br()
            LOG.info(_("Integration bridge successfully setup."))
            if "OVSFirewallDriver" in self.firewall_driver:
                self.setup_security_br()
        else:
            LOG.info(_("Agent has undergone some maintenance - "
                       "Attempting to recover the state of OVS bridges."))
            self.check_integration_br()
            if "OVSFirewallDriver" in self.firewall_driver:
                self.recover_security_br()
        self.setup_ovs_bridges()
        self.setup_rpc()
        defer_apply = CONF.SECURITYGROUP.defer_apply
        self.sg_agent = sgagent.OVSVAppSecurityGroupAgent(self.context,
                                                          self.sg_plugin_rpc,
                                                          defer_apply)

    def check_integration_br(self):
        """Check if the integration bridge is still existing."""
        if not self.int_br.bridge_exists(CONF.OVSVAPP.integration_bridge):
            LOG.error(_("Integration bridge %(bridge)s does not exist. "
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
            LOG.warn(_("Security bridge mappings not configured."))
            raise SystemExit(1)
        secbr_list = (CONF.SECURITYGROUP.security_bridge_mapping).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]
        self.sec_br = ovs_lib.OVSBridge(secbr_name)
        if not self.sec_br.bridge_exists(secbr_name):
            LOG.error(_("Security bridge does not exist. Terminating the "
                        "agent!"))
            raise SystemExit(1)
        self.sec_br.remove_all_flows()
        self.int_br.delete_port(ovsvapp_const.INT_TO_SEC_PATCH)
        self.sec_br.delete_port(ovsvapp_const.SEC_TO_INT_PATCH)
        self.phy_ofport = self.sec_br.get_port_ofport(secbr_phyname)
        if not self.phy_ofport:
            LOG.error(_("Physical bridge patch port not available on "
                        "Security bridge %s. Terminating the "
                        "agent!"), secbr_name)
            raise SystemExit(1)
        # br-sec patch port to br-int.
        self.patch_int_ofport = self.sec_br.add_patch_port(
            ovsvapp_const.SEC_TO_INT_PATCH, ovsvapp_const.INT_TO_SEC_PATCH)
        # br-int patch port to br-sec.
        self.patch_sec_ofport = self.int_br.add_patch_port(
            ovsvapp_const.INT_TO_SEC_PATCH, ovsvapp_const.SEC_TO_INT_PATCH)
        if int(self.patch_int_ofport) < 0 or int(self.patch_sec_ofport) < 0:
            LOG.error(_("Failed to create OVS patch port. Neutron port "
                        "security cannot be enabled on this agent. "
                        "Terminating the agent!"))
            raise SystemExit(1)

        self.sec_br.add_flow(priority=0, actions="drop")
        LOG.info(_("Security bridge successfully setup."))

    def recover_security_br(self):
        """Recover the security bridge.

        This method is helpful to retain the flow rules during agent
        restarts, there by avoiding datapath traffic loss.
        We just populate the agent cache back after the restart and let
        the flows remain.
        """
        if not CONF.SECURITYGROUP.security_bridge_mapping:
            LOG.warn(_("Security bridge mappings not configured."))
            raise SystemExit(1)
        secbr_list = (CONF.SECURITYGROUP.security_bridge_mapping).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]
        self.sec_br = ovs_lib.OVSBridge(secbr_name)
        if not self.sec_br.bridge_exists(secbr_name):
            LOG.error(_("Security bridge does not exist. Terminating the "
                        "agent!"))
            raise SystemExit(1)
        self.phy_ofport = self.sec_br.get_port_ofport(secbr_phyname)
        if not self.phy_ofport:
            LOG.error(_("Physical bridge patch port not available on "
                        "Security bridge %s. Terminating the "
                        "agent!"), secbr_name)
            raise SystemExit(1)
        # br-sec patch port to br-int.
        self.patch_int_ofport = self.sec_br.get_port_ofport(
            ovsvapp_const.SEC_TO_INT_PATCH)
        # br-int patch port to br-sec.
        self.patch_sec_ofport = self.int_br.get_port_ofport(
            ovsvapp_const.INT_TO_SEC_PATCH)
        if int(self.patch_int_ofport) < 0 or int(self.patch_sec_ofport) < 0:
            LOG.error(_("Failed to find OVS patch port. Cannot have "
                        "Security enabled on this agent. "
                        "Terminating the agent!"))
            raise SystemExit(1)
        LOG.info(_("Security bridge successfully recovered."))

    def recover_tunnel_bridge(self, tun_br_name=None):
        """Recover the tunnel bridge.

        :param tun_br_name: the name of the tunnel bridge.
        """
        self.tun_br = ovs_lib.OVSBridge(tun_br_name, self.root_helper)

        self.patch_tun_ofport = self.int_br.get_port_ofport(
            cfg.CONF.OVS.int_peer_patch_port)
        self.patch_int_ofport = self.tun_br.get_port_ofport(
            cfg.CONF.OVS.tun_peer_patch_port)
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error(_("Failed to find OVS tunnel patch port(s). Cannot have "
                        "tunneling enabled on this agent, since this version "
                        "of OVS does not support tunnels or patch ports. "
                        "Agent terminated!"))
            raise SystemExit(1)
        LOG.info(_("Tunnel bridge successfully recovered."))

    def recover_physical_bridges(self, bridge_mappings):
        """Recover data from the physical network bridges.

        :param bridge_mappings: map physical network names to bridge names.
        """
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ovs_bridges = ovs_lib.get_bridges()
        for phys_net, bridge in six.iteritems(bridge_mappings):
            LOG.info(_("Mapping physical network %(phys_net)s to "
                       "bridge %(bridge)s."), {'phys_net': phys_net,
                                               'bridge': bridge})
            # setup physical bridge.
            if bridge not in ovs_bridges:
                LOG.error(_("Bridge %(bridge)s for physical network "
                            "%(phys_net)s does not exist. Terminating "
                            "the agent!"), {'phys_net': phys_net,
                                            'bridge': bridge})
                raise SystemExit(1)
            br = ovs_lib.OVSBridge(bridge)
            self.phys_brs[phys_net] = br
            # Interconnect physical and integration bridges using veth/patch
            # ports.
            int_if_name = self.get_peer_name(ovs_const.PEER_INTEGRATION_PREFIX,
                                             bridge)
            phys_if_name = self.get_peer_name(ovs_const.PEER_PHYSICAL_PREFIX,
                                              bridge)
            int_ofport = self.int_br.get_port_ofport(int_if_name)
            phys_ofport = br.get_port_ofport(phys_if_name)
            if int(phys_ofport) < 0 or int(int_ofport) < 0:
                LOG.error(_("Patch ports missing for bridge %(bridge)s for "
                            "physical network %(phys_net)s. Agent "
                            "terminated!"), {'phys_net': phys_net,
                                             'bridge': bridge})
                raise SystemExit(1)
            self.int_ofports[phys_net] = int_ofport
            self.phys_ofports[phys_net] = phys_ofport
        LOG.info(_("Physical bridges successfully recovered."))

    def _init_ovs_flows(self, bridge_mappings):
        """Delete the drop flow created by OVSvApp Agent code.

        Add the new flow to allow all the packets between integration
        bridge and physical bridge.
        """
        self.phys_brs = {}
        self.int_br.delete_flows(in_port=self.patch_sec_ofport)
        for phys_net, bridge in six.iteritems(bridge_mappings):
            self.int_br.delete_flows(
                in_port=self.int_ofports[phys_net])
            # Egress FLOWs.
            self.int_br.add_flow(priority=2,
                                 in_port=self.patch_sec_ofport,
                                 actions="output:%s"
                                 % self.int_ofports[phys_net])
            br = ovs_lib.OVSBridge(bridge)
            eth_name = bridge.split('-').pop()
            eth_ofport = br.get_port_ofport(eth_name)
            br.delete_flows(in_port=self.phys_ofports[phys_net])
            if eth_ofport > 0:
                br.delete_flows(in_port=eth_ofport)
                br.add_flow(priority=2,
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
        LOG.info(_("OVS flows set on physical bridges."))

    def setup_ovs_bridges(self):
        self.tenant_network_type = CONF.OVSVAPP.tenant_network_type
        LOG.info(_("Network type supported by agent: %s."),
                 self.tenant_network_type)
        if self.tenant_network_type == p_const.TYPE_VLAN:
            if not self.agent_under_maintenance:
                self.setup_physical_bridges(self.bridge_mappings)
                LOG.info(_("Physical bridges successfully setup."))
                self._init_ovs_flows(self.bridge_mappings)
            else:
                self.recover_physical_bridges(self.bridge_mappings)

        elif self.tenant_network_type == p_const.TYPE_VXLAN:
            # For now l2_pop and arp_responder are disabled
            # Once enabled, their values will be read from ini file.
            self.l2_pop = False
            self.arp_responder_enabled = False
            self.local_vlan_map = {}
            self.tun_br_ofports = {p_const.TYPE_VXLAN: {}}
            self.polling_interval = CONF.OVSVAPP.polling_interval
            self.enable_tunneling = True
            self.vxlan_udp_port = CONF.OVSVAPP.vxlan_udp_port
            self.dont_fragment = CONF.OVSVAPP.dont_fragment
            self.local_ip = CONF.OVSVAPP.local_ip
            if not self.local_ip:
                LOG.error(_("Tunneling cannot be enabled without a valid "
                            "local_ip."))
                raise SystemExit(1)
            if not self.tun_br:
                self.tun_br = self.br_tun_cls(CONF.OVSVAPP.tunnel_bridge)
            self.agent_state['configurations']['tunneling_ip'] = self.local_ip
            self.agent_state['configurations']['l2_population'] = self.l2_pop
            if not self.agent_under_maintenance:
                self.reset_tunnel_br(CONF.OVSVAPP.tunnel_bridge)
                self.setup_tunnel_br()
                LOG.info(_("Tunnel bridge successfully set."))
            else:
                self.recover_tunnel_bridge(CONF.OVSVAPP.tunnel_bridge)

    def _add_physical_bridge_flows(self, port):
        for phys_net in self.phys_brs:
            br = self.phys_brs[phys_net]['br']
            eth_ofport = self.phys_brs[phys_net]['eth_ofport']
            br.add_flow(priority=4,
                        in_port=eth_ofport,
                        dl_src=port['mac_address'],
                        dl_vlan=port['segmentation_id'],
                        actions="drop")

    def _delete_physical_bridge_flows(self, port):
        for phys_net in self.phys_brs:
            br = self.phys_brs[phys_net]['br']
            br.delete_flows(dl_src=port.mac_addr,
                            dl_vlan=port.vlanid)

    def _ofport_set_to_str(self, ofport_set):
        return ",".join(map(str, ofport_set))

    def _populate_tunnel_flows_for_port(self, port):
        lvid = port['lvid']
        if self.tenant_network_type in ovs_const.TUNNEL_NETWORK_TYPES:
            ofports = self._ofport_set_to_str(self.tun_br_ofports[
                port['network_type']].values())
            if ofports:
                self.tun_br.mod_flow(table=ovs_const.FLOOD_TO_TUN,
                                     dl_vlan=lvid,
                                     actions="strip_vlan,"
                                     "set_tunnel:%s,output:%s" %
                                     (port['segmentation_id'], ofports))
            self.tun_br.add_flow(
                table=ovs_const.TUN_TABLE[port['network_type']],
                priority=1,
                tun_id=port['segmentation_id'],
                actions="mod_vlan_vid:%s,resubmit(,%s)" %
                (lvid, ovs_const.LEARN_FROM_TUN))

    def _populate_lvm(self, port):
        self.local_vlan_map[port['network_id']] = LocalVLANMapping(
            port['lvid'], port['network_type'], port['segmentation_id'])

    def _update_port_dict(self, port):
        ovsvapplock.acquire()
        try:
            self.ports_dict[port['id']] = PortInfo(port['id'],
                                                   port['lvid'],
                                                   port['mac_address'],
                                                   None,
                                                   port['fixed_ips'],
                                                   port['admin_state_up'],
                                                   port['network_id'],
                                                   port['device_id'])
            self.sg_agent.add_devices_to_filter([port])
            if self.tenant_network_type == p_const.TYPE_VXLAN:
                if port['id'] in self.cluster_host_ports:
                    if port['network_id'] not in self.local_vlan_map:
                        self._populate_lvm(port)
                self._populate_tunnel_flows_for_port(port)
            else:
                if port['network_id'] not in self.network_port_count.keys():
                    self.network_port_count[port['network_id']] = 1
                else:
                    self.network_port_count[port['network_id']] += 1
                if port['id'] in self.cluster_host_ports:
                    self._add_physical_bridge_flows(port)
            return True
        finally:
            ovsvapplock.release()

    def _update_port_bindings(self):
        ovsvapplock.acquire()
        ports_to_update = self.ports_to_bind
        LOG.info(_("update_ports_binding RPC called for %s ports."),
                 len(ports_to_update))
        self.ports_to_bind = set()
        ovsvapplock.release()
        try:
            # Update port binding with the host set as OVSvApp
            # VM's hostname.
            LOG.info(_("Invoking update_ports_binding RPC for %s ports:"),
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
                LOG.info(_("Port binding updates failed for %s ports."
                           "Will be retried in the next cycle."),
                         len(failed_ports))
                ovsvapplock.acquire()
                self.ports_to_bind |= failed_ports
                ovsvapplock.release()
        except Exception as e:
            LOG.exception(_("RPC update_ports_binding failed. All ports will "
                            "be retried in the next iteration."))
            ovsvapplock.acquire()
            self.ports_to_bind |= ports_to_update
            ovsvapplock.release()
            raise error.OVSvAppNeutronAgentError(e)

    @property
    def threadpool(self):
        if self._pool is None:
            self._pool = eventlet.GreenPool(THREAD_POOL_SIZE)
        return self._pool

    def _process_uncached_devices_sublist(self, devices):
        device_list = set()
        try:
            LOG.info(_("RPC get_ports_details_list is called with "
                       "port_ids: %s."), devices)
            ports = self.ovsvapp_rpc.get_ports_details_list(
                self.context, devices, self.agent_id, self.vcenter_id,
                self.cluster_id)
            # Stale VM's ports handling.
            if len(ports) != len(devices):
                # Remove the stale ports from update port bindings list.
                port_ids = set([port['port_id'] for port in ports])
                stale_ports = set(devices) - port_ids
                LOG.debug("Stale ports: %s.", stale_ports)
                self.ports_to_bind = self.ports_to_bind - stale_ports
            for port in ports:
                if port and 'port_id' in port:
                    port['id'] = port['port_id']
                    status = self._update_port_dict(port)
                    if status:
                        device_list.add(port['id'])
            if device_list:
                LOG.info(_("Going to update firewall for ports: "
                           "%s."), device_list)
                self.sg_agent.refresh_firewall(device_list)
        except Exception as e:
            LOG.exception(_("RPC get_ports_details_list failed %s."), e)
            # Process the ports again in the next iteration.
            self.devices_to_filter |= set(devices)
            self.refresh_firewall_required = True

    def _process_uncached_devices(self, devices):
        dev_list = list(devices)
        if len(dev_list) > RESTART_BATCH_SIZE:
            sublists = ([dev_list[x:x + RESTART_BATCH_SIZE]
                        for x in six.moves.range(0, len(dev_list),
                                                 RESTART_BATCH_SIZE)])
        else:
            sublists = [dev_list]
        for dev_ids in sublists:
            LOG.debug("Spawning a thread to process ports - %s.", dev_ids)
            try:
                self.threadpool.spawn_n(self._process_uncached_devices_sublist,
                                        dev_ids)
                eventlet.sleep(0)
            except Exception:
                LOG.exception(_("Exception occured while spawning thread "
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
            LOG.info(_("Going to update firewall for ports: "
                       "%s."), device_list)
            self.sg_agent.refresh_firewall(device_list)
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
            self.setup_integration_br()
            self.setup_security_br()
            if self.enable_tunneling:
                self.reset_tunnel_br(CONF.OVSVAPP.tunnel_bridge)
                self.setup_tunnel_br()
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
                self.network_port_count = {}
                self.devices_to_filter |= self.cluster_host_ports
                self.devices_to_filter |= self.cluster_other_ports
                self.refresh_firewall_required = True
            finally:
                ovsvapplock.release()
            LOG.info(_("Finished resetting the bridges post ovs restart."))
        except Exception:
            LOG.exception(_("Exception encountered while mitigating the ovs "
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
        if ovs_restarted == ovs_const.OVS_RESTARTED:
            self.mitigate_ovs_restart()
        # Case where devices_to_filter is having some entries.
        if self.refresh_firewall_required:
            self._update_firewall()
        # Case where sgagent's devices_to_refilter is having some
        # entries or global_refresh_firewall flag is set to True.
        if self.sg_agent.firewall_refresh_needed():
            self.sg_agent.refresh_port_filters(
                self.cluster_host_ports, self.cluster_other_ports)
        # Check if there are any pending port bindings to be made.
        if self.ports_to_bind:
            self._update_port_bindings()

    def check_for_updates(self):
        while self.run_check_for_updates:
            self._check_for_updates()
            # TODO(romilg): Use polling_interval like in ovs_neutron_agent.
            time.sleep(2)

    def tunnel_sync_rpc_loop(self):
        """Establishes VXLAN tunnels between tunnel end points."""

        tunnel_sync = True
        while tunnel_sync:
            try:
                start = time.time()
                # Notify the plugin of tunnel IP.
                if self.enable_tunneling and tunnel_sync:
                    LOG.info(_("OVSvApp Agent tunnel out of sync with "
                               "plugin!"))
                    tunnel_sync = self.tunnel_sync()
            except Exception:
                LOG.exception(_("Error while synchronizing tunnels."))
                tunnel_sync = True

            # sleep till end of polling interval.
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})

    def start(self):
        LOG.info(_("Starting OVSvApp L2 Agent."))
        self.set_node_state(True)
        self.setup_report_states()
        t = eventlet.spawn(self.check_for_updates)
        if self.tenant_network_type == p_const.TYPE_VXLAN:
            # A daemon loop which invokes tunnel_sync_rpc_loop
            # to sync up the tunnels.
            t1 = eventlet.spawn(self.tunnel_sync_rpc_loop)
        t.wait()
        if self.tenant_network_type == p_const.TYPE_VXLAN:
            t1.wait()

    def stop(self):
        LOG.info(_("Stopping OVSvApp L2 Agent."))
        self.set_node_state(False)
        self.run_check_for_updates = False
        if self.connection:
            self.connection.close()

    def setup_rpc(self):
        # Ensure that the control exchange is set correctly.
        LOG.info(_("Started setting up RPC topics and endpoints."))
        self.agent_id = "ovsvapp-agent %s" % self.hostname
        self.topic = topics.AGENT
        self.plugin_rpc = RpcPluginApi()
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.ovsvapp_rpc = OVSvAppPluginApi(ovsvapp_const.OVSVAPP)

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
            [topics.SECURITY_GROUP, topics.UPDATE]
        ]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        LOG.info(_("Finished setting up RPC."))

    def _report_state(self):
        """Reporting agent state to neutron server."""

        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        self.use_call)
            self.use_call = False
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Heartbeat failure - Failed reporting state!"))

    def setup_report_states(self):
        """Method to send heartbeats to the neutron server."""

        report_interval = CONF.OVSVAPP.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)
        else:
            LOG.warn(_("Report interval is not initialized."
                       "Unable to send heartbeats to Neutron Server."))

    def process_event(self, event):
        """Handles vCenter based events

         VM creation, VM deletion and VM updation.
         """

        try:
            vm = event.src_obj
            host = event.host_name
            if event.event_type == ovsvapp_const.VM_CREATED:
                LOG.info(_("Handling event %(event_type)s for %(src_obj)s."),
                         {'event_type': event.event_type,
                          'src_obj': event.src_obj})
                if not self.cluster_moid:
                    self.cluster_moid = event.cluster_id
                    LOG.info(_("Setting the cluster moid: %s."),
                             self.cluster_moid)
                self._notify_device_added(vm, host)
            elif event.event_type == ovsvapp_const.VM_UPDATED:
                LOG.info(_("Handling event %(event_type)s for %(src_obj)s."),
                         {'event_type': event.event_type,
                          'src_obj': event.src_obj})
                self._notify_device_updated(vm, host, event.host_changed)
            elif event.event_type == ovsvapp_const.VM_DELETED:
                LOG.info(_("Handling event %(event_type)s for %(src_obj)s."),
                         {'event_type': event.event_type,
                          'src_obj': event.src_obj})
                self._notify_device_deleted(vm, host)
            else:
                LOG.debug("Ignoring event: %s.", event)
        except Exception as e:
            LOG.error(_("This may result in failure of network "
                        "provisioning for %(name)s %(uuid)s."),
                      {'name': event.src_obj.__class__.__name__,
                       'uuid': event.src_obj.uuid})
            LOG.exception(_("Cause of failure: %s.") % str(e))

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

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_added(self, vm, host):
        """Handle VM created event."""
        if len(vm.vnics) > 0:
            # This is for existing VM.
            ovsvapplock.acquire()
            for vnic in vm.vnics:
                self.devices_to_filter.add(vnic.port_uuid)
                self._add_ports_to_host_ports([vnic.port_uuid],
                                              host == self.esx_hostname)
                if host == self.esx_hostname:
                    self.ports_to_bind.add(vnic.port_uuid)
            self.refresh_firewall_required = True
            ovsvapplock.release()
        else:
            if host == self.esx_hostname:
                device = {'id': vm.uuid,
                          'host': host,
                          'cluster_id': self.cluster_id,
                          'vcenter': self.vcenter_id}
                retry = True
                iteration = 1
                LOG.info(_("Invoking get_ports_for_device RPC for device: "
                           "%s."), device['id'])
                while retry:
                    try:
                        # Make RPC call to plugin to get port details.
                        status = self.ovsvapp_rpc.get_ports_for_device(
                            self.context, device, self.agent_id, self.hostname)
                        if status:
                            LOG.info(_("Successfully obtained ports details "
                                       "for device %s."), device['id'])
                            retry = False
                        else:
                            time.sleep(2)
                            iteration += 1
                            # Stop if we reached 3 iterations.
                            if iteration > 3:
                                retry = False
                    except Exception as e:
                        LOG.exception(_("RPC get_ports_for_device failed for "
                                        "device: %s."), device['id'])
                        raise error.OVSvAppNeutronAgentError(e)

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_updated(self, vm, host, host_changed):
        """Handle VM updated event."""
        try:
            if host == self.esx_hostname:
                for vnic in vm.vnics:
                    self._add_ports_to_host_ports([vnic.port_uuid])
                    # host_changed flag being True indicates, that
                    # this VM_UPDATED event is because of a vMotion.
                    if host_changed:
                        if self.tenant_network_type == p_const.TYPE_VLAN:
                            # Updated the physical bridge flows.
                            updated_port = self.ports_dict[vnic.port_uuid]
                            port = {}
                            port['mac_address'] = updated_port.mac_addr
                            port['segmentation_id'] = updated_port.vlanid
                            self._add_physical_bridge_flows(port)
                            LOG.info(_("Invoking update_port_binding RPC for "
                                       "port: %s."), vnic.port_uuid)
                            self.ovsvapp_rpc.update_port_binding(
                                self.context, agent_id=self.agent_id,
                                port_id=vnic.port_uuid, host=self.hostname)
                            return
                        # Bulk migrations result in racing for
                        # update_port_postcommit in the controller-side
                        # default l2pop mech driver. This results in the l2pop
                        # mech driver generating incorrect fdb entries and
                        # it ships them to all other L2Pop enabled nodes
                        # creating havoc with tunnel port allocations/releases
                        # of them.
                        # So we serialize the calls to update_device_up within
                        # this OVSvAPP agent.
                        ovsvapp_l2pop_lock.acquire()
                        try:
                            LOG.info(_("Invoking update_port_binding RPC for "
                                       "port: %s."), vnic.port_uuid)
                            self.ovsvapp_rpc.update_port_binding(
                                self.context, agent_id=self.agent_id,
                                port_id=vnic.port_uuid, host=self.hostname)
                            # For migration usecase, need to set the port-state
                            # to BUILD, just to mimic the way Nova does it
                            # in kvm. For that we invoke get_device_details
                            # to transition the port status to BUILD.
                            LOG.info(_("Invoking get_device_details RPC for "
                                       "port: %s."), vnic.port_uuid)
                            self.plugin_rpc.get_device_details(
                                self.context,
                                agent_id=self.agent_id,
                                device=vnic.port_uuid,
                                host=self.hostname)
                            # Now make the port status to ACTIVE again for
                            # this host, so that L2POP rules ensure tunnel to
                            # this new host from others.
                            LOG.info(_("Invoking update_device_up RPC for "
                                       "port: %s."), vnic.port_uuid)
                            self.plugin_rpc.update_device_up(
                                self.context,
                                vnic.port_uuid,
                                self.agent_id,
                                self.hostname)
                        except Exception as e:
                            LOG.exception(_("Failed to handle VM migration "
                                            "for VM: %s.") % vm.uuid)
                            raise error.OVSvAppNeutronAgentError(e)
                        finally:
                            ovsvapp_l2pop_lock.release()
                    else:
                        LOG.debug("Ignoring VM_UPDATED event for VM %s.",
                                  vm.uuid)
            else:
                for vnic in vm.vnics:
                    if host_changed:
                        if self.tenant_network_type == p_const.TYPE_VLAN:
                            if vnic.port_uuid in self.cluster_host_ports:
                                # Delete the physical bridge flows.
                                updated_port = self.ports_dict[vnic.port_uuid]
                                self._delete_physical_bridge_flows(
                                    updated_port)
                    self._add_ports_to_host_ports([vnic.port_uuid], False)
                    if vnic.port_uuid in self.ports_to_bind:
                        ovsvapplock.acquire()
                        self.ports_to_bind.remove(vnic.port_uuid)
                        ovsvapplock.release()
        except Exception as e:
            LOG.exception(_("Failed to handle VM_UPDATED event for VM: "
                            " %s."), vm.uuid)
            raise error.OVSvAppNeutronAgentError(e)

    def _delete_portgroup(self, network_id):

        if self.tenant_network_type == p_const.TYPE_VLAN:
            network = model.Network(name=network_id,
                                    network_type=ovsvapp_const.NETWORK_VLAN)
        elif self.tenant_network_type == p_const.TYPE_VXLAN:
            network_id = str(network_id) + "-" + self.cluster_moid
            network = model.Network(name=network_id,
                                    network_type=ovsvapp_const.NETWORK_VXLAN)
        retry_count = 3
        while retry_count > 0:
            try:
                LOG.debug("Deleting port group from vCenter: %s.", network_id)
                self.net_mgr.get_driver().delete_network(network)
                break
            except Exception as e:
                LOG.exception(_("Failed to delete network %s."), network_id)
                retry_count -= 1
                if retry_count == 0:
                    raise error.OVSvAppNeutronAgentError(e)
                time.sleep(2)

    def _process_delete_pg_novnic(self, host, vm):
        """Deletes the VLAN port group for a VM without nic."""

        LOG.debug("Deletion of VM with no vnics: %s.", vm.uuid)
        ovsvapplock.acquire()
        try:
            for port_id in self.ports_dict.keys():
                port_count = -1
                if self.ports_dict[port_id].vm_uuid == vm.uuid:
                    network_id = self.ports_dict[port_id].network_id
                    if network_id in self.network_port_count:
                        self.network_port_count[network_id] -= 1
                        port_count = self.network_port_count[network_id]
                        LOG.info(_("Network: %(net_id)s - Port Count: "
                                   "%(port_count)s."),
                                 {'net_id': network_id,
                                  'port_count': port_count})
                    if port_id in self.cluster_host_ports:
                        self.cluster_host_ports.remove(port_id)
                    elif port_id in self.cluster_other_ports:
                        self.cluster_other_ports.remove(port_id)
                    self.sg_agent.remove_devices_filter(port_id)
                    # Delete the physical bridge flows related to this port.
                    if self.tenant_network_type == p_const.TYPE_VLAN:
                        if host == self.esx_hostname:
                            self._delete_physical_bridge_flows(
                                self.ports_dict[port_id])
                    # Clean up ports_dict for the deleted port.
                    self.ports_dict.pop(port_id)
                    # Remove port count tracking per network when
                    # last VM associated with the network is deleted.
                    if port_count == 0:
                        self.network_port_count.pop(network_id)
                        if host == self.esx_hostname:
                            self._delete_portgroup(network_id)
            self.net_mgr.get_driver().post_delete_vm(vm)
        finally:
            ovsvapplock.release()

    def _process_delete_vlan_portgroup(self, host, vm, del_port):
        """Deletes the VLAN port group for a VM."""

        ovsvapplock.acquire()
        port_count = -1
        try:
            if del_port.network_id in self.network_port_count.keys():
                self.network_port_count[del_port.network_id] -= 1
                port_count = self.network_port_count[del_port.network_id]
                LOG.info(_("Network: %(net_id)s - Port Count: "
                           "%(port_count)s."),
                         {'net_id': del_port.network_id,
                          'port_count': port_count})
                # Remove port count tracking per network when
                # last VM associated with the network is deleted.
                if port_count == 0:
                    self.network_port_count.pop(del_port.network_id)
                LOG.debug("Port count per network details after VM "
                          "deletion: %s.", self.network_port_count)
                # Clean up ports_dict for the deleted port.
                self.ports_dict.pop(del_port.port_id)
            else:
                LOG.debug("Network %s does not exist in "
                          "network_port_count.", del_port.network_id)
        finally:
            ovsvapplock.release()
            self.net_mgr.get_driver().post_delete_vm(vm)
            if host == self.esx_hostname:
                # Delete the physical bridge flows related to this port.
                self._delete_physical_bridge_flows(del_port)
                if port_count == 0:
                    self._delete_portgroup(del_port.network_id)

    def _process_delete_vxlan_portgroup(self, host, vm, del_port):
        """Deletes the VXLAN port group for a VM."""

        ovsvapplock.acquire()
        try:
            # Clean up ports_dict for the deleted port.
            self.ports_dict.pop(del_port.port_id)
            LOG.debug("Deleted port: %s from ports_dict.", del_port.port_id)
        finally:
            ovsvapplock.release()
            self.net_mgr.get_driver().post_delete_vm(vm)

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_deleted(self, vm, host):
        """Handle VM deleted event."""
        # When a last VM associated with a given network is deleted
        # then portgroup associated with the network is deleted and hence
        # network_delete RPC call is not consumed by the OVSvApp agent.
        if not vm.vnics:
            LOG.info(_("Deletion of VM with no vnics %s."), vm.uuid)
            self._process_delete_pg_novnic(host, vm)
            return

        for vnic in vm.vnics:
            LOG.info(_("Deleting port %(port)s with mac address %(mac)s."),
                     {'port': vnic.port_uuid, 'mac': vnic.mac_address})
            if not vnic.port_uuid:
                LOG.warn(_("Port id for VM %s not present."), vm.uuid)
            else:
                try:
                    ovsvapplock.acquire()
                    if vnic.port_uuid in self.ports_to_bind:
                        self.ports_to_bind.remove(vnic.port_uuid)
                    del_port = None
                    if vnic.port_uuid in self.ports_dict.keys():
                        if vnic.port_uuid in self.cluster_host_ports:
                            self.cluster_host_ports.remove(vnic.port_uuid)
                        elif vnic.port_uuid in self.cluster_other_ports:
                            self.cluster_other_ports.remove(vnic.port_uuid)

                        self.sg_agent.remove_devices_filter(vnic.port_uuid)
                        del_port = self.ports_dict[vnic.port_uuid]
                    else:
                        LOG.warn(_("Port id %s is not available in "
                                   "ports_dict."), vnic.port_uuid)
                finally:
                    ovsvapplock.release()
                if del_port:
                    if self.tenant_network_type == p_const.TYPE_VLAN:
                        self._process_delete_vlan_portgroup(host, vm,
                                                            del_port)
                    elif self.tenant_network_type == p_const.TYPE_VXLAN:
                        self._process_delete_vxlan_portgroup(host, vm,
                                                             del_port)

    def _build_port_info(self, port):
        return PortInfo(port['id'],
                        port['segmentation_id'],
                        port['mac_address'],
                        port['security_groups'],
                        port['fixed_ips'],
                        port['admin_state_up'],
                        port['network_id'],
                        port['device_id'])

    def _map_port_to_common_model(self, port_info, local_vlan_id=None):
        """Map the port and network objects to vCenter objects."""

        port_id = port_info.get('id')
        segmentation_id = port_info.get('segmentation_id')
        if self.tenant_network_type == p_const.TYPE_VLAN:
            network_id = port_info.get('network_id')
        elif self.tenant_network_type == p_const.TYPE_VXLAN:
            # In VXLAN deployment, we have two DVS per cluster. Two port groups
            # cannot have the same name with network_uuid within a data center.
            # For uniqueness cluster_id is added along with network_uuid.
            network_id = (str(port_info.get('network_id')) + "-"
                          + self.cluster_moid)
        device_id = port_info.get('device_id')
        fixed_ips = port_info.get('fixed_ips')
        mac_address = port_info.get('mac_address')
        port_status = (ovsvapp_const.PORT_STATUS_UP
                       if port_info.get('admin_state_up')
                       else ovsvapp_const.PORT_STATUS_DOWN)

        # Create Common Model Network Object.
        if self.tenant_network_type == p_const.TYPE_VLAN:
            vlan = model.Vlan(vlanIds=[segmentation_id])
            network = model.Network(name=network_id,
                                    network_type=ovsvapp_const.NETWORK_VLAN,
                                    config=model.NetworkConfig(vlan))
        elif self.tenant_network_type == p_const.TYPE_VXLAN:
            vlan = model.Vlan(vlanIds=[local_vlan_id])
            network = model.Network(name=network_id,
                                    network_type=ovsvapp_const.NETWORK_VXLAN,
                                    config=model.NetworkConfig(vlan))

        # Create Common Model Port Object.
        port = model.Port(uuid=port_id,
                          name=None,
                          mac_address=mac_address,
                          vm_id=device_id,
                          network_uuid=network_id,
                          ipaddresses=fixed_ips,
                          port_status=port_status)
        return network, port

    def _create_portgroup(self, port_info, host, local_vlan_id=0,
                          pg_name=None):
        """Create port group based on port information."""
        if host == self.esx_hostname:
            network, port = self._map_port_to_common_model(port_info,
                                                           local_vlan_id)
            retry_count = 3
            LOG.info(_("Trying to create port group for network %s."),
                     network.name)
            while retry_count > 0:
                try:
                    self.net_mgr.get_driver().create_port(network, port, None)
                    break
                except Exception as e:
                    LOG.exception(_("Retrying to create portgroup for "
                                    "network: %s."), network.name)
                    exception_str = str(e)
                    if ("The name" and "already exists" in exception_str):
                        pg_vlan_id = self.net_mgr.get_driver().get_pg_vlanid(
                            self.cluster_dvs_info[1], pg_name)
                        local_vlan_id = pg_vlan_id
                        break
                    else:
                        retry_count -= 1
                        if retry_count == 0:
                            LOG.exception(_("Failed to create port group for "
                                            "network %s after retrying "
                                            "thrice."), network.name)
                            raise error.OVSvAppNeutronAgentError(e)
                        time.sleep(2)
            LOG.info(_("Finished creating port group for network %s."),
                     network.name)
            return local_vlan_id

    def _process_create_portgroup_vxlan(self, context, ports_list, host,
                                        device_id):
        try:
            ovsvapplock.acquire()
            valid_ports = []
            for port in ports_list:
                local_vlan_id = port['lvid']
                if host == self.esx_hostname:
                    net_id = port['network_id']
                    pg_name = str(net_id) + "-" + self.cluster_moid
                    if net_id not in self.local_vlan_map:
                        try:
                            pg_vlan_id = self._create_portgroup(port, host,
                                                                local_vlan_id,
                                                                pg_name)
                            if local_vlan_id != pg_vlan_id:
                                LOG.error(_("Local vlan id mismatch."
                                            "Expected local_vlan_id %(lvid)s. "
                                            "Retrieved pg_vlan_id %(pg_vid)s "
                                            "for network %(net_id)s for port "
                                            "%(port_id)s."),
                                          {'pg_vid': pg_vlan_id,
                                           'lvid': local_vlan_id,
                                           'net_id': net_id,
                                           'port_id': port['id']})
                                continue
                            self._populate_lvm(port)
                        except Exception:
                            LOG.exception(_("Port group creation failed for "
                                            "network %(net_id)s, "
                                            "port %(port_id)s."),
                                          {'net_id': net_id,
                                           'port_id': port['id']})
                            continue
                self.ports_dict[port['id']] = PortInfo(port['id'],
                                                       local_vlan_id,
                                                       port['mac_address'],
                                                       port['security_groups'],
                                                       port['fixed_ips'],
                                                       port['admin_state_up'],
                                                       port['network_id'],
                                                       port['device_id'])
                # TODO(vivek): This line results in asynchronously updating the
                # bindings, which is not useful. Commenting for now will be
                # revisited in vxlan refactoring.
                # if host == self.esx_hostname:
                #    self.ports_to_bind.append(port['id'])
                valid_ports.append(port)
        finally:
            ovsvapplock.release()

        if valid_ports:
            self.sg_agent.add_devices_to_filter(valid_ports)
            for port in valid_ports:
                self._populate_tunnel_flows_for_port(port)
                if host == self.esx_hostname:
                    # All update device calls from the same
                    # OVSvApp agent, to be serialized for VXLAN case
                    # in order to workaround races that arise in default
                    # l2pop mech driver.
                    ovsvapp_l2pop_lock.acquire()
                    try:
                        LOG.info(_("Invoking update_device_up RPC for port: "
                                   "%s."), port['id'])
                        self.plugin_rpc.update_device_up(self.context,
                                                         port['id'],
                                                         self.agent_id,
                                                         self.hostname)
                    except Exception as e:
                        LOG.exception(_("RPC update_device_up failed for "
                                        "port: %s."), port['id'])
                        raise error.OVSvAppNeutronAgentError(e)
                    finally:
                        ovsvapp_l2pop_lock.release()

    def _process_create_portgroup_vlan(self, context, ports_list, host):
        ovsvapplock.acquire()
        try:
            self.sg_agent.add_devices_to_filter(ports_list)
            for element in ports_list:
                self.ports_dict[element['id']] = self._build_port_info(element)
                if element['network_id'] not in self.network_port_count.keys():
                    self.network_port_count[element['network_id']] = 1
                else:
                    self.network_port_count[element['network_id']] += 1
                LOG.info(_("Network: %(net_id)s - Port Count: %(port_count)s"),
                         {'net_id': element['network_id'],
                          'port_count': self.network_port_count[
                          element['network_id']]})
        finally:
            LOG.debug("Port count per network details after VM creation: %s.",
                      self.network_port_count)
            ovsvapplock.release()

        if host == self.esx_hostname:
            for element in ports_list:
                # Add physical bridge flows.
                self._add_physical_bridge_flows(element)
                # Create a portgroup at vCenter and set it in enabled state.
                self._create_portgroup(element, host)
                LOG.info(_("Invoking update_device_up RPC for port %s."),
                         element['id'])
                try:
                    # set admin_state to True.
                    self.plugin_rpc.update_device_up(
                        self.context,
                        element['id'],
                        self.agent_id,
                        self.agent_state['host'])
                    LOG.info(_("Successfully set admin_state for port: %s."),
                             element['id'])
                except Exception as e:
                    LOG.exception(_("RPC update_device_up failed for port: "
                                    "%s."), element['id'])
                    raise error.OVSvAppNeutronAgentError(e)

    def device_create(self, context, **kwargs):
        """Gets the port details from plugin using RPC call."""
        device = kwargs.get('device')
        LOG.info(_("RPC device_create received for device: %s."), device)
        device_id = device['id']
        cluster_id = device['cluster_id']
        vcenter_id = device['vcenter']
        if cluster_id != self.cluster_id or vcenter_id != self.vcenter_id:
            LOG.debug('Cluster/vCenter mismatch..ignoring device_create rpc.')
            return
        ports_list = kwargs.get('ports')
        sg_rules = kwargs.get("sg_rules")
        host = device['host']
        LOG.debug("Received Port list: %s.", ports_list)
        port_ids = [port['id'] for port in ports_list]
        if host == self.esx_hostname:
            self._add_ports_to_host_ports(port_ids)
        else:
            self._add_ports_to_host_ports(port_ids, False)
            ovsvapplock.acquire()
            try:
                self.devices_to_filter |= set(port_ids)
            finally:
                ovsvapplock.release()
            self.refresh_firewall_required = True
        if self.tenant_network_type == p_const.TYPE_VLAN:
            self._process_create_portgroup_vlan(context, ports_list, host)
        elif self.tenant_network_type == p_const.TYPE_VXLAN:
            # In VXLAN case, the port_list will have ports pre populated
            # with the lvid.
            self._process_create_portgroup_vxlan(context, ports_list, host,
                                                 device_id)
        if sg_rules:
            self.sg_agent.ovsvapp_sg_update(sg_rules[device_id])
        LOG.info(_("device_create processed for VM: %s."), device_id)

    def _port_update_status_change(self, network_model, port_model):
        retry_count = 3
        LOG.info(_("Updating port state at vCenter for port %s."),
                 port_model.uuid)
        while retry_count > 0:
            try:
                self.net_mgr.get_driver().update_port(network_model,
                                                      port_model,
                                                      None)
                LOG.info(_("Successfully updated port state at vCenter for "
                           "port %s."), port_model.uuid)
                break
            except Exception as e:
                LOG.exception(_("Failed to update port at vCenter for "
                                "port: %s even after trying thrice."),
                              port_model.uuid)
                retry_count -= 1
                if retry_count == 0:
                    raise error.OVSvAppNeutronAgentError(e)
                time.sleep(2)

    def port_update(self, context, **kwargs):
        """Update the port details from plugin using RPC call."""
        new_port = kwargs.get('port')
        LOG.info(_("RPC port_update received for port: %s."), new_port)
        local_vlan_id = kwargs.get('segmentation_id')
        ovsvapplock.acquire()
        old_port_object = None
        new_port_object = None
        try:
            if new_port['id'] in self.ports_dict.keys():
                old_port_object = self.ports_dict[new_port['id']]
                if self.tenant_network_type == p_const.TYPE_VXLAN:
                    local_vlan_id = old_port_object.vlanid
                self.ports_dict[new_port['id']] = PortInfo(
                    new_port['id'],
                    local_vlan_id,
                    new_port['mac_address'],
                    new_port['security_groups'],
                    new_port['fixed_ips'],
                    new_port['admin_state_up'],
                    new_port['network_id'],
                    new_port['device_id'])
                new_port_object = self.ports_dict[new_port['id']]
        finally:
            ovsvapplock.release()

        if old_port_object and new_port_object:
            self.sg_agent.devices_to_refilter.add(new_port['id'])
            # We have to update the port state in vCenter and to the
            # controller only from the agent who is owning this port.
            cluster_host_port = new_port['id'] in self.cluster_host_ports
            if not cluster_host_port:
                LOG.info(_("RPC port_update for port %s exited "
                           "as agent does not own it."), new_port['id'])
                return
            if cmp(old_port_object.admin_state_up,
                   new_port_object.admin_state_up) != 0:
                LOG.debug("Updating admin_state_up status for %s.",
                          new_port['id'])
                network, port = self._map_port_to_common_model(new_port,
                                                               local_vlan_id)
                self._port_update_status_change(network, port)
                # All update device calls from the same
                # OVSvApp agent, to be serialized for VXLAN case
                # in order to workaround races that arise in default
                # l2pop mech driver.
                if self.tenant_network_type == p_const.TYPE_VXLAN:
                    ovsvapp_l2pop_lock.acquire()
                try:
                    if new_port['admin_state_up']:
                        LOG.info(_("Invoking update_device_up RPC for %s."),
                                 new_port['id'])
                        self.plugin_rpc.update_device_up(self.context,
                                                         new_port['id'],
                                                         self.agent_id,
                                                         self.hostname)
                        LOG.info(_("Successfully updated the status UP for "
                                   "port: %s."), new_port['id'])
                    else:
                        LOG.info(_("Invoking update_device_down RPC for %s."),
                                 new_port['id'])
                        self.plugin_rpc.update_device_down(self.context,
                                                           new_port['id'],
                                                           self.agent_id,
                                                           self.hostname)
                        LOG.info(_("Successfully updated the status DOWN for "
                                   "port: %s."), new_port['id'])
                except Exception as e:
                    LOG.exception(_("RPC update device up/down failed for "
                                    "port: %s."), new_port['id'])
                    raise error.OVSvAppNeutronAgentError(e)
                finally:
                    if self.tenant_network_type == p_const.TYPE_VXLAN:
                        ovsvapp_l2pop_lock.release()
        else:
            LOG.info(_("Old and/or New port objects not available for port "
                       "%s."), new_port['id'])
        LOG.info(_("RPC port_update for port %s finished!"),
                 new_port['id'])

    def _remove_tunnel_flows_for_network(self, lvm):
        self.tun_br.delete_flows(
            table=ovs_const.TUN_TABLE[lvm.network_type],
            tun_id=lvm.segmentation_id)
        self.tun_br.delete_flows(dl_vlan=lvm.vlan)

    def device_delete(self, context, **kwargs):
        """Delete the portgroup, flows and reclaim lvid for a VXLAN network."""
        host = kwargs.get('host')
        network_info = kwargs.get('network_info')
        cluster_id = network_info['cluster_id']
        network_id = network_info['network_id']
        LOG.info(_("RPC device_delete received for network: %s."),
                 network_info)
        if cluster_id != self.cluster_id:
            LOG.error(_("Skipping device delete RPC, since "
                        "port group doesn't belong to cluster."))
            return
        if host == self.hostname:
            try:
                self._delete_portgroup(network_id)
                LOG.info(_("Invoking update_lvid_assignment RPC for "
                           "network %s."), network_info)
                self.ovsvapp_rpc.update_lvid_assignment(self.context,
                                                        network_info)
                LOG.info(_("lvid assignment done successfully for "
                           "network %s."), network_info)
            except Exception:
                LOG.error(_("Exception occurred while processing "
                            "device_delete RPC."))

        ovsvapplock.acquire()
        try:
            # Delete FLOWs which match entries:
            # network_id - local_vlan_id - segmentation_id.
            LOG.debug("Reclaiming local vlan associated with the network: %s.",
                      network_id)
            lvm = self.local_vlan_map.pop(network_id, None)
            if lvm is None:
                LOG.debug("Network %s not used on agent.", network_id)
                # Try to construct LVM from the payload.
                lvid = network_info['lvid']
                network_type = p_const.TYPE_VXLAN
                seg_id = None
                if 'segmentation_id' in network_info:
                    seg_id = network_info['segmentation_id']
                    lvm = LocalVLANMapping(lvid, network_type, seg_id)
                    self._remove_tunnel_flows_for_network(lvm)
            else:
                self._remove_tunnel_flows_for_network(lvm)
        except Exception as e:
            LOG.exception(_("Failed to remove tunnel flows associated with "
                            "network %s."), network_id)
            raise error.OVSvAppNeutronAgentError(e)
        finally:
            ovsvapplock.release()


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

    def update_port_binding(self, context, agent_id, port_id, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_port_binding', agent_id=agent_id,
                          port_id=port_id, host=host)

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
