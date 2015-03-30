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

from neutron.agent.common import ovs_lib
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron import context
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.agent import ovs_neutron_agent as ovs_agent
from neutron.plugins.openvswitch.common import constants as ovs_const

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
        self.esx_hostname = CONF.VMWARE.esx_hostname
        self.vcenter_id = CONF.VMWARE.vcenter_id
        if not self.vcenter_id:
            self.vcenter_id = CONF.VMWARE.vcenter_ip
        self.cluster_dvs_info = (CONF.VMWARE.cluster_dvs_mapping)[0].split(":")
        self.cluster_id = self.cluster_dvs_info[0]
        self.ports_dict = {}
        self.network_port_count = {}
        self.devices_to_filter = set()
        self.cluster_host_ports = set()
        self.cluster_other_ports = set()
        self.update_port_bindings = []
        self.refresh_firewall_required = False
        self.run_check_for_updates = True
        self.use_call = True
        self.hostname = cfg.CONF.host
        try:
            self.bridge_mappings = n_utils.parse_mappings(
                CONF.OVSVAPP.bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)
        self.tunnel_types = []
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
        self.int_br = ovs_lib.OVSBridge(CONF.OVSVAPP.integration_bridge)
        self.firewall_driver = CONF.SECURITYGROUP.ovsvapp_firewall_driver
        if not self.agent_under_maintenance:
            self.setup_integration_br()
            LOG.info(_("Integration bridge successfully setup."))
            if "OVSFirewallDriver" in self.firewall_driver:
                self.setup_security_br()
        else:
            self.check_integration_br()
            if "OVSFirewallDriver" in self.firewall_driver:
                self.recover_security_br()
        self.initialize_physical_bridges()
        self.setup_rpc()
        defer_apply = CONF.SECURITYGROUP.defer_apply
        self.sg_agent = sgagent.OVSVAppSecurityGroupAgent(self.context,
                                                          self.sg_plugin_rpc,
                                                          defer_apply)
        self.setup_report_states()

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

    def _init_ovs_flows(self, bridge_mappings):
        """Delete the drop flow created by OVSvApp Agent code.

        Add the new flow to allow all the packets between integration
        bridge and physical bridge.
        """
        self.int_br.delete_flows(in_port=self.patch_sec_ofport)
        for phys_net, bridge in bridge_mappings.iteritems():
            self.int_br.delete_flows(
                in_port=self.int_ofports[phys_net])
            # Egress FLOWs
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
                # Ingress FLOWs
                br.add_flow(priority=2,
                            in_port=eth_ofport,
                            actions="normal")
            self.int_br.add_flow(priority=2,
                                 in_port=self.int_ofports[phys_net],
                                 actions="output:%s" % self.patch_sec_ofport)

    def initialize_physical_bridges(self):
        self.tenant_network_type = CONF.OVSVAPP.tenant_network_type
        if self.tenant_network_type == p_const.TYPE_VLAN:
            self.bridge_mappings = n_utils.parse_mappings(
                CONF.OVSVAPP.bridge_mappings)
            if not self.agent_under_maintenance:
                self.setup_physical_bridges(self.bridge_mappings)
                LOG.info(_("Physical bridges successfully setup."))
                self._init_ovs_flows(self.bridge_mappings)
            else:
                self.recover_physical_bridges(self.bridge_mappings)
        else:
            # TODO(bhooshan): Add VxLAN related code.
            return

    def recover_physical_bridges(self, bridge_mappings):
        """Recover data from the physical network bridges.

        :param bridge_mappings: map physical network names to bridge names.
        """
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ovs_bridges = ovs_lib.get_bridges()
        for phys_net, bridge in bridge_mappings.iteritems():
            LOG.info(_("Mapping physical network %(phys_net)s to "
                       "bridge %(bridge)s"), {'phys_net': phys_net,
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

    # TODO(sudhakar-gariganti): Check if this method is required
    # if we have update_port_bindings called within get_ports_for_device RPC.
    def _update_port_bindings(self):
        for element in self.update_port_bindings:
            try:
                # Update port binding with the host as OVSvApp
                # VM's hostname.
                LOG.debug("Updating port binding for port %s.", element)
                self.ovsvapp_rpc.update_port_binding(
                    self.context,
                    agent_id=self.agent_id,
                    port_id=element,
                    host=self.hostname)
                self.update_port_bindings.remove(element)
            except Exception as e:
                LOG.exception(_("Port binding update failed "
                                "for port: %s"), element)
                raise error.OVSvAppNeutronAgentError(e)
            LOG.debug("update_port_binding RPC finished for port: "
                      "%s", element)

    def mitigate_ovs_restart(self):
        """Mitigates OpenvSwitch process restarts.

        Method to reset the flows which are lost due to an openvswitch
        process restart. After resetting up all the bridges, we set the
        SG agent's global_refresh_firewall flag to True to bring back all
        the flows related to Tenant VMs.
        """
        try:
            self.setup_integration_br()
            self.setup_physical_bridges(self.bridge_mappings)
            self._init_ovs_flows(self.bridge_mappings)
        # TODO(bhooshan): Add tunneling related code below.
            if self.enable_tunneling:
                pass
        # TODO(garigant): We need to add the DVR related resets
        # once it is enabled for vApp, similar to what is being
        # done in ovs_neutron_agent.
            self.setup_security_br()
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

    def _update_port_dict(self, port):
        ovsvapplock.acquire()
        try:
            self.ports_dict[port['id']] = PortInfo(port['id'],
                                                   port['segmentation_id'],
                                                   None, None, None,
                                                   port['admin_state_up'],
                                                   port['network_id'],
                                                   port['device'])
            if port['network_id'] not in self.network_port_count.keys():
                self.network_port_count[port['network_id']] = 1
            else:
                self.network_port_count[port['network_id']] += 1
            self.sg_agent.add_devices_to_filter([port])
            return True
        finally:
            ovsvapplock.release()

    def _update_firewall(self):
        """Helper method to monitor devices added.

        If devices_to_filter is not empty, we update the OVS firewall
        for those devices.
        """
        devices_to_filter = self.devices_to_filter
        self.devices_to_filter = set()
        self.refresh_firewall_required = False
        device_list = set()
        for device in devices_to_filter:
            if device in self.ports_dict:
                device_list.add(device)
        devices_to_filter = devices_to_filter - device_list
        ports = []
        if devices_to_filter:
            try:
                ports = self.plugin_rpc.get_devices_details_list(
                    self.context, devices_to_filter, self.agent_id)
                for port in ports:
                    if port and 'port_id' in port:
                        port['id'] = port['port_id']
                        status = self._update_port_dict(port)
                        if status:
                            device_list.add(port['id'])
            except Exception:
                LOG.exception(_("get_devices_details_list rpc failed."))
                # Process the ports again in the next iteration.
                self.devices_to_filter |= devices_to_filter
                self.refresh_firewall_required = True
            if device_list:
                LOG.info(_("Going to update firewall for ports: "
                           "%s"), device_list)
                self.sg_agent.refresh_firewall(device_list)

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
            LOG.info(_("OpenvSwitch restarted..going to mitigate."))
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
        if self.update_port_bindings:
            self._update_port_bindings()

    def check_for_updates(self):
        while self.run_check_for_updates:
            self._check_for_updates()
            time.sleep(2)

    def start(self):
        LOG.info(_("Starting OVSvApp L2 Agent."))
        self.set_node_state(True)
        t = eventlet.spawn(self.check_for_updates)
        t.wait()

    def stop(self):
        LOG.info(_("Stopping OVSvApp L2 Agent."))
        self.set_node_state(False)
        self.run_check_for_updates = False
        if self.connection:
            self.connection.close()

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

    def setup_rpc(self):
        # Ensure that the control exchange is set correctly.
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
        # Define the listening consumers for the agent.
        consumers = [
            [topics.PORT, topics.UPDATE],
            [ovsvapp_const.DEVICE, topics.CREATE],
            [ovsvapp_const.DEVICE, topics.UPDATE],
            [ovsvapp_const.DEVICE, topics.DELETE],
            [topics.SECURITY_GROUP, topics.UPDATE]
        ]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        LOG.debug("Finished Setup RPC.")

    def process_event(self, event):
        """Handles vCenter based events

         VM creation, VM deletion and VM updation.
         """

        try:
            LOG.debug("Handling event %(event_type)s for %(src_obj)s",
                      {'event_type': event.event_type,
                       'src_obj': event.src_obj})
            vm = event.src_obj
            host = event.host_name
            if event.event_type == ovsvapp_const.VM_CREATED:
                if not self.cluster_id:
                    self.cluster_id = event.cluster_id
                    LOG.info(_("Setting the cluster id: %s."), self.cluster_id)
                self._notify_device_added(vm, host)
            elif event.event_type == ovsvapp_const.VM_UPDATED:
                self._notify_device_updated(vm, host)
            elif event.event_type == ovsvapp_const.VM_DELETED:
                self._notify_device_deleted(vm, host)
            else:
                LOG.debug("Ignoring event: %s.", event)
        except Exception as e:
            LOG.error(_("This may result in failure of network "
                        "provisioning for %(name)s %(uuid)s"),
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
                while retry:
                    try:
                        # Make RPC call to plugin to get port details.
                        status = self.ovsvapp_rpc.get_ports_for_device(
                            self.context, device, self.agent_id, self.hostname)
                        if status:
                            retry = False
                        else:
                            time.sleep(5 + iteration)
                            iteration += 1
                            # Stop if we reached 10 iterations.
                            if iteration > 10:
                                retry = False
                    except Exception as e:
                        LOG.exception(_("Failed to get port details for "
                                        "device: %s.") % device['id'])
                        raise error.OVSvAppNeutronAgentError(e)

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_updated(self, vm, host):
        """Handle VM updated event."""
        try:
            if host == self.esx_hostname:
                for vnic in vm.vnics:
                    self._add_ports_to_host_ports([vnic.port_uuid])
                    LOG.debug("Invoking update_port_binding for port: %s.",
                              vnic.port_uuid)
                    self.ovsvapp_rpc.update_port_binding(
                        self.context, agent_id=self.agent_id,
                        port_id=vnic.port_uuid, host=self.hostname)
            else:
                for vnic in vm.vnics:
                    self._add_ports_to_host_ports([vnic.port_uuid], False)
        except Exception as e:
            LOG.exception(_("Failed to update port bindings for device: %s."),
                          vm.uuid)
            raise error.OVSvAppNeutronAgentError(e)

    def _delete_portgroup(self, del_port):
        network = model.Network(name=del_port.network_id,
                                network_type=ovsvapp_const.NETWORK_VLAN)
        retry_count = 3
        while retry_count > 0:
            try:
                LOG.debug("Deleting port group from vCenter: %s.",
                          del_port.network_id)
                self.net_mgr.get_driver().delete_network(network)
                break
            except Exception as e:
                LOG.exception(_("Failed to delete network %s."),
                              del_port.network_id)
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
                    self.network_port_count[network_id] -= 1
                    port_count = self.network_port_count[network_id]
                    LOG.debug("Port count per network details after VM "
                              "deletion: %s.", self.network_port_count)
                    # Clean up ports_dict for the deleted port.
                    del_port = self.ports_dict[port_id]
                    if port_id in self.cluster_host_ports:
                        self.cluster_host_ports.remove(port_id)
                    elif port_id in self.cluster_other_ports:
                        self.cluster_other_ports.remove(port_id)
                    self.sg_agent.remove_devices_filter(port_id)
                    self.ports_dict.pop(port_id)
                    # Remove port count tracking per network when
                    # last VM associated with the network is deleted.
                    if port_count == 0:
                        self.network_port_count.pop(del_port.network_id)
                        if host == self.esx_hostname:
                            self._delete_portgroup(del_port)
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
                # Remove port count tracking per network when
                # last VM associated with the network is deleted.
                if port_count == 0:
                    self.network_port_count.pop(del_port.network_id)
                LOG.debug("Port count per network details after VM "
                          "deletion: %s", self.network_port_count)
                # Clean up ports_dict for the deleted port.
                self.ports_dict.pop(del_port.port_id)
            else:
                LOG.debug("Network %s does not exist in "
                          "network_port_count.", del_port.network_id)
        finally:
            ovsvapplock.release()
            self.net_mgr.get_driver().post_delete_vm(vm)
            if port_count == 0:
                if host == self.esx_hostname:
                    self._delete_portgroup(del_port)

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_deleted(self, vm, host):
        """Handle VM deleted event."""
        # When a last VM associated with a given network is deleted
        # then portgroup associated with the network is deleted and hence
        # network_delete RPC call is not consumed by the OVSvApp agent.
        LOG.debug("Deleting VM %s.", vm.uuid)
        if not vm.vnics:
            self._process_delete_pg_novnic(host, vm)
            return

        for vnic in vm.vnics:
            LOG.info(_("Deleting port %(port)s with mac address %(mac)s."),
                     {'port': vnic.port_uuid, 'mac': vnic.mac_address})
            if not vnic.port_uuid:
                LOG.info(_("Port id for VM %s not present."), vm.uuid)
            else:
                try:
                    ovsvapplock.acquire()
                    del_port = None
                    if vnic.port_uuid in self.ports_dict.keys():
                        if vnic.port_uuid in self.cluster_host_ports:
                            self.cluster_host_ports.remove(vnic.port_uuid)
                        elif vnic.port_uuid in self.cluster_other_ports:
                            self.cluster_other_ports.remove(vnic.port_uuid)

                        self.sg_agent.remove_devices_filter(vnic.port_uuid)
                        LOG.info(_("Delete port %(port)s with mac %(mac)s for "
                                   "VM %(vm)s finished."),
                                 {'port': vnic.port_uuid,
                                  'mac': vnic.mac_address,
                                  'vm': vm.uuid})
                        del_port = self.ports_dict[vnic.port_uuid]
                    else:
                        LOG.debug("Port id %s is not available in "
                                  "ports_dict.", vnic.port_uuid)
                finally:
                    ovsvapplock.release()
                if del_port:
                    if self.tenant_network_type == p_const.TYPE_VLAN:
                        self._process_delete_vlan_portgroup(host, vm,
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

    def _map_port_to_common_model(self, port_info):
        """Map the port and network objects to vCenter objects."""

        port_id = port_info.get('id')
        segmentation_id = port_info.get('segmentation_id')
        if self.tenant_network_type == p_const.TYPE_VLAN:
            network_id = port_info.get('network_id')
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

        # Create Common Model Port Object.
        port = model.Port(uuid=port_id,
                          name=None,
                          mac_address=mac_address,
                          vm_id=device_id,
                          network_uuid=network_id,
                          ipaddresses=fixed_ips,
                          port_status=port_status)
        return network, port

    def _create_portgroup(self, port_info, host):
        """Create port group based on port information."""
        if host == self.esx_hostname:
            network, port = self._map_port_to_common_model(port_info)
            retry_count = 3
            LOG.debug("Trying to create port group for network %s.",
                      network.name)
            while retry_count > 0:
                try:
                    self.net_mgr.get_driver().create_port(network, port, None)
                    break
                except Exception as e:
                    LOG.error(_("Retrying to create portgroup for network: "
                                "%s."),
                              network.name)
                    retry_count -= 1
                    if retry_count == 0:
                        LOG.exception(_("Failed to create port group for "
                                        "network %s after retrying thrice."),
                                      network.name)
                        raise error.OVSvAppNeutronAgentError(e)
                    time.sleep(2)
        LOG.debug("Finished creating port group for network %s.", network.name)

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
        finally:
            LOG.debug("Port count per network details after VM creation: %s.",
                      self.network_port_count)
            ovsvapplock.release()

        if host == self.esx_hostname:
            for element in ports_list:
                # Create a portgroup at vCenter and set it in enabled state.
                self._create_portgroup(element, host)
                LOG.debug("Invoking update_device_up for port %s.",
                          element['id'])
                try:
                    # set admin_state to True
                    self.plugin_rpc.update_device_up(
                        self.context,
                        element['id'],
                        self.agent_id,
                        self.agent_state['host'])
                except Exception as e:
                    LOG.exception(_("update_device_up failed for port: %s."),
                                  element['id'])
                    raise error.OVSvAppNeutronAgentError(e)
                self.update_port_bindings.append(element['id'])
                # TODO(romilg): Revisit for VXLAN, update_port_bindings must
                # be done much before update_device_up.

    def device_create(self, context, **kwargs):
        """Gets the port details from plugin using RPC call."""

        LOG.info(_("OVSvApp Agent - device create RPC received."))
        device = kwargs.get('device')
        device_id = device['id']
        cluster_id = device['cluster_id']
        vcenter_id = device['vcenter']
        LOG.debug("device_create notification for VM %s.", device_id)
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
        if host == self.esx_hostname:
            if sg_rules:
                self.sg_agent.ovsvapp_sg_update(sg_rules[device_id])

    def _port_update_status_change(self, network_model, port_model):
        retry_count = 3
        while retry_count > 0:
            try:
                self.net_mgr.get_driver().update_port(network_model,
                                                      port_model,
                                                      None)
                break
            except Exception as e:
                LOG.exception(_("Failed to update port %s."),
                              port_model.uuid)
                retry_count -= 1
                if retry_count == 0:
                    raise error.OVSvAppNeutronAgentError(e)
                time.sleep(2)

    def port_update(self, context, **kwargs):
        """Update the port details from plugin using RPC call."""

        LOG.info(_("OVSvApp Agent - port update RPC received."))
        LOG.debug("port_update arguments : %s.", kwargs)
        new_port = kwargs.get('port')
        new_port['segmentation_id'] = kwargs.get('segmentation_id')
        ovsvapplock.acquire()
        old_port_object = None
        new_port_object = None
        try:
            if new_port['id'] not in self.ports_dict.keys():
                return
            else:
                old_port_object = self.ports_dict[new_port['id']]
                self.ports_dict[new_port['id']] = self._build_port_info(
                    new_port)
                new_port_object = self.ports_dict[new_port['id']]
                # TODO(romilg): With the introduction of following feature
                # 'port mac-address modification', When the mac-address gets
                # changed for a port we will need to rewrite the rules in
                # OVS-Firewall.
        finally:
            ovsvapplock.release()

        if old_port_object and new_port_object:
            if cmp(old_port_object.admin_state_up,
                   new_port_object.admin_state_up) != 0:
                LOG.debug("Updating admin_state_up status for %s.",
                          new_port['id'])
                network, port = self._map_port_to_common_model(new_port)
                self._port_update_status_change(network, port)
            self.sg_agent.devices_to_refilter.add(new_port['id'])
            try:
                if new_port['admin_state_up']:
                    LOG.debug("Invoking update_device_up for %s.",
                              new_port['id'])
                    self.plugin_rpc.update_device_up(self.context,
                                                     new_port['id'],
                                                     self.agent_id,
                                                     self.hostname)
                else:
                    LOG.debug("Invoking update_device_down for %s.",
                              new_port['id'])
                    self.plugin_rpc.update_device_down(self.context,
                                                       new_port['id'],
                                                       self.agent_id,
                                                       self.hostname)
            except Exception as e:
                LOG.exception(_("update device up/down failed for port: %s."),
                              new_port['id'])
                raise error.OVSvAppNeutronAgentError(e)
            LOG.info(_("OVSvApp Agent - port update finished."))

    def device_delete(self, context, **kwargs):
        """Delete the portgroup, flows and reclaim lvid for a VXLAN network."""

        LOG.info(_("OVSvApp Agent - device delete RPC received."))


class RpcPluginApi(agent_rpc.PluginApi):

    def __init__(self):
        super(RpcPluginApi, self).__init__(topic=topics.PLUGIN)


class OVSvAppPluginApi(object):

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_ports_for_device(self, context, device, agent_id, host):
        cctxt = self.client.prepare()
        LOG.info(_("RPC get_ports_for_device is called for device_id: %s."),
                 device['id'])
        return cctxt.call(context, 'get_ports_for_device', device=device,
                          agent_id=agent_id, host=host)

    def update_port_binding(self, context, agent_id, port_id, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_port_binding', agent_id=agent_id,
                          port_id=port_id, host=host)

    def get_ports_details_list(self, context, port_ids, agent_id,
                               vcenter_id, cluster_id):
        cctxt = self.client.prepare()
        LOG.info(_("RPC get_ports_details_list is called with port_ids: %s."),
                 port_ids)
        return cctxt.call(context, 'get_ports_details_list', port_ids=port_ids,
                          agent_id=agent_id, vcenter_id=vcenter_id,
                          cluster_id=cluster_id)
