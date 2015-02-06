# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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

import sys
import threading
import time

from oslo.config import cfg
from oslo import messaging

from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as neutron_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.agent import ovs_neutron_agent as ovs_agent

from networking_vsphere.agent import agent
from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.common import error
from networking_vsphere.common import model
from networking_vsphere.common import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

ovsvapplock = threading.RLock()
ports_dict = {}
network_port_count = {}


class portInfo():
    def __init__(self, vlanid, mac_addr, sec_gps, fixed_ips, admin_state_up,
                 network_id, vm_uuid):
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
        neutron_config.init(sys.argv[1:])
        neutron_config.setup_logging()
        self.esx_hostname = CONF.VMWARE.esx_hostname
        self.cluster_id = None
        self.cluster_devices = set()
        self.devices_to_filter = set()
        self.cluster_host_ports = set()
        self.cluster_other_ports = set()
        self.update_port_bindings = []
        self.refresh_firewall_required = False
        self.use_call = True
        self.hostname = cfg.CONF.host
        self.bridge_mappings = CONF.OVSVAPP.bridge_mappings
        self.tunnel_types = []
        self.agent_state = {
            'binary': 'ovsvapp-agent',
            'host': self.hostname,
            'topic': topics.AGENT,
            'configurations': {'bridge_mappings': self.bridge_mappings,
                               'tunnel_types': self.tunnel_types},
            'agent_type': ovsvapp_const.AGENT_TYPE_OVSVAPP,
            'start_flag': True}

        self.setup_rpc()
        self.setup_report_states()

    def start(self):
        LOG.info(_("Starting OVSvApp L2 Agent"))
        self.set_node_state(True)

    def stop(self):
        LOG.info(_("Stopping OVSvApp L2 Agent"))
        self.set_node_state(False)
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
                       "Unable to send heartbeats to Neutron Server"))

    def setup_rpc(self):
        # Ensure that the control exchange is set correctly
        self.agent_id = "ovsvapp-agent %s" % self.hostname
        self.topic = topics.AGENT
        self.plugin_rpc = RpcPluginApi()
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.ovsvapp_rpc = OVSvAppPluginApi(ovsvapp_const.OVSVAPP)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [
            [topics.PORT, topics.UPDATE],
            [ovsvapp_const.DEVICE, topics.CREATE],
            [ovsvapp_const.DEVICE, topics.UPDATE],
            [topics.SECURITY_GROUP, topics.UPDATE]
        ]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        LOG.debug("Finished Setup RPC")

    def process_event(self, event):
        """Override the callback method for NetworkDriverCallback."""

        try:
            LOG.debug("Handling event %(event_type)s for %(src_obj)s",
                      {'event_type': event.event_type,
                       'src_obj': event.src_obj})
            vm = event.src_obj
            host = event.host_name
            if event.event_type == ovsvapp_const.VM_CREATED:
                if not self.cluster_id:
                    self.cluster_id = event.cluster_id
                    LOG.info(_("Setting the cluster id: %s"), self.cluster_id)
                self._notify_device_added(vm, host, event.cluster_id)
            elif event.event_type == ovsvapp_const.VM_UPDATED:
                self._notify_device_updated(vm, host)
            elif event.event_type == ovsvapp_const.VM_DELETED:
                self._notify_device_deleted(vm, host)
            else:
                LOG.debug("Ignoring event %s", event)
        except Exception as e:
            LOG.error(_("This may result in failure of network "
                        "provisioning for %(name)s %(uuid)s"),
                      {'name': event.src_obj.__class__.__name__,
                       'uuid': event.src_obj.uuid})
            LOG.exception(_("Cause of failure %s") % str(e))

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
    def _notify_device_added(self, vm, host, cluster_id):
        """Handle VM created event."""
        self.cluster_devices.add(vm.uuid)
        if len(vm.vnics) > 0:
            # This is for existing VM
            ovsvapplock.acquire()
            self.refresh_firewall_required = True
            for vnic in vm.vnics:
                self.devices_to_filter.add(vnic.port_uuid)
                self._add_ports_to_host_ports([vnic.port_uuid],
                                              host == self.esx_hostname)
            ovsvapplock.release()
        else:
            if host == self.esx_hostname:
                device = {'id': vm.uuid,
                          'host': host,
                          'cluster_id': cluster_id}
                retry = True
                iteration = 1
                while retry:
                    try:
                        # Make RPC call to plugin to get port details
                        status = self.ovsvapp_rpc.get_ports_for_device(
                            self.context, device, self.agent_id)
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
                                        "device: %s") % device['id'])
                        raise error.OVSvAppNeutronAgentError(e)

    @utils.require_state([ovsvapp_const.AGENT_RUNNING])
    def _notify_device_updated(self, vm, host):
        """Handle VM updated event."""
        try:
            if host == self.esx_hostname:
                for vnic in vm.vnics:
                    self._add_ports_to_host_ports([vnic.port_uuid])
                    LOG.debug("Invoking update_port_binding for port %s",
                              vnic.port_uuid)
                    self.ovsvapp_rpc.update_port_binding(
                        self.context, agent_id=self.agent_id,
                        port_id=vnic.port_uuid, host=self.hostname)
            else:
                for vnic in vm.vnics:
                    self._add_ports_to_host_ports([vnic.port_uuid], False)
        except Exception as e:
            LOG.exception(_("Failed to update port bindings for device: %s"),
                          vm.uuid)
            raise error.OVSvAppNeutronAgentError(e)

    def _delete_portgroup(self, del_port):
        network = model.Network(name=del_port.network_id,
                                network_type=ovsvapp_const.NETWORK_VLAN)
        retry_count = 3
        while retry_count > 0:
            try:
                LOG.debug("Deleting port group from vCenter: %s",
                          del_port.network_id)
                self.net_mgr.get_driver().delete_network(network)
                break
            except Exception as e:
                LOG.exception(_("Failed to delete network %s"),
                              del_port.network_id)
                retry_count -= 1
                if retry_count == 0:
                    raise error.OVSvAppNeutronAgentError(e)
                time.sleep(2)

    def _process_delete_pg_vlan_novnic(self, host, vm):
        ovsvapplock.acquire()
        try:
            for port in ports_dict.keys():
                port_count = -1
                if ports_dict[port].vm_uuid == vm.uuid:
                    network_port_count[ports_dict[port].network_id] -= 1
                    port_count = (
                        network_port_count[ports_dict[port].network_id])
                    LOG.debug("Port count per network details after VM "
                              "deletion: %s", network_port_count)
                    # Clean up ports_dict for the deleted port
                    del_port = ports_dict[port]
                    if port in self.cluster_host_ports:
                        self.cluster_host_ports.remove(port)
                    elif port in self.cluster_other_ports:
                        self.cluster_other_ports.remove(port)

                    # TODO(romilg): Uncomment the line below once
                    # OVSVAppSecurityGroupAgent is added.
                    # self.sg_agent.remove_devices_filter(port)

                    ports_dict.pop(port)
                    # Remove port count tracking per network when
                    # last VM associated with the network is deleted
                    if port_count == 0:
                        network_port_count.pop(del_port.network_id)
                        if host == self.esx_hostname:
                            self._delete_portgroup(del_port)
                    break
            self.net_mgr.get_driver().post_delete_vm(vm)
        finally:
            ovsvapplock.release()

    def _process_delete_portgroup_vlan(self, host, vm, vnic, del_port):
        ovsvapplock.acquire()
        port_count = -1
        try:
            if del_port.network_id in network_port_count.keys():
                network_port_count[del_port.network_id] -= 1
                port_count = network_port_count[del_port.network_id]
                # Remove port count tracking per network when
                # last VM associated with the network is deleted
                if port_count == 0:
                    network_port_count.pop(del_port.network_id)
                LOG.debug("Port count per network details after VM "
                          "deletion: %s", network_port_count)
                # Clean up ports_dict for the deleted port
                ports_dict.pop(vnic.port_uuid)
            else:
                LOG.debug("Network %s does not exist in "
                          "network_port_count", del_port.network_id)
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
        self.cluster_devices.remove(vm.uuid)
        LOG.warn(_("Deleting VM %s"), vm.uuid)
        if not vm.vnics:
            LOG.debug("Deletion of VM with no vnics %s" % vm.uuid)
            self._process_delete_pg_vlan_novnic(host, vm)
            return

        for vnic in vm.vnics:
            LOG.info(_("Deleting port %(port)s with mac address %(mac)s"),
                     {'port': vnic.port_uuid, 'mac': vnic.mac_address})
            if not vnic.port_uuid:
                LOG.info(_("Port id for vnic with mac address %s not present"),
                         vnic.mac_address)
            else:
                del_port = None
                if vnic.port_uuid in self.cluster_host_ports:
                    self.cluster_host_ports.remove(vnic.port_uuid)
                elif vnic.port_uuid in self.cluster_other_ports:
                    self.cluster_other_ports.remove(vnic.port_uuid)
                ovsvapplock.acquire()
                try:
                    if vnic.port_uuid in ports_dict.keys():
                        # TODO(romilg): Uncomment the line below once
                        # OVSVAppSecurityGroupAgent is added.
                        # self.sg_agent.remove_devices_filter(vnic.port_uuid)
                        LOG.info(_("Delete port %(port)s with mac %(mac)s "
                                   "finished"), {'port': vnic.port_uuid,
                                                 'mac': vnic.mac_address})
                        del_port = ports_dict[vnic.port_uuid]
                    else:
                        LOG.debug("Port id %s is not available in "
                                  "ports_dict", vnic.port_uuid)
                finally:
                    ovsvapplock.release()
                    if del_port is not None:
                        if self.tenant_network_type == p_const.TYPE_VLAN:
                            self._process_delete_portgroup_vlan(host, vm,
                                                                vnic, del_port)

    def _build_port_info(self, port):
        return portInfo(port['segmentation_id'],
                        port['mac_address'],
                        port['security_groups'],
                        port['fixed_ips'],
                        port['admin_state_up'],
                        port['network_id'],
                        port['device_id'])

    def _map_port_to_common_model(self, port_info):
        """Map the port and network objects to vCenter objects."""

        port_id = port_info['id']
        segmentation_id = port_info.get('segmentation_id')
        if self.tenant_network_type == p_const.TYPE_VLAN:
            network_id = port_info.get('network_id')
        device_id = port_info.get('device_id')
        fixed_ips = port_info.get('fixed_ips')
        mac_address = port_info.get('mac_address')
        port_status = (ovsvapp_const.PORT_STATUS_UP
                       if port_info.get('admin_state_up')
                       else ovsvapp_const.PORT_STATUS_DOWN)

        # Create Common Model Network Object
        if self.tenant_network_type == p_const.TYPE_VLAN:
            vlan = model.Vlan(vlanIds=[segmentation_id])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name=network_id,
            network_type=ovsvapp_const.NETWORK_VLAN,
            config=network_config)

        # Create Common Model Port Object
        port = model.Port(
            uuid=port_id,
            name=None,
            mac_address=mac_address,
            vm_id=device_id,
            network_uuid=network_id,
            ipaddresses=fixed_ips,
            port_status=port_status)
        return network, port

    def _create_portgroup(self, port_info, host):
        """Create port group based on port information."""

        LOG.debug("OVSvApp Agent - port group create started")
        if host == self.esx_hostname:
            network, port = self._map_port_to_common_model(port_info)
            retry_count = 3
            while retry_count > 0:
                try:
                    self.net_mgr.get_driver().create_port(network, port, None)
                    break
                except Exception as e:
                    LOG.error(_("Failed to create network %s ") % network.name)
                    retry_count -= 1
                    if retry_count == 0:
                        LOG.exception(_("Failed to create network %s ")
                                      % network.name)
                        raise error.NeutronAgentError(e)
                    time.sleep(2)
        LOG.debug(_("OVSvApp Agent - port group create finished"))

    def _process_create_portgroup_vlan(self, context, ports_list, host):
        ovsvapplock.acquire()
        try:
            # TODO(romilg): Uncomment the line below once
            # OVSVAppSecurityGroupAgent is added.
            # self.sg_agent.add_devices_to_filter(ports_list)

            for element in ports_list:
                ports_dict[element['id']] = self._build_port_info(element)
                if element['network_id'] not in network_port_count.keys():
                    network_port_count[element['network_id']] = 1
                else:
                    network_port_count[element['network_id']] += 1
        finally:
            LOG.debug("Port count per network details after VM creation: %s",
                      network_port_count)
            ovsvapplock.release()

        if host == self.esx_hostname:
            for element in ports_list:
                # Create a portgroup at vCenter and set it in enabled state
                self._create_portgroup(element, host)
                LOG.debug("Invoking update_device_up for port %s",
                          element['id'])
                try:
                    # set admin_state to True
                    self.plugin_rpc.update_device_up(
                        self.context,
                        element['id'],
                        self.agent_id,
                        self.agent_state['host'])
                except Exception as e:
                    LOG.exception(_("update_device_up failed for port: %s"),
                                  element['id'])
                    raise error.NeutronAgentError(e)
                self.update_port_bindings.append(element['id'])

    def device_create(self, context, **kwargs):
        """Gets the port details from plugin using RPC call."""

        LOG.info(_("OVSvApp Agent - device create received"))
        device = kwargs.get('device')
        device_id = device['id']
        cluster_id = device['cluster_id']
        LOG.debug("device_create notification for VM %s", device_id)
        if cluster_id != self.cluster_id:
            LOG.debug("Cluster mismatch ..ignoring device_create rpc")
            return
        ports_list = kwargs.get('ports')
        # TODO(romilg): Uncomment the line below once
        # OVSVAppSecurityGroupAgent is added.
        # sg_rules = kwargs.get("sg_rules")
        host = device['host']
        LOG.debug("Received Port list: %s", ports_list)
        port_ids = [port['id'] for port in ports_list]
        if host == self.esx_hostname:
            self._add_ports_to_host_ports(port_ids)
        else:
            self._add_ports_to_host_ports(port_ids, False)
            ovsvapplock.acquire()
            try:
                self.devices_to_filter = self.devices_to_filter | set(
                    port_ids)
            finally:
                ovsvapplock.release()
            self.refresh_firewall_required = True
        if self.tenant_network_type == p_const.TYPE_VLAN:
            self._process_create_portgroup_vlan(context, ports_list, host)
        # TODO(romilg): Uncomment the code below once
        # OVSVAppSecurityGroupAgent is added.
        # if host == self.esx_hostname:
        #    if sg_rules:
        #        self.sg_agent.ovsvapp_sg_update(sg_rules[device_id])

    def _port_update_status_change(self, network_model, port_model):
        retry_count = 3
        while retry_count > 0:
            try:
                self.net_mgr.get_driver().update_port(network_model,
                                                      port_model,
                                                      None)
                break
            except Exception as e:
                LOG.exception(_("Failed to update port %s"),
                              port_model.uuid)
                retry_count -= 1
                if retry_count == 0:
                    raise error.NeutronAgentError(e)
                time.sleep(2)

    def port_update(self, context, **kwargs):
        """Update the port details from plugin using RPC call."""

        LOG.info(_("OVSvApp Agent - port update received"))
        LOG.debug("port_update arguments : %s", kwargs)
        new_port = kwargs.get('port')
        ovsvapplock.acquire()
        old_port_object = None
        new_port_object = None
        try:
            if new_port['id'] in ports_dict.keys():
                old_port_object = ports_dict[new_port['id']]
                ports_dict[new_port['id']] = self._build_port_info(new_port)
                new_port_object = ports_dict[new_port['id']]
        finally:
            ovsvapplock.release()

        if old_port_object and new_port_object:
            if cmp(old_port_object.admin_state_up,
                   new_port_object.admin_state_up) != 0:
                LOG.debug("Updating admin_state_up status for %s",
                          new_port['id'])
                network, port = self._map_port_to_common_model(new_port)
                self._port_update_status_change(network, port)
            # TODO(romilg): Uncomment the code below once
            # OVSVAppSecurityGroupAgent is added.
            # self.sg_agent.devices_to_refilter.add(new_port['id'])
            try:
                if(new_port['admin_state_up']):
                    LOG.debug("Invoking update_device_up for %s",
                              new_port['id'])
                    self.plugin_rpc.update_device_up(self.context,
                                                     new_port['id'],
                                                     self.agent_id,
                                                     self.hostname)
                else:
                    LOG.debug("Invoking update_device_down for %s",
                              new_port['id'])
                    self.plugin_rpc.update_device_down(self.context,
                                                       new_port['id'],
                                                       self.agent_id,
                                                       self.hostname)
            except Exception as e:
                LOG.exception(_("update device up/down failed for port: %s"),
                              new_port['id'])
                raise error.NeutronAgentError(e)
        else:
            LOG.debug("old_port and new_port objects not available for "
                      "port %s ", new_port['id'])
        LOG.info(_("OVSvApp Agent - port update finished"))


class RpcPluginApi(agent_rpc.PluginApi,
                   sg_rpc.SecurityGroupServerRpcApi):

    def __init__(self):
        super(RpcPluginApi, self).__init__(topic=topics.PLUGIN)


class OVSvAppPluginApi(object):

    def __init__(self, topic):
        target = messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_ports_for_device(self, context, device, agent_id):
        cctxt = self.client.prepare()
        LOG.info(_(" RPC get_ports_for_device is called for device_id: %s"),
                 device['id'])
        return cctxt.call(context, 'get_ports_for_device', device=device,
                          agent_id=agent_id)

    def update_port_binding(self, context, agent_id, port_id, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_port_binding', agent_id=agent_id,
                          port_id=port_id, host=host)