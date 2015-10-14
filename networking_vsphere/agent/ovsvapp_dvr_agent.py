import collections
import eventlet

from oslo_config import cfg
from oslo_log import log
from six import moves
import time

from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron._i18n import _LW
from neutron.agent.common.ovs_lib import VifPort
from neutron.agent.linux import polling as linux_polling

from neutron.common import constants as n_const
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import\
    constants as ovs_const
from neutron.plugins.ml2.drivers.openvswitch.agent import\
    ovs_dvr_neutron_agent as ovs_dvr_agent
from neutron.plugins.ml2.drivers.openvswitch.agent import\
    ovs_neutron_agent as ovs_agent


LOG = log.getLogger(__name__)
CONF = cfg.CONF
DEAD_VLAN_TAG = p_const.MAX_VLAN_TAG + 1


class OVSvAppDvrAgent(ovs_agent.OVSNeutronAgent):

    def __init__(self):

        self.prevent_arp_spoofing = CONF.AGENT.prevent_arp_spoofing
        self.polling_interval = CONF.AGENT.polling_interval
        self.minimize_polling = CONF.AGENT.minimize_polling
        self.ovsdb_monitor_respawn_interval = (
            CONF.AGENT.ovsdb_monitor_respawn_interval or
            ovs_const.DEFAULT_OVSDBMON_RESPAWN)

        self.run_check_for_router_port_updates = True
        self.enable_distributed_routing = (
            self.conf.AGENT.enable_distributed_routing)
        self.patch_int_ofport = ovs_const.OFPORT_INVALID
        self.patch_tun_ofport = ovs_const.OFPORT_INVALID

        # Keep track of int_br's device count for use by _report_state()
        self.int_br_device_count = 0

        self.available_local_vlans = set(moves.range(p_const.MIN_VLAN_TAG,
                                                     p_const.MAX_VLAN_TAG))

        self.init_extension_manager(self.connection)

        self.network_ports = collections.defaultdict(set)
        self._restore_local_vlan_map()

        self.polling_manager = None
        self.sync = False
        self.current_ports = set()
        self.updated_ports = set()
        self.deleted_ports = set()
        self.updated_ports_copy = set()
        self.current_ancillary_ports = set()
        self.tunnels_are_synced = True
        self.consecutive_resyncs = 0
        self.need_clean_stale_flow = True
        self.ports_not_ready_yet = set()
        self.failed_devices = {'added': set(), 'removed': set()}
        self.failed_ancillary_devices = {'added': set(), 'removed': set()}
        self.failed_devices_retries_map = {}
        self.failed_devices = {'added': set(), 'removed': set()}
        self.failed_ancillary_devices = {'added': set(), 'removed': set()}
        self.failed_devices_retries_map = {}
        self.list_of_untagged_devices = {}
        self.iter_num = 0
        self.fullsync = False
        self._local_vlan_hints = {}
        self.dvr_plugin_rpc = None
        self._local_vlan_hints = {}
        self._network_router_ports = {}
        self.dvr_agent = ovs_dvr_agent.OVSDVRNeutronAgent(
            self.context,
            self.dvr_plugin_rpc,
            self.int_br,
            self.tun_br,
            self.bridge_mappings,
            self.phys_brs,
            self.int_ofports,
            self.phys_ofports,
            self.patch_int_ofport,
            self.patch_tun_ofport,
            self.hostname,
            self.enable_tunneling,
            self.enable_distributed_routing)
        # Collect additional bridges to monitor
        self.ancillary_brs = self.setup_ancillary_bridges(
            self.conf.OVS.integration_bridge, self.conf.OVS.tunnel_bridge)

    def check_changed_vlans(self):
        """Return ports which have lost their vlan tag.

        The returned value is a set of port ids of the ports concerned by a
        vlan tag loss.
        """
        port_tags = self.int_br.get_port_tag_dict()
        changed_ports = set()
        for lvm in self.local_vlan_map.values():
            for port in lvm.vif_ports.values():
                if (
                    isinstance(port, VifPort) and
                    port.port_name in port_tags and
                    port_tags[port.port_name] != lvm.vlan
                ):
                    LOG.info(
                        _LI("Port '%(port_name)s' has lost "
                            "its vlan tag '%(vlan_tag)d'!"),
                        {'port_name': port.port_name,
                         'vlan_tag': lvm.vlan}
                    )
                    changed_ports.add(port.vif_id)
        return changed_ports

    def _initialize_router_ports_data_structures(self):
        self.ports_not_ready_yet = set()
        self.failed_devices = {'added': set(), 'removed': set()}
        self.failed_ancillary_devices = {'added': set(), 'removed': set()}
        self.failed_devices_retries_map = {}
        self.current_ancillary_ports = set()
        self.current_ports = set()
        self.sync = False
        self.consecutive_resyncs = 0
        self.need_clean_stale_flow = True

    def treat_devices_removed(self, devices):
        for device in devices:
            self.sg_agent.remove_devices_filter(device)
            LOG.info(_LI("Port %s removed"), device)
        devices_down = self.plugin_rpc.update_device_list(self.context,
                                                          [],
                                                          devices,
                                                          self.agent_id,
                                                          self.conf.host)
        failed_devices = set(devices_down.get('failed_devices_down'))
        LOG.debug("Port removal failed for %s", failed_devices)
        for device in devices:
            self.port_unbound(device)
        return failed_devices

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   ovs_restarted):
        """Bind port to net_uuid/lsw_id

        If the port if found in the local_vlan_map it si bound to
        net_uuid/lsw_id and flows for inbound traffic to vm are installed
        :param ovs_restarted:
        :param device_owner:
        :param fixed_ips:
        :param segmentation_id:
        :param physical_network:
        :param network_type:
        :param net_uuid:
        :param net_uuid:
        :param port:

        """
        if net_uuid not in self.local_vlan_map:
            self._add_to_untagged_devices(port, net_uuid)
            return True
        self._remove_from_untagged_devices(port)
        if net_uuid in self._network_router_ports.keys():
            self._network_router_ports[net_uuid].update({port.port_name: port})
        else:
            self._network_router_ports[net_uuid] = {port.port_name: port}

        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port.vif_id] = port

        self.dvr_agent.bind_port_to_dvr(port, lvm,
                                        fixed_ips,
                                        device_owner)
        port_other_config = self.int_br.db_get_val("Port", port.port_name,
                                                   "other_config")
        if port_other_config is None:
            if port.vif_id in self.deleted_ports:
                LOG.debug("Port %s deleted concurrently", port.vif_id)
            elif port.vif_id in self.updated_ports:
                LOG.error(_LE("Expected port %s not found"), port.vif_id)
            else:
                LOG.debug("Unable to get config for port %s", port.vif_id)
            return False

        vlan_mapping = {'net_uuid': net_uuid,
                        'network_type': network_type,
                        'physical_network': physical_network}
        if segmentation_id is not None:
            vlan_mapping['segmentation_id'] = segmentation_id
        port_other_config.update(vlan_mapping)
        self.int_br.set_db_attribute("Port", port.port_name, "other_config",
                                     port_other_config)
        return True

    def _add_to_untagged_devices(self, port, net_uuid):
        """Adds port to list of untagged devices along with the net_uuid

        :param port: an ovs_lib.VifPort object
        :param net_uuid:  The net_uuid this port is associated with
        :return:  nothing
        """
        self.list_of_untagged_devices[port.port_name] = {'port': port,
                                                         'net_uuid': net_uuid}

    def _remove_from_untagged_devices(self, port):
        if port.port_name in self.list_of_untagged_devices:
            del self.list_of_untagged_devices[port.port_name]

    def process_port_info(self, start, polling_manager, sync, ovs_restarted,
                          ports, ancillary_ports, updated_ports_copy,
                          consecutive_resyncs, ports_not_ready_yet,
                          failed_devices, failed_ancillary_devices):
        if sync:
            LOG.info(_LI("Agent out of sync with plugin!"))
            consecutive_resyncs += 1
            if (consecutive_resyncs >=
                    n_const.MAX_DEVICE_RETRIES):
                LOG.warn(_LW(
                    "Clearing cache of registered ports,"
                    " retries to resync were > %s"),
                    n_const.MAX_DEVICE_RETRIES)
                ports.clear()
                ancillary_ports.clear()
                consecutive_resyncs = 0
            reg_ports = (set() if ovs_restarted else ports)
            # Because this is a full sync (sync=true). We scan all ports
            # with sync = True)
            # scan_ports returns a port_inf{{added:lsit, updated:list, etc...
            port_info = self.scan_ports(reg_ports, sync,
                                        updated_ports_copy)
            # Treat ancillary devices if they exist
            if self.ancillary_brs:
                ancillary_port_info = self.scan_ancillary_ports(
                    ancillary_ports, sync)
                LOG.debug("Agent rpc_loop - iteration:%(iter_num)d"
                          " - ancillary port info retrieved. "
                          "Elapsed:%(elapsed).3f",
                          {'iter_num': self.iter_num,
                           'elapsed': time.time() - start})
            else:
                ancillary_port_info = {}

        else:
            # If this is not a full sync the we process port events.
            consecutive_resyncs = 0
            events = polling_manager.get_events()
            port_info, ancillary_port_info, ports_not_ready_yet = (
                self.process_ports_events(events, ports, ancillary_ports,
                                          ports_not_ready_yet,
                                          failed_devices,
                                          failed_ancillary_devices,
                                          updated_ports_copy))
        return (port_info, ancillary_port_info, consecutive_resyncs,
                ports_not_ready_yet)

    def _process_dvr_port_updates(self, polling_manager=None):
        """Processes any newly created, updated, or deleted router ports.

        It will also handle any request for a full sync (reprocess all known
        ports) as well as an agent retart.

        The list of ports to process is obtained from the following sources:

        self.updated_ports : a list of ports which can be added to by
        other methods of the class

        self.failed_rotuer_devices: a list of router devices (ports) which
        were marked as failed the last time this method was called.

        self.failed_ancillary_devices: a list of ancillary router
        devices (ports) whcih were marked as failed the last time this method
        was called.

        self.ports_not_ready_yet: a list of ports which were deemed
        "not ready" the last time this method was called. For example, a router
        port which had not been instantiated on the ovs-bridge but was already
        listed in the self.updated_ports list. It mitigates timing
        issues between the L3 agent and the L2 (ovsvapp) agent.

        polling_manager: a polling_manager process which monitors the ovs
        bridges for any new ports being created on it by the L3 agent. For
        example the router interfaces on the br-int bridge created by the l3
        agent when it runs on dvr agent mode.
        """
        ovs_restarted = self._handle_ovs_restart(polling_manager)

        # Get the list of devices which need to be retried
        if self._router_port_processing_required(polling_manager):
            start = time.time()
            # Keep a copy of the updated_ports list
            # so that we can recover in case an excpetion is thrown
            updated_ports_copy = self.updated_ports
            self.updated_ports = set()

            try:

                # Get port information for all the ports we need to
                # process. port_info and ancillary_port_info will contain
                # added, updated, and removed sets of ports
                # each set of ports is made up of vifports
                (port_info,
                 ancillary_port_info) = self._collect_port_info(
                    start, polling_manager, ovs_restarted, updated_ports_copy)

                # Handle deleted ports
                self._handle_deleted_ports(port_info)

                # Handle any changes on the ofports (ports in the output of the
                # "ovs-ofctl show <bridge-name>" command).
                # Arp spoofind rules are the only things that use
                # ofport-based rules. so if arp spoofing is off the following
                # does nothing.
                self._handle_ofport_changes(port_info)

                # Process any new or updated ports and also handle ovs restart
                self._handle_new_port_info_change_or_ovs_restarted(
                    port_info, ovs_restarted)

                # update the list of current router ports
                self.current_ports = port_info['current']

                # process any ancillary ports
                self._handle_ancillary_ports(ancillary_port_info)

                # Signal polling manager that processing is done.
                polling_manager.polling_completed()

                # Update the list of failed router devices we will retry
                # next time.
                self._update_failed_devices_to_try_next_time()

                # clean up the local vlan hinst
                self._update_local_vlan_hints()

            except Exception:
                LOG.exception(_LE("Error while processing VIF router ports"))
                # Put the ports back in self.updated_port
                self.updated_ports |= updated_ports_copy
                self.sync = True

    def _router_port_processing_required(self, polling_manager):

        # Get the list of devices which need to be retried
        devices_with_tags = self._tagg_untagged_devices()
        self.ports_not_ready_yet.update(devices_with_tags)
        devices_need_retry = (any(self.failed_devices.values()) or
                              any(self.failed_ancillary_devices.values()
                                  ) or
                              self.ports_not_ready_yet)

        # Start processing any ports that need attention or do a full sync
        # if requested
        if (self._agent_has_updates(polling_manager) or self.sync or
                devices_need_retry):
            return True
        return False

    def _handle_ovs_restart(self, polling_manager):
        ovs_status = self.check_ovs_status()
        ovs_restarted = False
        ovs_restarted |= (ovs_status == ovs_const.OVS_RESTARTED)

        if ovs_restarted:
            if isinstance(polling_manager,
                          linux_polling.InterfacePollingMinimizer):
                    polling_manager.stop()
                    polling_manager.start()
        return ovs_restarted

    def _collect_port_info(self, start, polling_manager, ovs_restarted,
                           updated_ports_copy):
        (port_info, ancillary_port_info, self.consecutive_resyncs,
         self.ports_not_ready_yet) = (
            self.process_port_info(
                start,
                polling_manager,
                self.sync,
                ovs_restarted,
                self.current_ports,
                self.current_ancillary_ports,
                updated_ports_copy,
                self.consecutive_resyncs,
                self.ports_not_ready_yet,
                self.failed_devices,
                self.failed_ancillary_devices
            )
        )
        self.sync = False
        return port_info, ancillary_port_info

    def _handle_ofport_changes(self, port_info):
        ofport_changed_ports = self.update_stale_ofport_rules()
        if ofport_changed_ports:
            port_info.setdefault('updated', set()).update(
                ofport_changed_ports)

    def _handle_ancillary_ports(self, ancillary_port_info):
        if self.ancillary_brs:
            self.failed_ancillary_devices = (
                self.process_ancillary_network_ports(
                    ancillary_port_info))
            self.current_ancillary_ports = (
                ancillary_port_info['current'])

    def _handle_new_port_info_change_or_ovs_restarted(self, port_info,
                                                      ovs_restarted):
        if self._port_info_has_changes(port_info) or ovs_restarted:
            LOG.debug("Starting to process devices in:%s", port_info)
            # process_network_ports returns a complete dictionary of failed
            # devices of the form
            self.failed_devices = self.process_network_ports(
                port_info, ovs_restarted)
            if self.need_clean_stale_flow:
                self.cleanup_stale_flows()
                self.need_clean_stale_flow = False

    def _handle_deleted_ports(self, port_info):
            self.process_deleted_ports(port_info)

    def _update_failed_devices_to_try_next_time(self):
        self.failed_devices_retries_map = (
            self.update_retries_map_and_remove_devs_not_to_retry(
                self.failed_devices,
                self.failed_ancillary_devices,
                self.failed_devices_retries_map))

    def _update_local_vlan_hints(self):
        self._dispose_local_vlan_hints()

    def process_deleted_ports(self, port_info):
        """Processes deleted ports derived from port_info

        - Remove all ports in port_info['removed'] queue from the global list
          of deleted ports

        - Start processing all ports left in the global list of deleted ports

        - For each port id in global deleted_ports:
            Remove port from list of untagged devices.
            Remove port from global list of untagged devices.
            Notify  all agent extensions to delete port.
            Move port to dead VLAN.
            Unbind port.

        :param port_info: a dictionary of sets with port information
        :return:
        """
        # don't try to process removed ports as deleted ports since
        # they are already gone.
        # Take out any ports marked as 'removed' in port_info from the
        # global list of "deleted" ports
        if 'removed' in port_info:
            self.deleted_ports -= port_info['removed']
        deleted_ports = list(self.deleted_ports)

        # Now process all deleted ports in self.deleted_ports
        while self.deleted_ports:
            # Get a port from the deleted_port queue
            port_id = self.deleted_ports.pop()

            # process port (delete and unbind)
            self._delete_and_unbind_vif_port(port_id)
        # Flush firewall rules after ports are put on dead VLAN to be
        # more secure
        self.sg_agent.remove_devices_filter(deleted_ports)

    def _delete_and_unbind_vif_port(self, port_id):
        """Delete and unbind vifport

        Create Port object from port_id
        Use port object to remove port from list of untagged devices.
        Remove port from the map of network_ids to network ports
        Notify  all agent extensions to delete port.
        Move port to dead VLAN.
        Unbind port.

        :param port:
        :return:
        """
        # create a vifport from it
        port = self.int_br.get_vif_port_by_id(port_id)

        # remove port from global list of untagged devices
        self._remove_from_untagged_devices(port)

        # remove the port from the map of network_ids to network ports
        self._clean_network_ports(port_id)

        # Notify  all agent extensions to delete port
        self.ext_manager.delete_port(self.context,
                                     {"vif_port": port,
                                      "port_id": port_id})

        # Move port to dead VLAN.
        # so deleted ports no longer have access to the network
        if port:
            # don't log errors since there is a chance someone will be
            # removing the port from the bridge at the same time
            self.port_dead(port, log_errors=False)

        # Unbind port
        self.port_unbound(port_id)

    def _tagg_untagged_devices(self):
        _set = set()
        for port_name in self.list_of_untagged_devices.keys():
            device = self.list_of_untagged_devices[port_name]
            if device['net_uuid'] in self.local_vlan_map:
                _set.add(device['port'].port_name)
        return _set

    def _restore_local_vlan_map(self):
        # currently there is not way for the local_vlan_map to survive
        # a restarte of the agent.  If the agent is restarted.
        # self.local_vlan_map is empty. That is NOT GOOD. There will be no
        # way for new routers to figure out what vlan tags to use for networks
        # that have vms attached to them that were created before restart!!!!

        self._local_vlan_hints = {}
        cur_ports = self.int_br.get_vif_ports()
        port_names = [p.port_name for p in cur_ports]
        port_info = self.int_br.get_ports_attributes(
            "Port", columns=["name", "other_config", "tag"], ports=port_names)
        by_name = {x['name']: x for x in port_info}
        for port in cur_ports:
            # if a port was deleted between get_vif_ports and
            # get_ports_attributes, we
            # will get a KeyError
            try:
                local_vlan_map = by_name[port.port_name]['other_config']
                local_vlan = by_name[port.port_name]['tag']
            except KeyError:
                continue
            if not local_vlan:
                continue
            net_uuid = local_vlan_map.get('net_uuid')
            if (net_uuid and
                    net_uuid not in self._local_vlan_hints and
                    local_vlan != DEAD_VLAN_TAG):
                if local_vlan in self.available_local_vlans:
                    self.available_local_vlans.remove(local_vlan)
                self._local_vlan_hints[local_vlan_map['net_uuid']] = \
                    local_vlan

    def port_unbound(self, vif_id, net_uuid=None):
        """Unbind port.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.
        """

        # if no net_uuid provided go look for it in local_vlan_map
        if net_uuid is None:
            net_uuid = self.get_net_uuid(vif_id)

        if not self.local_vlan_map.get(net_uuid):
            LOG.info(_LI('port_unbound(): net_uuid %s not in local_vlan_map'),
                     net_uuid)
            self._remove_from_untagged_devices_by_vif_id(vif_id)
            return

        lvm = self.local_vlan_map[net_uuid]

        # If the vif_id corresponds to one of the vif_ports listed in the lvm
        # dvr_unbind_it
        if vif_id in lvm.vif_ports:
            vif_port = lvm.vif_ports[vif_id]
            #
            self.dvr_agent.unbind_port_from_dvr(vif_port, lvm)
        # once it has been unbound, remove iti from the lvm list of ports.
        lvm.vif_ports.pop(vif_id, None)

    def check_for_router_port_updates(self, polling_manager=None):
        while self.run_check_for_router_port_updates:
            self._process_dvr_port_updates(polling_manager)
            eventlet.greenthread.sleep(1)

    def _untagg_router_ports(self, network_id):
        if network_id in self._network_router_ports:
            for port in self._network_router_ports[network_id].values():
                self._add_to_untagged_devices(port, network_id)
                self.int_br.clear_db_attribute("Port", port.port_name, "tag")
            self._network_router_ports.pop(network_id)
