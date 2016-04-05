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
import re
import time

from oslo_log import log
from oslo_vmware import exceptions

from networking_vsphere._i18n import _, _LE, _LI, _LW
from networking_vsphere.common import constants
from networking_vsphere.common import error
from networking_vsphere.common import model
from networking_vsphere.common import utils
from networking_vsphere.drivers import driver
from networking_vsphere.utils import cache
from networking_vsphere.utils import common_util
from networking_vsphere.utils import error_util
from networking_vsphere.utils import network_util
from networking_vsphere.utils import resource_util
from networking_vsphere.utils import vim_session
from networking_vsphere.utils import vim_util

LOG = log.getLogger(__name__)


class VCNetworkDriver(driver.NetworkDriver):

    def __init__(self):
        driver.NetworkDriver.__init__(self)
        self.state = constants.DRIVER_IDLE
        self.clusters_by_id = {}
        self.cluster_id_to_filter = {}
        cache.VCCache.reset()
        self.session = vim_session.ConnectionHandler.get_connection()

    def get_unused_portgroups(self, switch):
        raise NotImplementedError()

    def delete_portgroup(self, switch, pg):
        raise NotImplementedError()

    def is_valid_switch(self, cluster_mor, switch):
        """Validate if the switch is valid for this cluster.

           Makes sure that the switch is present on all the hosts of the
           cluster and returns list of hosts present on the cluster,
           if switch is valid else returns None.
        """
        raise NotImplementedError()

    def delete_stale_portgroups(self, switch):
        LOG.info(_LI("Deleting unused portgroups on %s."), switch)
        port_group_names = self.get_unused_portgroups(switch)
        uuid_regex_vlan = ("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
                           "-[0-9a-f]{4}-[0-9a-f]{12}")
        uuid_regex_vxlan = ("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
                            "-[0-9a-f]{4}-[0-9a-f]{12}-domain-c[0-9]*")
        for port_group in port_group_names:
            if (re.match(uuid_regex_vlan, port_group, re.IGNORECASE) or
                    re.match(uuid_regex_vxlan, port_group, re.IGNORECASE)):
                try:
                    self.delete_portgroup(switch, port_group)
                except Exception as e:
                    LOG.exception(_LE("Failed to delete portgroup %(pg)s from "
                                      "dvs %(dvs)s. Cause : %(err)s"),
                                  {'pg': port_group, 'dvs': switch, 'err': e})

    def validate_cluster_switch_mapping(self, cluster_path, switch):
        """Validate the cluster_switch_mapping."""
        if not cluster_path or not switch:
            return False, None
        cluster_mor = resource_util.get_cluster_mor_by_path(self.session,
                                                            cluster_path)
        if not cluster_mor:
            LOG.error(_LE("Invalid cluster: %s."), cluster_path)
            return False, None
        else:
            if not self.is_valid_switch(cluster_mor, switch):
                LOG.error(_LE("Invalid Switch: %(switch)s for cluster: "
                              "%(path)s."),
                          {'switch': switch, 'path': cluster_path})
                return False, None
            else:
                LOG.info(_LI("Cluster: %(path)s and switch: %(sw)s are "
                             "validated."),
                         {'path': cluster_path, 'sw': switch})
                return True, cluster_mor

    def _find_cluster_id_for_path(self, path):
        return cache.VCCache.get_cluster_id_for_path(path)

    def _unregister_cluster_for_updates(self, cluster_mor):
        property_filter_obj = self.cluster_id_to_filter[cluster_mor.value]
        if property_filter_obj:
            self.session._call_method(self.session._get_vim(),
                                      "DestroyPropertyFilter",
                                      property_filter_obj)

    def _register_cluster_for_updates(self, cluster_mor):
        vm_properties = ['name',
                         'config.extraConfig["nvp.vm-uuid"]',
                         'runtime.host',
                         'config.hardware.device']
        propertyDict = {"VirtualMachine": vm_properties}
        property_filter_spec = self.session._call_method(
            vim_util,
            "get_property_filter_specs",
            propertyDict,
            [cluster_mor])
        property_filter_obj = self.session._call_method(vim_util,
                                                        "create_filter",
                                                        property_filter_spec)
        return property_filter_obj

    def _find_cluster_switch_for_vm(self, device_id):
        cluster_mor = resource_util.get_cluster_mor_for_vm(self.session,
                                                           device_id)
        cluster_path = None
        if cluster_mor:
            cluster_id = cluster_mor.value
            cluster_path = cache.VCCache.get_cluster_path_for_id(cluster_id)
        if not cluster_path:
            raise error.VcenterConfigurationError(_("Cluster for VM %s could "
                                                  "not be determined")
                                                  % device_id)
        switch_name = cache.VCCache.get_switch_for_cluster_path(cluster_path)
        return cluster_mor, cluster_path, switch_name

    def add_cluster(self, cluster_path, switch_name):
        LOG.info(_LI("Adding cluster_switch_mapping %(path)s:%(switch)s."),
                 {'path': cluster_path, 'switch': switch_name})
        if (cluster_path in cache.VCCache.get_cluster_switch_mapping() and
            cache.VCCache.get_switch_for_cluster_path(
                cluster_path) == switch_name):
            LOG.info(_LI("cluster_switch_mapping %(cp)s:%(sw)s already "
                         "present."),
                     {'cp': cluster_path, 'sw': switch_name})
            return
        valid, cluster_mor = self.validate_cluster_switch_mapping(cluster_path,
                                                                  switch_name)
        if not valid:
            if cluster_path in cache.VCCache.get_cluster_switch_mapping():
                LOG.info(_LI("Removing invalid cluster_switch_mapping: "
                         "%(cp)s:%(sw)s."),
                         {'cp': cluster_path, 'sw': switch_name})
                self.remove_cluster(cluster_path, switch_name)
            return
        if cluster_path in cache.VCCache.get_cluster_switch_mapping():
            cluster_id = self._find_cluster_id_for_path(cluster_path)
            if cluster_id == cluster_mor.value:
                LOG.info(_LI("Updating switch name for cluster: "
                         "%(cp)s to %(sw)s."),
                         {'cp': cluster_path, 'sw': switch_name})
                cache.VCCache.add_switch_for_cluster_path(cluster_path,
                                                          switch_name)
                self.delete_stale_portgroups(switch_name)
                return
            else:
                # Now this path points to a different cluster.
                LOG.info(_LI("Removing cluster %(cid)s as now path %(cp)s "
                             "points to a different cluster."),
                         {'cid': cluster_id, 'cp': cluster_path})
                old_clu_mor = self.clusters_by_id[cluster_id]
                if cluster_id in self.cluster_id_to_filter:
                    self._unregister_cluster_for_updates(old_clu_mor)
                    del self.cluster_id_to_filter[cluster_id]
                cache.VCCache.remove_cluster_id(cluster_id)
                if cluster_id in self.clusters_by_id:
                    del self.clusters_by_id[cluster_id]
        LOG.info(_LI("Registering cluster for mapping %(cp)s:%(sw)s."),
                 {'cp': cluster_path, 'sw': switch_name})
        property_filter_obj = self._register_cluster_for_updates(cluster_mor)
        # Cache the cluster.
        cache.VCCache.add_path_for_cluster_id(cluster_mor.value, cluster_path)
        self.clusters_by_id[cluster_mor.value] = cluster_mor
        self.cluster_id_to_filter[cluster_mor.value] = property_filter_obj
        cache.VCCache.add_switch_for_cluster_path(cluster_path,
                                                  switch_name)
        self.delete_stale_portgroups(switch_name)
        if self.state != constants.DRIVER_RUNNING and self.is_connected():
            self.state = constants.DRIVER_READY

    def remove_cluster(self, cluster_path, switch_name):
        mapping = "%s:%s" % (cluster_path, switch_name)
        LOG.info(_LI("Removing cluster_switch_mapping: %s."), mapping)
        if cluster_path not in cache.VCCache.get_cluster_switch_mapping():
            LOG.info(_LI("cluster_switch_mapping %s not present."), mapping)
            return
        cluster_id = self._find_cluster_id_for_path(cluster_path)
        if not cluster_id:
            LOG.info(_LI("Cluster for cluster_switch_mapping %s "
                         "not present in cache."), mapping)
        else:
            LOG.info(_LI("Unregistering cluster for mapping: %s."), mapping)
            cluster_mor = self.clusters_by_id[cluster_id]
            if cluster_id in self.cluster_id_to_filter:
                self._unregister_cluster_for_updates(cluster_mor)
                del self.cluster_id_to_filter[cluster_id]
            cache.VCCache.remove_cluster_id(cluster_id)
        if cluster_id in self.clusters_by_id:
            del self.clusters_by_id[cluster_id]
        cache.VCCache.remove_cluster_path(cluster_path)
        if not cache.VCCache.get_cluster_switch_mapping():
            self.state = constants.DRIVER_IDLE

    def is_connected(self):
        if self.session:
            return True
        else:
            return False

    def stop(self):
        self.pause()
        self.session = None
        self.state = constants.DRIVER_STOPPED

    @utils.require_state(state=[constants.DRIVER_RUNNING], excp=False)
    def pause(self):
        self.session._call_method(vim_util, "cancel_wait_for_updates")
        self.state = constants.DRIVER_READY

    @utils.require_state(state=[constants.DRIVER_READY], excp=False)
    def monitor_events(self):
        try:
            LOG.info(_LI("Starting monitoring for vCenter updates"))
            version = ""
            self.state = constants.DRIVER_RUNNING
            while self.state in (constants.DRIVER_RUNNING):
                try:
                    LOG.debug("Waiting for vCenter updates...")
                    try:
                        updateSet = self.session._call_method(
                            vim_util,
                            "wait_for_updates_ex",
                            version)
                        if self.state != constants.DRIVER_RUNNING:
                            LOG.error(_LE("Driver is not in running state."))
                            break
                    except error_util.SocketTimeoutException:
                        # Ignore timeout.
                        LOG.warning(_LW("Ignoring socket timeouts while "
                                        "monitoring for vCenter updates."))
                        continue
                    if updateSet:
                        version = updateSet.version
                        events = self._process_update_set(updateSet)
                        LOG.debug("Sending events : %s.", events)
                        self.dispatch_events(events)
                except exceptions.VimFaultException as e:
                    # InvalidCollectorVersionFault happens
                    # on session re-connect.
                    # Re-initialize WaitForUpdatesEx.
                    if "InvalidCollectorVersion" in e.fault_list:
                        LOG.debug("InvalidCollectorVersion - "
                                  "Re-initializing vCenter updates "
                                  "monitoring.")
                        version = ""
                        for cluster_mor in self.clusters_by_id.values():
                            pfo = self._register_cluster_for_updates(
                                cluster_mor)
                            clu_id = cluster_mor.value
                            self.cluster_id_to_filter[clu_id] = pfo
                        continue
                    LOG.exception(_LE("VimFaultException while processing "
                                      "update set %s."), e)
                except Exception:
                    LOG.exception(_LE("Exception while processing update"
                                      " set."))
                time.sleep(0)
            LOG.info(_LI("Stopped monitoring for vCenter updates."))
        except Exception:
            LOG.exception(_LE("Monitoring for vCenter updates failed."))

    def _process_update_set(self, updateSet):
        """Processes the updateSet and returns VM events."""

        events = []
        host_name = None
        clus_name = None
        clus_id = None
        LOG.debug("Processing UpdateSet version: %s.", updateSet.version)
        filterSet = updateSet.filterSet
        if not filterSet:
            return events
        for propFilterUpdate in filterSet:
            objectSet = propFilterUpdate.objectSet
            if not objectSet:
                continue
            for objectUpdate in objectSet:
                try:
                    obj_mor = objectUpdate.obj
                    if obj_mor._type != "VirtualMachine":
                        continue
                    if objectUpdate.kind == "enter":
                        event_type = constants.VM_CREATED
                    elif objectUpdate.kind == "modify":
                        event_type = constants.VM_UPDATED
                    elif objectUpdate.kind == "leave":
                        event_type = constants.VM_DELETED
                    else:
                        continue
                    host_changed = False
                    vm_uuid = None
                    changes = common_util.convert_objectupdate_to_dict(
                        objectUpdate)
                    if changes.get('config.extraConfig["nvp.vm-uuid"]'):
                        vm_uuid = changes.get('config.extraConfig'
                                              '["nvp.vm-uuid"]').value
                        event_type = constants.VM_CREATED
                        cache.VCCache.add_vm_mor_for_uuid(vm_uuid, obj_mor)
                    else:
                        vm_uuid = cache.VCCache.get_vmuuid_for_moid(
                            obj_mor.value)
                    if vm_uuid:
                        old_vm = cache.VCCache.get_vm_model_for_uuid(vm_uuid)
                        LOG.debug("Old VM: %s.", old_vm)
                        LOG.debug("cache.VCCache.vm_uuid_to_model: %s.",
                                  cache.VCCache.vm_uuid_to_model)
                        new_vm = None
                        if old_vm:
                            if event_type == constants.VM_CREATED:
                                # Our cache has information about VM. But event
                                # received is VM_CREATED. This means it is
                                # session restart case. So we should not add
                                # this to new event.
                                LOG.debug("Session restart event for VM %s",
                                          vm_uuid)
                                continue
                            new_vm = copy.deepcopy(old_vm)
                        else:
                            new_vm = model.VirtualMachine(name=None,
                                                          vnics=[],
                                                          uuid=None,
                                                          key=None)
                            LOG.debug("VM not found in cache. New created: "
                                      " %s.", new_vm)
                        new_vm.uuid = vm_uuid
                        new_vm.key = obj_mor.value
                        if changes.get('name'):
                            new_vm.name = changes.get('name')
                        if changes.get('runtime.host'):
                            # Host got changed / New VM.
                            clus_mor = self.session._call_method(
                                vim_util,
                                "get_dynamic_property",
                                changes.get('runtime.host'),
                                "HostSystem", "parent")
                            # Cache the VM and Cluster.
                            cache.VCCache.add_cluster_mor_for_vm(vm_uuid,
                                                                 clus_mor)
                        if event_type != constants.VM_DELETED:
                            extraconfigs = (
                                resource_util.get_extraconfigs_for_vm(
                                    self.session, obj_mor))
                            if changes.get('config.hardware.device'):
                                devices = changes.get('config.hardware.device')
                                nicdvs = network_util.get_vnics_from_devices(
                                    devices)
                                i = 0
                                vnics = []
                                for nicdev in nicdvs:
                                    macadd = nicdev.macAddress
                                    port = nicdev.backing.port
                                    pgkey = port.portgroupKey
                                    portid = extraconfigs.get("nvp.iface-id.%d"
                                                              % i)
                                    vnic = model.VirtualNic(
                                        mac_address=macadd,
                                        port_uuid=portid,
                                        vm_id=vm_uuid,
                                        vm_name=new_vm.name,
                                        nic_type=None,
                                        pg_id=pgkey,
                                        key=None)
                                    vnics.append(vnic)
                                    i += 1
                                new_vm.vnics = vnics
                            host_mor = resource_util.get_host_mor_for_vm(
                                self.session, vm_uuid)
                            clus_mor = resource_util.get_cluster_mor_for_vm(
                                self.session, vm_uuid)
                            host_name = (
                                resource_util.get_hostname_for_host_mor(
                                    self.session, host_mor))
                            old_host_name = (
                                cache.VCCache.get_esx_hostname_for_vm(vm_uuid))
                            if old_host_name and old_host_name != host_name:
                                host_changed = True
                            cache.VCCache.add_esx_hostname_for_vm(vm_uuid,
                                                                  host_name)
                            clus_name = (
                                resource_util.get_clustername_for_cluster_mor(
                                    self.session, clus_mor))
                            clus_id = (
                                resource_util.get_clusterid_for_cluster_mor(
                                    self.session, clus_mor))
                        elif event_type == constants.VM_DELETED:
                            host_name = cache.VCCache.get_esx_hostname_for_vm(
                                vm_uuid)
                        event = model.Event(event_type, new_vm, None,
                                            host_name, clus_name, clus_id,
                                            host_changed)
                        events.append(event)
                        cache.VCCache.add_vm_model_for_uuid(vm_uuid, new_vm)
                        LOG.debug("Added vm to cache: %s.", new_vm.uuid)
                    else:
                        LOG.debug("Ignoring update for VM: %s.",
                                  changes.get('name'))
                except Exception:
                    LOG.exception(_LE("Exception while processing update set "
                                      "for event %(event)s for vm %(vm)s."),
                                  {'event': event_type, 'vm': vm_uuid})
        LOG.debug("Finished processing UpdateSet version: %s.",
                  updateSet.version)
        return events

    @utils.require_state(state=[constants.DRIVER_READY,
                         constants.DRIVER_RUNNING])
    def create_port(self, network, port, virtual_nic):
        device_id = port.vm_id
        cluster_mor, cluster_path, switch = self._find_cluster_switch_for_vm(
            device_id)
        host_mors = self.is_valid_switch(cluster_mor, switch)
        if not host_mors:
            LOG.error(_LE("Invalid Switch: %(sw)s for cluster: %(cp)s."),
                      {'sw': switch, 'cp': cluster_path})
            raise error.VcenterConfigurationError("Invalid Switch: %s for "
                                                  "cluster: %s." %
                                                  (switch, cluster_path))
        hosts = []
        for host_mor in host_mors:
            hosts.append(model.Host(key=host_mor.value))
        vswitch = model.VirtualSwitch(switch, hosts=hosts)
        self.create_network(network, vswitch)

    @utils.require_state(state=[constants.DRIVER_READY,
                         constants.DRIVER_RUNNING])
    def post_delete_vm(self, vm):
        cache.VCCache.remove_vm_for_uuid(vm.uuid)
