# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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
'''
Implements methods defined in NetworkDriver and VCNetworkDriver
and supports VMware Virtual Standard Switch.
'''


import re

from oslo_log import log as logging

from networking_vsphere.common import constants
from networking_vsphere.common import error
from networking_vsphere.common import utils
from networking_vsphere.drivers import vc_driver
from networking_vsphere.drivers import driver
from networking_vsphere.utils import cache
from networking_vsphere.utils import common_util
from networking_vsphere.utils import error_util
from networking_vsphere.utils import network_util
from networking_vsphere.utils import resource_util
from networking_vsphere.utils import vss_network_util
from networking_vsphere.utils import vim_util

LOG = logging.getLogger(__name__)


class VssNetworkDriver(vc_driver.VCNetworkDriver):

    def __init__(self):
        vc_driver.VCNetworkDriver.__init__(self)

    def delete_portgroup(self, cluster_mor, switch, pg):
        hosts_in_cluster = resource_util.get_host_mors_for_cluster(
            self.session, cluster_mor)
        for host_mor in hosts_in_cluster:
            vss_network_util.delete_port_group(self.session, host_mor,
                                               switch, pg)

    def is_valid_switch(self, cluster_mor, switch):
        return vss_network_util.is_valid_vswitch(self.session,
                                                 cluster_mor,
                                                 switch)

    def is_valid_switch_from_cache(self, cluster_mor, switch):
        dc = self.cluster_to_dc[cluster_mor.value]
        cluster_mor = cache.VCCache.\
            get_from_datacenter("ClusterComputeResource",
                                moid=cluster_mor.value,
                                dc=dc)
        hosts_in_cluster = cluster_mor.get("host").ManagedObjectReference
        for host_mor in hosts_in_cluster:
            host_mor = cache.VCCache.\
                get_from_datacenter("HostSystem",
                                    moid=host_mor.value,
                                    dc=dc)
            vswitches = getattr(host_mor.get("config.network.vswitch"),
                                "HostVirtualSwitch", [])
            vswitch_names = [vswitch.name for vswitch in vswitches]
            if vswitches and switch not in vswitch_names:
                LOG.error(
                    _("VSS not present on host %s." % host_mor.get("name")))
                return None
        return hosts_in_cluster

    def delete_stale_portgroups(self, cluster_mor, switch):
        LOG.info(_("Deleting unused portgroups on %s"), switch)
        hosts_in_cluster = resource_util.get_host_mors_for_cluster(
            self.session, cluster_mor)
        for host_mor in hosts_in_cluster:
            port_group_names = vss_network_util.get_unused_portgroup_names(
                self.session,
                host_mor, switch)
            uuid_regex = ("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
                          "-[0-9a-f]{4}-[0-9a-f]{12}")
            for port_group in port_group_names:
                if re.match(uuid_regex, port_group, re.IGNORECASE):
                    vss_network_util.delete_port_group(self.session, host_mor,
                                                       switch, port_group)

    def enable_disable_port_of_vm(self, vm_mor, mac_address, enabled, netname):
        return vss_network_util.enable_disable_port_of_vm(self.session,
                                                          vm_mor,
                                                          mac_address,
                                                          enabled,
                                                          netname)

    @utils.require_state(state=[constants.DRIVER_READY,
                         constants.DRIVER_RUNNING])
    def create_network(self, network, cluster_mor, virtual_switch):
        LOG.info(
            _("Creating portgroup %s with vlan id %s on standard "
              "virtual switch %s"),
            network.name, network.config.vlan.vlanIds[0],
            virtual_switch.name)
        hosts_in_cluster = resource_util.get_host_mors_for_cluster(
            self.session, cluster_mor)
        for host_mor in hosts_in_cluster:
            for host in virtual_switch.hosts:
                vss_network_util.create_port_group(self.session,
                                                   host_mor,
                                                   vss_name=virtual_switch.name,
                                                   pg_name=network.name,
                                                   vlan_id=network.config.
                                                   vlan.vlanIds[0])

    @utils.require_state(state=[constants.DRIVER_READY,
                                constants.DRIVER_RUNNING])
    def delete_network(self, network, virtual_switch=None):
        if not virtual_switch:
            cluster_paths = cache.VCCache.get_cluster_switch_mapping().keys()
            for cluster_path in cluster_paths:
                vss_name = cache.VCCache. \
                    get_switch_for_cluster_path(cluster_path)
                cluster_mor = resource_util.get_cluster_mor_by_path(self.session, cluster_path)
                self.delete_portgroup(cluster_mor, vss_name, network.name)
        else:
            "Handle delete_network for controllers other than Aurora"
            pass

    @utils.require_state(state=[constants.DRIVER_READY,
                                constants.DRIVER_RUNNING])
    def post_create_port(self, port):
        device_id = port.vm_id
        net_name = port.network_uuid
        vm_mor = resource_util.get_vm_mor_for_uuid(self.session,
                                                   device_id)
        if vm_mor is None:
            msg = (_("Virtual machine %(id)s with "
                         "port %(port)s not created."),
                       {'id': device_id,
                        'port': port.uuid})
            raise error_util.RunTimeError(msg)
        vss_network_util.enable_disable_port_of_vm(self.session,
                                                   vm_mor,
                                                   port.mac_address,
                                                   True,
                                                   net_name)

    @utils.require_state(state=[constants.DRIVER_READY,
                                constants.DRIVER_RUNNING])
    def update_port(self, network, port, virtual_nic):
        device_id = port.vm_id
        mac_address = port.mac_address
        vm_mor = resource_util.get_vm_mor_for_uuid(self.session, device_id)
        netname = port.network_uuid
        if not vm_mor:
            LOG.warn(_("VM %(vm)s with mac address %(mac)s for port %(uuid)s "
                       "not found on this node."),
                     {'vm': device_id, 'mac': mac_address, 'uuid': port.uuid})
            return False
        if port.port_status == constants.PORT_STATUS_UP:
            enabled = True
        elif port.port_status == constants.PORT_STATUS_DOWN:
            enabled = False
        else:
            msg = (_("Invalid port status %(port)s in update for port %(id)s"),
                   {'port': port.port_status, 'id': port.uuid})
            raise error.OVSvAppNeutronAgentError(msg)
        action = "Enabling" if enabled else "Disabling"
        LOG.debug("%(action)s port used by VM %(id)s for VNIC with "
                  "mac address %(mac)s.",
                  {'action': action, 'id': device_id, 'mac': mac_address})
        status = self.enable_disable_port_of_vm(vm_mor, mac_address, enabled, netname)
        return status

