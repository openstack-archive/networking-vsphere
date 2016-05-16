# Copyright 2013 Hewlett-Packard Development Company, L.P.
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


from eventlet import greenthread
from oslo_config import cfg
from oslo_log import log as logging

from networking_vsphere.common import constants
from networking_vsphere.utils import common_util
from networking_vsphere.utils import error_util
from networking_vsphere.utils import resource_util
from networking_vsphere.utils import vim_util
from networking_vsphere.utils import cache
from networking_vsphere.utils import network_util

LOG = logging.getLogger(__name__)

opts = [cfg.StrOpt('disabled_net_name',
                   help=_("Network name used for disabled NICs"),
                   default="disabled-network"),
        ]
cfg.CONF.register_opts(opts)


def get_virtual_switch_by_name(session, host_mor, vss_name):
    vswitches = get_all_virtual_switches_on_host(session, host_mor)
    for vswitch in vswitches:
        if vswitch.name == vss_name:
            return vswitch
    return None

def get_all_virtual_switches_on_host(session, host_mor):
    host_vswitches = session._call_method(vim_util, "get_dynamic_property",
                                          host_mor,
                                          "HostSystem",
                                          "config.network.vswitch")
    if (host_vswitches and hasattr(host_vswitches,"HostVirtualSwitch")):
        vswitches = host_vswitches.HostVirtualSwitch
        return vswitches
    return None

def get_portgroup_by_name(session, host_mor, vss_name, port_group_name):
    """
       check if portgroup exists on the standard switch.
    """
    host_name = session._call_method(vim_util, "get_dynamic_property",
                                 host_mor,
                                 host_mor._type,
                                 "summary.config.name")
    portgroups = session._call_method(vim_util, "get_dynamic_property",
                                 host_mor,
                                 host_mor._type,
                                 "config.network.portgroup")

    if (portgroups and hasattr(portgroups, "HostPortGroup")):
        port_groups = portgroups.HostPortGroup
        for port_group in port_groups:
            if port_group.spec.vswitchName == vss_name and \
                    port_group.spec.name == port_group_name:
                return (host_name, port_group)
    return (host_name, None)

def get_all_portgroups_on_switch(session, host_mor, vss_name):
    """
       check if portgroup exists on the standard switch.
    """
    portgroups_on_switch = []
    portgroups = session._call_method(vim_util, "get_dynamic_property",
                                      host_mor,
                                      "HostSystem",
                                      "config.network.portgroup")

    if (portgroups and hasattr(portgroups, "HostPortGroup")):
        port_groups = portgroups.HostPortGroup
        for port_group in port_groups:
            if port_group.spec.vswitchName == vss_name:
                portgroups_on_switch.append(port_group)
    return portgroups_on_switch

def get_all_network_mors_for_host(session, host_mor):
    """
    Returns a list Managed Object Reference for all the portgroups
    attached to the specified vss
    """
    networks = session._call_method(vim_util, "get_dynamic_property",
                                    host_mor,
                                    "HostSystem",
                                    "network")

    network_mors = networks.ManagedObjectReference
    vss_network_mors = [network_mor for network_mor in network_mors
                        if network_mor._type == 'Network']
    return vss_network_mors

def _get_add_host_port_group_spec(client_factory, host_mor, vss_name,
                                  pg_name, vlan_id, vswitch_policy):

    """Builds the virtual switch port group add spec."""
    host_port_group_spec = client_factory.create(
        'ns0:HostPortGroupSpec')
    host_port_group_spec.name = pg_name
    host_port_group_spec.vswitchName = vss_name
    host_port_group_spec.policy = vswitch_policy
    host_port_group_spec.vlanId = vlan_id
    return host_port_group_spec

def create_port_group(session, host_mor, vss_name, pg_name, vlan_id):
    host_name = resource_util.get_hostname_for_host_mor(session, host_mor)
    vswitch = get_virtual_switch_by_name(session, host_mor, vss_name)

    if vswitch:
        vswitch_policy = vswitch.spec.policy
        host_network_mor = session._call_method(vim_util, "get_dynamic_property",
                                                host_mor,
                                                "HostSystem",
                                                "configManager.networkSystem")
        client_factory = session._get_vim().client.factory
        host_prt_grp_spec = _get_add_host_port_group_spec(
            client_factory, host_mor, vss_name, pg_name, vlan_id,
            vswitch_policy)
        try:
            session._call_method( session._get_vim(),
                                  "AddPortGroup",
                                  host_network_mor,
                                  portgrp=host_prt_grp_spec)
            LOG.info(_("Successfully created portgroup "
                       "%s with vlan id %s on host %s") % (pg_name,
                                                           vlan_id,
                                                           host_name))
        except Exception as e:
            if "already exists" in str(e):
                LOG.debug(_(e))
                return
            LOG.exception(_("Failed to create portgroup %s with vlan id "
                            "%s on host %s. Cause : %s") %
                          (pg_name, vlan_id, host_name, e))
            raise Exception("Failed to create portgroup %s with vlan id "
                            "%s on host %s. Cause : %s" %
                            (pg_name, vlan_id, host_name, e))
    else:
        msg = _("VSS %s not present on host %s.") % (vss_name, host_name)
        LOG.error(msg)
        raise Exception(msg)

def delete_port_group(session, host_mor, vss_name, pg_name):
    """
    Deletes a port group on the specified Standard
    Virtual Switch.
    """
    LOG.debug(_("Deleting portgroup %s from vss %s" % (pg_name, vss_name)))
    port_group = get_portgroup_by_name(session,
                                       host_mor, vss_name, pg_name)
    if port_group:
        host_name = session._call_method(vim_util, "get_dynamic_property",
                                     host_mor,
                                     host_mor._type,
                                     "summary.config.name")
        host_network_mor = session._call_method(vim_util, "get_dynamic_property",
                                     host_mor,
                                     host_mor._type,
                                     "configManager.networkSystem")

        try:
            session._call_method( session._get_vim(),
                                  "RemovePortGroup",
                                  host_network_mor,
                                  pgName=pg_name)
            LOG.info(
                _("Successfully deleted portgroup %s from vss %s on host %s" %
                    (pg_name, vss_name, host_name)))
        except Exception as e:
            LOG.exception(_("Failed to delete portgroup %s from vss %s "
                            "on host %s ,Cause : %s" % (pg_name,
                                                        vss_name,
                                                        host_name,
                                                        e)))
            raise Exception("Failed to delete portgroup %s from vss %s "
                            "on host %s, Cause : %s" % (pg_name,
                                                        vss_name,
                                                        host_name,
                                                        e))
    else:
        LOG.info(_("Portgroup %s not present on vss %s on host %s" % (
                   pg_name,
                   vss_name,
                   host_mor.value)))

def is_valid_vswitch(session, cluster_mor, vss_name):
    """
       Check if VSS is present for the cluster specified in conf.
       Also validate if VSS is attached to all the hosts in the cluster.
    """
        # Get all the hosts present in the cluster
    hosts_in_cluster = resource_util.get_host_mors_for_cluster(
        session, cluster_mor)
    for host_mor in hosts_in_cluster:
        vswitches = get_all_virtual_switches_on_host(session, host_mor)
        vswitch_names = [vswitch.name for vswitch in vswitches]
        if vswitches and vss_name not in vswitch_names:
            LOG.error(
                _("VSS not present on host %s." % host_mor.value))
            return None
    return hosts_in_cluster

def get_unused_portgroup_names(session, host_mor, vss_name):
    """
    Returns a list of all the portgroups
    attached to the specified vss and are not
    connected to any virtual Machine.
    """
    unsed_port_group_names = []
    portgroups = get_all_portgroups_on_switch(session, host_mor, vss_name)
    if portgroups:
        portgroup_names = [portgroup.spec.name for portgroup in portgroups]
        network_mors = get_all_network_mors_for_host(session,
                                                     host_mor)
        if network_mors:
            networks = session._call_method(vim_util,
                                            "get_properties_for_a_collection_of_objects",
                                            "Network",
                                            network_mors,
                                            ["summary.name", "vm"])

            for network in networks:
                propset_dict = common_util.convert_propset_to_dict(
                    network.propSet)
                if propset_dict['summary.name'] in portgroup_names and \
                        not propset_dict['vm']:
                    unsed_port_group_names.append(propset_dict['summary.name'])
    return unsed_port_group_names

def is_nic_enabled(nic):
    """ Check if the nic is enabled or not

        If the nic is connected to port group
        other than disabled-network the nic is enabled
    """
    if hasattr(nic, "backing") and nic.backing:
        if (hasattr(nic.backing, "deviceName") and
                nic.backing.deviceName):
            if nic.backing.deviceName == cfg.CONF.disabled_net_name:
                return False
    return True

def enable_disable_port_of_vm(session, vm_mor, mac_address, enabled, netname):
    """Enable or disable a port of a VM having specific mac_address."""
    props = session._call_method(vim_util,
                                 "get_dynamic_properties",
                                 vm_mor,
                                 ["config.hardware.device"])
    devices = props["config.hardware.device"]
    LOG.debug("Found %(nod)s devices on VM %(vm)s",
              {'nod': len(devices.VirtualDevice), 'vm': vm_mor.value})
    nic = network_util.get_vnics_from_devices(devices)
    for device in nic:
        #if netname == device.backing.deviceName:
        netdevice_key = device.key
    if not nic:
        return False
    enabled = True if enabled else False
    enabl_str = "enabled" if enabled else "disabled"
    if is_nic_enabled(nic) == enabled:
        LOG.debug("vNIC of vm %s with mac %s is already %s",
                  vm_mor.value, mac_address, enabl_str)
        return True
    if enabled and not netname:
        LOG.error(_("Enable port failed- Invalid network name %s"), netname)
        return False

    client_factory = session._get_vim().client.factory
    network_spec = client_factory.create('ns0:VirtualDeviceConfigSpec')
    network_spec.operation = "edit"
    net_device = client_factory.create('ns0:VirtualE1000')
    backing = client_factory.create('ns0:VirtualEthernetCardNetworkBackingInfo')

    if enabled:
        backing.deviceName = netname
    else:
        backing.deviceName = cfg.CONF.disabled_net_name
    net_device.backing = backing
    net_device.addressType = "manual"
    net_device.macAddress = mac_address
    net_device.wakeOnLanEnabled = True
    net_device.key = netdevice_key
    connectable_spec = client_factory.create('ns0:VirtualDeviceConnectInfo')
    connectable_spec.startConnected = True
    connectable_spec.allowGuestControl = True
    connectable_spec.connected = True
    net_device.connectable = connectable_spec
    network_spec.device = net_device
    config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
    config_spec.deviceChange = network_spec
    enabl_str = "enable" if enabled else "disable"
    LOG.info(_("Reconfiguring VM to %s vNIC"), enabl_str)
    reconfig_task = session._call_method(session._get_vim(),
                                         "ReconfigVM_Task",
                                         vm_mor,
                                         spec=config_spec)
    session.wait_for_task(reconfig_task)
    LOG.debug(_("Reconfigured VM instance"))
    return True
