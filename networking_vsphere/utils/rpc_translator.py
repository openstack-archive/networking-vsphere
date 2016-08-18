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

from eventlet import greenthread
from oslo_config import cfg
from oslo_log import log

from networking_vsphere._i18n import _LE, _LI
from networking_vsphere.common import constants
from networking_vsphere.utils import common_util
from networking_vsphere.utils import error_util
from networking_vsphere.utils import resource_util
from networking_vsphere.utils import vim_util

LOG = log.getLogger(__name__)


def get_dvs_mor_by_uuid(session, uuid):
    """Returns DVS mor by UUID."""
    return session._call_method(vim_util,
                                "get_dvs_mor_by_uuid",
                                uuid)


def get_dvs_mor_by_name(session, dvs_name):
    """Returns DVS mor from its name."""
    dvs_mors = session._call_method(
        vim_util, "get_objects", "DistributedVirtualSwitch", ["name"])
    for dvs_mor in dvs_mors:
        propset_dict = common_util.convert_propset_to_dict(dvs_mor.propSet)
        if propset_dict['name'] == dvs_name:
            return dvs_mor.obj
    return None


def get_all_portgroup_mors_for_switch(session, dvs_name):
    """Returns a list of mors of all portgroups attached to specified DVS."""
    dvs_mor = get_dvs_mor_by_name(session, dvs_name)
    if dvs_mor:
        dvs_config = session._call_method(
            vim_util, "get_dynamic_property", dvs_mor,
            "DistributedVirtualSwitch", "portgroup")
        port_group_mors = dvs_config.ManagedObjectReference
        return port_group_mors
    return None


def get_unused_portgroup_names(session, dvs_name):
    """Returns a list of unused portgroups.

    Unused portgroups - Portgroups of a specific DVS not
    connected to any virtual Machine.
    """
    unused_port_group_names = []
    port_group_mors = get_all_portgroup_mors_for_switch(session, dvs_name)
    if port_group_mors:
        port_groups = session._call_method(
            vim_util, "get_properties_for_a_collection_of_objects",
            "DistributedVirtualPortgroup", port_group_mors,
            ["summary.name", "tag", "vm"])
        for port_group in port_groups:
            propset_dict = common_util.convert_propset_to_dict(
                port_group.propSet)
            if not propset_dict['vm'] and not propset_dict['tag']:
                unused_port_group_names.append(propset_dict['summary.name'])
    return unused_port_group_names


def get_portgroup_mor_by_name(session, dvs_name, port_group_name):
    """Get Portgroup mor by Portgroup name."""
    port_group_mors = get_all_portgroup_mors_for_switch(session, dvs_name)
    if port_group_mors:
        port_groups = session._call_method(
            vim_util, "get_properties_for_a_collection_of_objects",
            "DistributedVirtualPortgroup", port_group_mors, ["summary.name"])
        for port_group in port_groups:
            if port_group.propSet[0].val == port_group_name:
                return port_group.obj
    return None


def _get_add_vswitch_port_group_spec(client_factory,
                                     port_group_name, vlan_id):
    """Builds DVS port group configuration spec."""
    vswitch_port_group_spec = client_factory.create(
        'ns0:DVPortgroupConfigSpec')
    vswitch_port_group_spec.name = port_group_name

    portSettingSpec = client_factory.create('ns0:VMwareDVSPortSetting')
    vlanSpec = client_factory.create(
        'ns0:VmwareDistributedVirtualSwitchVlanIdSpec')
    vlanSpec.inherited = False
    vlanSpec.vlanId = vlan_id
    portSettingSpec.vlan = vlanSpec

    vswitch_port_group_spec.autoExpand = True
    vswitch_port_group_spec.type = "earlyBinding"
    vswitch_port_group_spec.defaultPortConfig = portSettingSpec
    return vswitch_port_group_spec


def get_portgroup_details(session, dvs_name, pg_name):
    """Get VLAN id associated with a port group on a DVS."""
    port_group_mor = get_portgroup_mor_by_name(session, dvs_name, pg_name)
    vlan_id = constants.DEAD_VLAN
    if port_group_mor:
        port_group_config = session._call_method(
            vim_util, "get_dynamic_property", port_group_mor,
            "DistributedVirtualPortgroup", "config")
        vlan_id = port_group_config.defaultPortConfig.vlan.vlanId
    return vlan_id


def get_portgroup_vlan(session, pg_id):
    """Get VLAN id associated with a port group."""
    vlan_id = 0
    if pg_id:
        # Obtain vlan_id for the port group.
        pg_mors = session._call_method(
            vim_util, "get_objects", "DistributedVirtualPortgroup",
            ["key", "config.defaultPortConfig"])
        for pg_mor in pg_mors:
            propset_dict = common_util.convert_propset_to_dict(pg_mor.propSet)
            if propset_dict['key'] == pg_id:
                pconfig = propset_dict["config.defaultPortConfig"]
                vlan_id = pconfig["vlan"]["vlanId"]
                LOG.debug("VLAN ID for port group is %s.", vlan_id)
                break
    return vlan_id


def wait_until_dvs_portgroup_available(session, vm_ref, pg_name, wait_time):
    """Wait until a portgroup is available on a DVS."""
    time_elapsed = 0
    while time_elapsed < wait_time:
        host = session._call_method(vim_util, "get_dynamic_property",
                                    vm_ref, "VirtualMachine", "runtime.host")
        vm_networks_prop = session._call_method(vim_util,
                                                "get_dynamic_property", host,
                                                "HostSystem", "network")
        if vm_networks_prop:
            vm_networks = vm_networks_prop.ManagedObjectReference
            for network in vm_networks:
                if network._type == 'DistributedVirtualPortgroup':
                    props = session._call_method(vim_util,
                                                 "get_dynamic_property",
                                                 network,
                                                 network._type,
                                                 "config")
                    if props.name in pg_name:
                        LOG.debug("DistributedVirtualPortgroup created %s "
                                  % pg_name)
                        return True
        LOG.debug("Portgroup %s not created yet. Retrying again "
                  "after 5 seconds" % pg_name)
        greenthread.sleep(5)
        time_elapsed += 5
    if time_elapsed >= wait_time:
        LOG.debug("Portgroup %(pg)s not created within %(secs)s secs",
                  {'pg': pg_name, 'secs': wait_time})
    return False


def create_port_group(session, dvs_name, pg_name, vlan_id):
    """Creates a Portgroup on DVS with a vlan id."""
    port_group_mor = get_portgroup_mor_by_name(session, dvs_name, pg_name)
    if port_group_mor:
        port_group_config = session._call_method(
            vim_util, "get_dynamic_property", port_group_mor,
            "DistributedVirtualPortgroup", "config")
        if vlan_id == port_group_config.defaultPortConfig.vlan.vlanId:
            LOG.debug("Portgroup %(pg)s with vlan id %(vid)s already exists",
                      {'pg': pg_name, 'vid': vlan_id})
            return
        else:
            LOG.info(_LI("Portgroup %(pg)s already exists "
                         "but with vlan id %(vid)s"),
                     {'pg': pg_name,
                      'vid': port_group_config.defaultPortConfig.vlan.vlanId})
            raise error_util.RunTimeError("Inconsistent vlan id for portgroup"
                                          " %s", pg_name)
    else:
        client_factory = session._get_vim().client.factory
        add_prt_grp_spec = _get_add_vswitch_port_group_spec(
            client_factory, pg_name, vlan_id)
        blocked = client_factory.create('ns0:BoolPolicy')
        blocked.value = False
        blocked.inherited = False
        add_prt_grp_spec.defaultPortConfig.blocked = blocked
        dvs_mor = get_dvs_mor_by_name(session, dvs_name)

        try:
            task_ref = session._call_method(
                session._get_vim(), "AddDVPortgroup_Task", dvs_mor,
                spec=add_prt_grp_spec)
            session.wait_for_task(task_ref)
            LOG.info(_LI("Successfully created portgroup "
                         "%(pg)s with vlan id %(vid)s"),
                     {'pg': pg_name, 'vid': vlan_id})
        except Exception as e:
            LOG.exception(_LE("Failed to create portgroup %(pg)s with "
                              "vlan id %(vid)s on vCenter. Cause : %(err)s"),
                          {'pg': pg_name, 'vid': vlan_id, 'err': e})
            raise error_util.RunTimeError("Failed to create portgroup %s "
                                          "with vlan id %s on vCenter.Cause"
                                          " : %s" % (pg_name, vlan_id, e))


def delete_port_group(session, dvs_name, pg_name):
    """Deletes a port group from DVS."""
    port_group_mor = get_portgroup_mor_by_name(session, dvs_name, pg_name)
    if port_group_mor:
        try:
            destroy_task = session._call_method(session._get_vim(),
                                                "Destroy_Task", port_group_mor)
            session.wait_for_task(destroy_task)
            LOG.info(_LI("Successfully deleted portgroup %(pg)s from "
                         "dvs %(dvs)s"),
                     {'pg': pg_name, 'dvs': dvs_name})
        except Exception as e:
            LOG.exception(_LE("Failed to delete portgroup %(pg)s from "
                              "dvs %(dvs)s .Cause : %(err)s"),
                          {'pg': pg_name, 'dvs': dvs_name, 'err': e})
            raise error_util.RunTimeError("Failed to delete portgroup %s "
                                          "on dvs %s on vCenter.Cause"
                                          " : %s" % (pg_name, dvs_name, e))
    else:
        LOG.info(_LI("portgroup %(pg)s not present on dvs %(dvs)s"),
                 {'pg': pg_name, 'dvs': dvs_name})


def enable_disable_port_of_vm(session, vm_mor, mac_address, enabled):
    """Enable or disable a port of a VM having specific mac_address."""
    props = session._call_method(vim_util,
                                 "get_dynamic_properties",
                                 vm_mor,
                                 ["config.hardware.device"])
    devices = props["config.hardware.device"]
    LOG.debug("Found %(nod)s devices on VM %(vm)s",
              {'nod': len(devices.VirtualDevice), 'vm': vm_mor.value})
    vnics = get_vnics_from_devices(devices)
    for device in vnics:
        if (hasattr(device, "macAddress") and
                device.macAddress == mac_address):
            port = device.backing.port
            pgkey = port.portgroupKey
            portkey = port.portKey
            swuuid = port.switchUuid
            enable_disable_port(session, swuuid, pgkey, portkey, enabled)
            return True
    return False


def get_vnics_from_devices(devices):
    """Obtain vnic information."""
    vnics = None
    if (devices and hasattr(devices, "VirtualDevice")):
        vnics = []
        devices = devices.VirtualDevice
        for device in devices:
            if (device.__class__.__name__ in
                ("VirtualEthernetCard",
                 "VirtualE1000", "VirtualE1000e",
                 "VirtualPCNet32", "VirtualVmxnet",
                 "VirtualVmxnet2", "VirtualVmxnet3")):
                vnics.append(device)
    return vnics


def enable_disable_port(session, swuuid, pgkey, portkey, enabled):
    """Enable or Disable VM port."""
    action = "Enabling" if enabled else "Disabling"
    LOG.debug("%(action)s port %(port)s on %(pg)s",
              {'action': action, 'port': portkey, 'pg': pgkey})
    vds_mor = get_dvs_mor_by_uuid(session, swuuid)
    client_factory = session._get_vim().client.factory
    spec = client_factory.create('ns0:DVPortConfigSpec')
    spec.key = portkey
    spec.operation = "edit"
    setting = client_factory.create('ns0:DVPortSetting')
    blocked = client_factory.create('ns0:BoolPolicy')
    blocked.value = not enabled
    blocked.inherited = False
    setting.blocked = blocked
    spec.setting = setting
    reconfig_task = session._call_method(session._get_vim(),
                                         "ReconfigureDVPort_Task",
                                         vds_mor,
                                         port=[spec])
    session.wait_for_task(reconfig_task)
    action = "enabled" if enabled else "disabled"
    LOG.debug("Successfully %(action)s port %(port)s on port "
              "group %(pg)s on dvs %(dvs)s",
              {'action': action, 'port': portkey, 'pg': pgkey, 'dvs': swuuid})


def is_valid_dvswitch(session, cluster_mor, dvs_name):
    """Validate a DVS.

    Check if DVS exists for a cluster specified in conf.
    Also validate if DVS is attached to all hosts in a cluster.
    """
    dvs_mor = get_dvs_mor_by_name(session, dvs_name)
    if dvs_mor:
        dvs_config = session._call_method(
            vim_util, "get_dynamic_property", dvs_mor,
            "DistributedVirtualSwitch", "config.host")
        # Get all the host attached to given VDS
        dvs_host_members = dvs_config[0]
        dvs_attached_host_ids = []
        for dvs_host_member in dvs_host_members:
            dvs_attached_host_ids.append(dvs_host_member.config.host.value)

        # Get all the hosts present in the cluster
        hosts_in_cluster = resource_util.get_host_mors_for_cluster(
            session, cluster_mor)

        # Check if the host on which OVSvApp VM is hosted is a part of DVSwitch
        if hosts_in_cluster:
            for host in hosts_in_cluster:
                hostname = resource_util.get_hostname_for_host_mor(
                    session, host)
                if hostname == cfg.CONF.VMWARE.esx_hostname:
                    if host.value not in dvs_attached_host_ids:
                        LOG.error(_LE("DVS not present on"
                                      "host %s") % host.value)
                        return False
            return hosts_in_cluster
    else:
        LOG.error(_LE("DVS not present %s") % dvs_name)
        return False
