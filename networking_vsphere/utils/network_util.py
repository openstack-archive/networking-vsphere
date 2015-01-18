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

from eventlet import greenthread

from neutron.openstack.common import log as logging

from networking_vsphere.utils import common_util
from networking_vsphere.utils import error_util
from networking_vsphere.utils import vim_util


LOG = logging.getLogger(__name__)


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
    """Get VLAN id associated with a portgroup on a DVS."""
    port_group_mor = get_portgroup_mor_by_name(session, dvs_name, pg_name)
    vlan_id = 0
    if port_group_mor:
        port_group_config = session._call_method(
            vim_util, "get_dynamic_property", port_group_mor,
            "DistributedVirtualPortgroup", "config")
        vlan_id = port_group_config.defaultPortConfig.vlan.vlanId
    return vlan_id


def wait_on_dvs_portgroup(session, vm_ref, pg_name):
    """Wait for a portgroup creation on a DVS."""
    max_counts = 25
    count = 0
    while count < max_counts:
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
                        LOG.debug("DistributedVirtualPortgroup %s ",
                                  "created" % pg_name)
                        return True
        count += 1
        LOG.debug("Portgroup %s not created yet. Retrying again "
                  "after 2 seconds" % pg_name)
        greenthread.sleep(2)
    if count == max_counts:
        LOG.debug("Tried max times, but portgroup %s not created" % pg_name)
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
            LOG.info(_("Portgroup %(pg)s already exists "
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
            session._wait_for_task(task_ref)
            LOG.info(_("Successfully created portgroup "
                     "%(pg)s with vlan id %(vid)s"),
                     {'pg': pg_name, 'vid': vlan_id})
        except Exception as e:
            LOG.exception(_("Failed to create portgroup %(pg)s with "
                          "vlan id %(vid)s on vCenter. Cause : %(err)s"),
                          {'pg': pg_name, 'vid': vlan_id, 'err': e})
            raise error_util.RunTimeError("Failed to create portgroup %s "
                                          "with vlan id %s on vCenter.Cause"
                                          " : %s" % (pg_name, vlan_id, e))
