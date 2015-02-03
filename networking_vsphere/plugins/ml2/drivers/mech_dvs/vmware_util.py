# Copyright 2014 IBM Corp.
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

import re

from oslo.vmware import api as vmwareapi
from oslo.vmware import exceptions
from oslo.vmware import vim_util

from neutron.openstack.common.gettextutils import _LI, _LW
from neutron.openstack.common import log
from neutron.plugins.ml2.drivers.mech_dvs import config

LOG = log.getLogger(__name__)
CONF = config.CONF


class ResourceNotFoundException(exceptions.VimException):
    """Thrown when a resource can not be found."""
    pass


def _get_net_name(network):
    name = network["name"]
    name_pattern = "[0-9a-zA-Z_-]*"
    m = re.match(name_pattern, name)
    if m.group() != name:
        raise Exception(_("Illegal network name '%s': can only contain "
                          "numbers, lowercase and uppercase letters, '_' "
                          "and '-'.") % name)

    uuid = network["id"]
    net_name = ("%s-%s" % (name, uuid) if name else uuid)
    # The length limit of a port group's name in vcenter is 80
    if len(net_name) > 80:
        suffix_len = len(uuid) + 1
        name_len_limit = 80 - suffix_len
        raise Exception(_("Network name '%(name)s' is too long, please limit "
                          "your network name in length "
                          "%(limit)d.") % {"name": name,
                                           "limit": name_len_limit})
    return net_name


def _get_object_by_type(results, type_value):
    """Get object by type.

    Get the desired object from the given objects
    result by the given type.
    """
    return [obj for obj in results
            if obj._type == type_value]


class VMWareUtil():
    def __init__(self):
        self._session = None
        self._create_session()

    def _create_session(self):
        """Create Vcenter Session for API Calling."""
        host_ip = CONF.ml2_vmware.host_ip
        host_username = CONF.ml2_vmware.host_username
        host_password = CONF.ml2_vmware.host_password
        wsdl_location = CONF.ml2_vmware.wsdl_location
        task_poll_interval = CONF.ml2_vmware.task_poll_interval
        api_retry_count = CONF.ml2_vmware.api_retry_count

        self._session = vmwareapi.VMwareAPISession(
            host_ip,
            host_username,
            host_password,
            api_retry_count,
            task_poll_interval,
            create_session=True,
            wsdl_loc=wsdl_location)

    def build_pg_spec(self, name, vlan_tag):
        client_factory = self._session.vim.client.factory
        pg_spec = client_factory.create('ns0:DVPortgroupConfigSpec')
        pg_spec.name = name
        pg_spec.numPorts = 128
        pg_spec.type = 'ephemeral'
        DESCRIPTION = "Managed By Neutron"
        pg_spec.description = DESCRIPTION
        config = client_factory.create('ns0:VMwareDVSPortSetting')
        # Create the spec for the vlan tag
        spec_ns = 'ns0:VmwareDistributedVirtualSwitchVlanIdSpec'
        vlan_spec = client_factory.create(spec_ns)
        vlan_spec.vlanId = vlan_tag
        vlan_spec.inherited = '0'
        config.vlan = vlan_spec
        pg_spec.defaultPortConfig = config
        return pg_spec

    def get_datacenter(self):
        """Get the datacenter reference."""
        results = self._session.invoke_api(
            vim_util, 'get_objects', self._session.vim,
            "Datacenter", 100, ["name"])
        return results.objects[0].obj

    def get_network_folder(self):
        """Get the network folder from datacenter."""
        dc_ref = self.get_datacenter()
        results = self._session.invoke_api(
            vim_util, 'get_object_property', self._session.vim,
            dc_ref, "networkFolder")
        return results

    def get_dvs(self, dvs_name):
        """Get the dvs by name"""
        net_folder = self.get_network_folder()
        results = self._session.invoke_api(
            vim_util, 'get_object_property', self._session.vim,
            net_folder, "childEntity")
        networks = results.ManagedObjectReference
        dvswitches = _get_object_by_type(networks,
                                         "VmwareDistributedVirtualSwitch")
        dvs_ref = None
        for dvs in dvswitches:
            name = self._session.invoke_api(
                vim_util, 'get_object_property',
                self._session.vim, dvs,
                "name")
            if name == dvs_name:
                dvs_ref = dvs
                break

        if not dvs_ref:
            raise ResourceNotFoundException(_("Distributed Virtual Switch "
                                              "%s not found!") % dvs_name)
        else:
            LOG.info(_LI("Got distriubted virtual switch by name %s."),
                     dvs_name)

        return dvs_ref

    def get_dvpg_by_name(self, dvpg_name):
        """Get the dvpg ref by name"""
        dc_ref = self.get_datacenter()
        net_list = self._session.invoke_api(
            vim_util, 'get_object_property', self._session.vim,
            dc_ref, "network").ManagedObjectReference
        type_value = "DistributedVirtualPortgroup"
        dvpg_list = _get_object_by_type(net_list, type_value)
        dvpg_ref = None
        for pg in dvpg_list:
            name = self._session.invoke_api(
                vim_util, 'get_object_property',
                self._session.vim, pg,
                "name")
            if dvpg_name == name:
                dvpg_ref = pg
                break

        if not dvpg_ref:
            LOG.warning(_LW("Distributed Port Group %s not found!"),
                        dvpg_name)
        else:
            LOG.info(_LI("Got distriubted port group by name %s."),
                     dvpg_name)

        return dvpg_ref

    def create_dvpg(self, context):
        """Create a distributed virtual port group."""
        network = context.current
        segments = context.network_segments
        name = _get_net_name(network)
        net_type = segments[0]['network_type']
        if net_type == 'local':
            raise Exception(_("VCenter does not support "
                              "network_type:local, abort creating."))
        vlan_id = segments[0]['segmentation_id'] or 0

        physical_network = segments[0]['physical_network']
        dvs_name = ""
        network_maps = CONF.ml2_vmware.network_maps
        for map in network_maps:
            physnet, dvswitch = map.split(":")
            if physnet == physical_network:
                dvs_name = dvswitch
                break
        if not dvs_name:
            raise Exception(_("No distributed virtual switch is "
                              "dedicated to create netowrk %s.") % name)

        LOG.info(_LI("Will create network %(name)s on distributed "
                     "virtual switch %(dvs)s..."),
                 {"name": name, "dvs": dvs_name})

        dvs_ref = self.get_dvs(dvs_name)
        pg_spec = self.build_pg_spec(name,
                                     vlan_id)
        pg_create_task = self._session.invoke_api(self._session.vim,
                                                  "CreateDVPortgroup_Task",
                                                  dvs_ref, spec=pg_spec)

        result = self._session.wait_for_task(pg_create_task)
        dvpg = result.result
        LOG.info(_LI("Network %(name)s created! \n%(pg_ref)s"),
                 {"name": name, "pg_ref": dvpg})

    def delete_dvpg(self, context):
        """Delete the distributed virtual port group."""
        network = context.current
        name = _get_net_name(network)
        LOG.info(_LI("Will delete network %s..."), name)
        dvpg_ref = self.get_dvpg_by_name(name)
        if not dvpg_ref:
            LOG.warning(_LW("Network %s not present in vcenter, may be "
                            "deleted. Now remove network from neutron."),
                        name)
            return

        pg_delete_task = self._session.invoke_api(self._session.vim,
                                                  "Destroy_Task",
                                                  dvpg_ref)
        self._session.wait_for_task(pg_delete_task)
        LOG.info(_LI("Network %s deleted."), name)

    def update_dvpg(self, context):
        """Update the name of the given distributed virtual port group."""
        curr_net = context.current
        orig_net = context.original
        orig_name = _get_net_name(orig_net)
        dvpg_ref = self.get_dvpg_by_name(orig_name)
        rename_task = self._session.invoke_api(self._session.vim,
                                               "Rename_Task",
                                               dvpg_ref,
                                               newName=_get_net_name(curr_net))
        self._session.wait_for_task(rename_task)
        LOG.info(_LI("Network updated"))
