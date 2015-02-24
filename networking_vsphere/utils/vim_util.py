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

from oslo_vmware import vim_util


def build_recursive_traversal_spec(client_factory):
    # Recurse through all ResourcePools
    rp_to_rp = client_factory.create('ns0:TraversalSpec')
    rp_to_rp.name = 'rpToRp'
    rp_to_rp.type = 'ResourcePool'
    rp_to_rp.path = 'resourcePool'
    rp_to_rp.skip = False
    rp_to_vm = client_factory.create('ns0:TraversalSpec')
    rp_to_vm.name = 'rpToVm'
    rp_to_vm.type = 'ResourcePool'
    rp_to_vm.path = 'vm'
    rp_to_vm.skip = False
    spec_array_resource_pool = [client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec')]
    spec_array_resource_pool[0].name = 'rpToRp'
    spec_array_resource_pool[1].name = 'rpToVm'
    rp_to_rp.selectSet = spec_array_resource_pool

    # Traversal through resource pool branch
    cr_to_rp = client_factory.create('ns0:TraversalSpec')
    cr_to_rp.name = 'crToRp'
    cr_to_rp.type = 'ComputeResource'
    cr_to_rp.path = 'resourcePool'
    cr_to_rp.skip = False
    spec_array_compute_resource = [client_factory.create('ns0:SelectionSpec'),
                                   client_factory.create('ns0:SelectionSpec')]
    spec_array_compute_resource[0].name = 'rpToRp'
    spec_array_compute_resource[1].name = 'rpToVm'
    cr_to_rp.selectSet = spec_array_compute_resource

    # Traversal through host branch
    cr_to_h = client_factory.create('ns0:TraversalSpec')
    cr_to_h.name = 'crToH'
    cr_to_h.type = 'ComputeResource'
    cr_to_h.path = 'host'
    cr_to_h.skip = False

    # Traversal through hostFolder branch
    dc_to_hf = client_factory.create('ns0:TraversalSpec')
    dc_to_hf.name = 'dcToHf'
    dc_to_hf.type = 'Datacenter'
    dc_to_hf.path = 'hostFolder'
    dc_to_hf.skip = False
    spec_array_datacenter_host = [client_factory.create('ns0:SelectionSpec')]
    spec_array_datacenter_host[0].name = 'visitFolders'
    dc_to_hf.selectSet = spec_array_datacenter_host

    # Traversal through vmFolder branch
    dc_to_vmf = client_factory.create('ns0:TraversalSpec')
    dc_to_vmf.name = 'dcToVmf'
    dc_to_vmf.type = 'Datacenter'
    dc_to_vmf.path = 'vmFolder'
    dc_to_vmf.skip = False
    spec_array_datacenter_vm = [client_factory.create('ns0:SelectionSpec')]
    spec_array_datacenter_vm[0].name = 'visitFolders'
    dc_to_vmf.selectSet = spec_array_datacenter_vm

    # Traversal through datastore branch
    dc_to_ds = client_factory.create('ns0:TraversalSpec')
    dc_to_ds.name = 'dcToDs'
    dc_to_ds.type = 'Datacenter'
    dc_to_ds.path = 'datastore'
    dc_to_ds.skip = False
    spec_array_datacenter_ds = [client_factory.create('ns0:SelectionSpec')]
    spec_array_datacenter_ds[0].name = 'visitFolders'
    dc_to_ds.selectSet = spec_array_datacenter_ds

    # Recurse through all hosts
    h_to_vm = client_factory.create('ns0:TraversalSpec')
    h_to_vm.name = 'hToVm'
    h_to_vm.type = 'HostSystem'
    h_to_vm.path = 'vm'
    h_to_vm.skip = False
    spec_array_host_vm = [client_factory.create('ns0:SelectionSpec')]
    spec_array_host_vm[0].name = 'visitFolders'
    h_to_vm.selectSet = spec_array_host_vm

    # Recurse through all datastores
    ds_to_vm = client_factory.create('ns0:TraversalSpec')
    ds_to_vm.name = 'dsToVm'
    ds_to_vm.type = 'Datastore'
    ds_to_vm.path = 'vm'
    ds_to_vm.skip = False
    spec_array_datastore_vm = [client_factory.create('ns0:SelectionSpec')]
    spec_array_datastore_vm[0].name = 'visitFolders'
    ds_to_vm.selectSet = spec_array_datastore_vm

    # Recurse through the folders
    visit_folders = client_factory.create('ns0:TraversalSpec')
    visit_folders.name = 'visitFolders'
    visit_folders.type = 'Folder'
    visit_folders.path = 'childEntity'
    visit_folders.skip = False
    spec_array_visit_folders = [client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec'),
                                client_factory.create('ns0:SelectionSpec')]
    spec_array_visit_folders[0].name = 'visitFolders'
    spec_array_visit_folders[1].name = 'dcToHf'
    spec_array_visit_folders[2].name = 'dcToVmf'
    spec_array_visit_folders[3].name = 'crToH'
    spec_array_visit_folders[4].name = 'crToRp'
    spec_array_visit_folders[5].name = 'dcToDs'
    spec_array_visit_folders[6].name = 'hToVm'
    spec_array_visit_folders[7].name = 'dsToVm'
    spec_array_visit_folders[8].name = 'rpToVm'
    visit_folders.selectSet = spec_array_visit_folders

    # Add all of them here
    spec_array = [visit_folders, dc_to_vmf, dc_to_ds, dc_to_hf, cr_to_h,
                  cr_to_rp, rp_to_rp, h_to_vm, ds_to_vm, rp_to_vm]
    return spec_array


def get_object_properties(vim, collector, mobj, type, properties):
    """Gets the properties of the Managed object specified."""
    client_factory = vim.client.factory
    if mobj is None:
        return None
    usecoll = collector
    if usecoll is None:
        usecoll = vim.service_content.propertyCollector
    property_filter_spec = client_factory.create('ns0:PropertyFilterSpec')
    property_spec = client_factory.create('ns0:PropertySpec')
    property_spec.all = (properties is None or len(properties) == 0)
    property_spec.pathSet = properties
    property_spec.type = type
    object_spec = client_factory.create('ns0:ObjectSpec')
    object_spec.obj = mobj
    object_spec.skip = False
    property_filter_spec.propSet = [property_spec]
    property_filter_spec.objectSet = [object_spec]
    return retrieve_properties_ex(vim,
                                  usecoll,
                                  [property_filter_spec])


def get_dynamic_property(vim, mobj, type, property_name):
    """Gets a particular property of the Managed Object."""
    properties = get_dynamic_properties(vim, mobj, [property_name], type)
    property_value = None
    if property_name in properties:
        property_value = properties.get(property_name)
    return property_value


def get_dynamic_properties(vim, mobj, property_names, obj_type=None):
    """Gets specific properties of the Managed Object."""
    if not obj_type:
        obj_type = mobj._type
    obj_content = get_object_properties(
        vim, None, mobj, obj_type, property_names)
    properties = {}
    if obj_content:
        dynamic_properties = obj_content[0].propSet
        for dynamic_property in dynamic_properties:
            property_name = dynamic_property.name
            property_value = dynamic_property.val
            properties[property_name] = property_value
    return properties


def retrieve_properties_ex(vim, prop_coll, spec_set, max_count=500):
    """Retrieve properties.

    Retrieve properties using PropertyCollector.RetrievePropertiesEx
    and PropertyCollector.ContinueRetrievePropertiesEx
    args:
    :param vim: Vim object
    :param prop_coll: PropertyCollector MOR
    :param max_count: Max num of objects returned in a single call.
    """
    objcont = []
    client_factory = vim.client.factory
    opts = client_factory.create('ns0:RetrieveOptions')
    opts.maxObjects = max_count
    res = vim.RetrievePropertiesEx(prop_coll,
                                   specSet=spec_set,
                                   options=opts)
    while True:
        if res and res.objects:
            objcont.extend(res.objects)
        if hasattr(res, "token") and res.token:
            res = vim.ContinueRetrievePropertiesEx(prop_coll, token=res.token)
        else:
            break
    return objcont


def get_objects(vim, type, properties_to_collect=None, all=False):
    """Gets the list of objects of the type specified."""
    if not properties_to_collect:
        properties_to_collect = ["name"]

    client_factory = vim.client.factory
    trav_spec = vim_util.build_recursive_traversal_spec(client_factory)
    object_spec = vim_util.build_object_spec(client_factory,
                                             vim.service_content.rootFolder,
                                             [trav_spec])
    property_spec = vim_util.build_property_spec(
        client_factory, type_=type,
        properties_to_collect=properties_to_collect,
        all_properties=all)
    property_filter_spec = vim_util.build_property_filter_spec(client_factory,
                                                               [property_spec],
                                                               [object_spec])
    property_collector = vim.service_content.propertyCollector
    return retrieve_properties_ex(vim,
                                  property_collector,
                                  [property_filter_spec])


def get_prop_spec(client_factory, spec_type, properties):
    """Builds the Property Spec Object."""
    prop_spec = client_factory.create('ns0:PropertySpec')
    prop_spec.type = spec_type
    prop_spec.pathSet = properties
    return prop_spec


def get_obj_spec(client_factory, obj, select_set=None):
    """Builds the Object Spec object."""
    obj_spec = client_factory.create('ns0:ObjectSpec')
    obj_spec.obj = obj
    obj_spec.skip = False
    if select_set is not None:
        obj_spec.selectSet = select_set
    return obj_spec


def get_prop_filter_spec(client_factory, obj_spec, prop_spec):
    """Builds the Property Filter Spec Object."""
    prop_filter_spec = client_factory.create('ns0:PropertyFilterSpec')
    prop_filter_spec.propSet = prop_spec
    prop_filter_spec.objectSet = obj_spec
    return prop_filter_spec


def get_property_filter_specs(vim, property_dict, objects=None):
    client_factory = vim.client.factory
    object_specs = []
    if not objects:
        objects = [vim.service_content.rootFolder]
    for obj in objects:
        if obj.value == get_root_folder_id(vim):
            traversal_spec = [
                vim_util.build_recursive_traversal_spec(client_factory)]
        else:
            traversal_spec = build_recursive_traversal_spec(client_factory)
        object_spec = vim_util.build_object_spec(client_factory,
                                                 obj,
                                                 traversal_spec)
        object_specs.append(object_spec)

    property_specs = []
    for obj_type in property_dict:
        props = property_dict[obj_type]
        property_spec = vim_util.build_property_spec(
            client_factory, type_=obj_type, properties_to_collect=props)
        property_specs.append(property_spec)

    property_filter_spec = vim_util.build_property_filter_spec(client_factory,
                                                               property_specs,
                                                               object_specs)
    return property_filter_spec


def create_filter(vim, prop_filter_spec, collector=None):
    if not collector:
        collector = vim.service_content.propertyCollector
    return vim.CreateFilter(collector,
                            spec=prop_filter_spec,
                            partialUpdates=False)


def create_property_collector(vim, collector=None):
    if not collector:
        collector = vim.service_content.propertyCollector
    return vim.CreatePropertyCollector(collector)


def destroy_property_collector(vim, collector):
    if collector:
        return vim.DestroyPropertyCollector(collector)


def wait_for_updates_ex(vim, version, collector=None,
                        max_wait=85, max_update_count=-1):
    """Polling mechanism for property collection

        args:
        :param vim: Vim object
        :param version: version string
        :param collector: PropertyCollector MOR
        :param max_wait: Max time in seconds before the call returns
                       (Default set to 85 as 90 is the http socket timeout)
        :param max_update_count: Max num of ObjectUpdates returned
                               in a single call. Not set if <= 0
    """
    client_factory = vim.client.factory
    waitopts = client_factory.create('ns0:WaitOptions')
    waitopts.maxWaitSeconds = max_wait
    if max_update_count > 0:
        waitopts.maxObjectUpdates = max_update_count
    if not collector:
        collector = vim.service_content.propertyCollector
    return vim.WaitForUpdatesEx(collector,
                                version=version,
                                options=waitopts)


def cancel_wait_for_updates(vim, collector=None):
    if not collector:
        collector = vim.service_content.propertyCollector
    return vim.CancelWaitForUpdates(collector)


def get_properties_for_a_collection_of_objects(vim, type,
                                               obj_list, properties):
    """Gets the list of properties for the collection of objects."""
    client_factory = vim.client.factory
    if len(obj_list) == 0:
        return []
    prop_spec = get_prop_spec(client_factory, type, properties)
    lst_obj_specs = []
    for obj in obj_list:
        lst_obj_specs.append(get_obj_spec(client_factory, obj))
    prop_filter_spec = get_prop_filter_spec(client_factory,
                                            lst_obj_specs, [prop_spec])
    return retrieve_properties_ex(vim,
                                  vim.service_content.propertyCollector,
                                  [prop_filter_spec])


def get_search_index(vim):
    return vim.service_content.searchIndex


def find_by_inventory_path(vim, search_index, path):
    return vim.FindByInventoryPath(search_index, inventoryPath=path)


def get_root_folder_id(vim):
    return vim.service_content.rootFolder.value


def get_dv_switch_manager(vim):
    """Get reference of DistributedVirtualSwitchManager."""
    return vim.service_content.dvSwitchManager


def get_dvs_mor_by_uuid(vim, uuid):
    """Query DVS by UUID."""
    dvs_mgr = get_dv_switch_manager(vim)
    return vim.QueryDvsByUuid(dvs_mgr, uuid=uuid)
