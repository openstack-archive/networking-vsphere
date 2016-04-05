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

"""Utils for managing resources like cluster, VM and host."""

from oslo_log import log

from networking_vsphere._i18n import _LE
from networking_vsphere.utils import cache
from networking_vsphere.utils import common_util
from networking_vsphere.utils import vim_util

LOG = log.getLogger(__name__)


def get_host_mor_for_vm(session, vm_uuid):
    """Return host mor from VM uuid."""

    vm_mor = get_vm_mor_for_uuid(session, vm_uuid)
    if vm_mor:
        host_mor = session._call_method(
            vim_util, "get_dynamic_property", vm_mor,
            "VirtualMachine", "runtime.host")
        return host_mor
    return None


def get_hostname_for_host_mor(session, host_mor):
    """Return hostname from host mor."""

    if host_mor:
        hostname = session._call_method(
            vim_util, "get_dynamic_property", host_mor,
            "HostSystem", "name")
        return hostname
    return None


def get_host_mor_by_name(session, host_name):
    """Return Host mor from its name."""

    host_mors = session._call_method(
        vim_util, "get_objects", "HostSystem", ["name"])
    for host_mor in host_mors:
        propset_dict = common_util.convert_propset_to_dict(host_mor.propSet)
        if propset_dict['name'] == host_name:
            return host_mor.obj
    return None


def get_vm_mor_by_name(session, vm_name):
    """Return VM mor from its name."""

    vm_mors = session._call_method(
        vim_util, "get_objects", "VirtualMachine", ["name"])
    for vm_mor in vm_mors:
        propset_dict = common_util.convert_propset_to_dict(vm_mor.propSet)
        if propset_dict['name'] == vm_name:
            return vm_mor.obj
    return None


def set_vm_poweroff(session, vm_mor):
    """Power off the VM."""

    try:
        task_ref = session._call_method(
            session._get_vim(), "PowerOffVM_Task", vm_mor)
        session.wait_for_task(task_ref)
    except Exception as e:
        LOG.exception(_LE("%s"), e)
        raise Exception(e)


def set_host_into_maintenance_mode(session, host_mor):
    """Put ESX host into maintenance mode."""

    try:
        task_ref = session._call_method(
            session._get_vim(), "EnterMaintenanceMode_Task", host_mor,
            timeout=0, evacuatePoweredOffVms=False)
        session.wait_for_task(task_ref)
    except Exception as e:
        LOG.exception(_LE("%s"), e)
        raise Exception(e)


def set_host_into_shutdown_mode(session, host_mor):
    """Shutdown the ESX host."""

    try:
        enabled = _check_shutdown_enabled(session, host_mor)
        if enabled:
            task_ref = session._call_method(
                session._get_vim(), "ShutdownHost_Task", host_mor,
                force=True)
            session.wait_for_task(task_ref)
    except Exception as e:
        LOG.exception(_LE("%s"), e)
        raise Exception(e)


def _check_shutdown_enabled(session, host_mor):
    """Check shutdown enabled on ESX host."""

    if host_mor:
        shutdown_enabled = session._call_method(
            vim_util, "get_dynamic_property", host_mor,
            "HostSystem", "capability.shutdownSupported")
        return shutdown_enabled
    return False


def get_clustername_for_cluster_mor(session, cluster_mor):
    """Return cluster name from cluster mor."""

    if cluster_mor:
        clustername = session._call_method(
            vim_util, "get_dynamic_property", cluster_mor,
            "ClusterComputeResource", "name")
        return clustername
    return None


def get_clusterid_for_cluster_mor(session, cluster_mor):
    """Return cluster id from cluster mor."""

    if cluster_mor:
        clusterid = cluster_mor.value
        return clusterid
    return None


def get_cluster_mor_for_vm(session, vm_uuid):
    """Return cluster mor from VM uuid."""

    cluster_mor = cache.VCCache.get_cluster_mor_for_vm(vm_uuid)
    if cluster_mor:
        return cluster_mor
    vm_mor = get_vm_mor_for_uuid(session, vm_uuid)
    if vm_mor:
        host_mor = session._call_method(
            vim_util, "get_dynamic_property", vm_mor,
            "VirtualMachine", "runtime.host")
        cluster_mor = session._call_method(
            vim_util, "get_dynamic_property", host_mor,
            "HostSystem", "parent")
        cache.VCCache.add_cluster_mor_for_vm(vm_uuid, cluster_mor)
        return cluster_mor
    LOG.debug("Unable to retrieve VM information")
    return None


def get_vm_mor_for_uuid(session, vm_uuid):
    """Return VM mor from VM uuid."""

    vm_mor = cache.VCCache.get_vm_mor_for_uuid(vm_uuid)
    if vm_mor:
        return vm_mor
    # TODO(romilg) : use config.uuid instead of
    # config.extraConfig["nvp.vm-uuid"] once fixed in nova.
    vm_mors = session._call_method(vim_util, "get_objects",
                                   "VirtualMachine",
                                   ['config.extraConfig["nvp.vm-uuid"]'])
    for vm_mor in vm_mors:
        if hasattr(vm_mor, "propSet"):
            propset_dict = common_util.convert_propset_to_dict(vm_mor.propSet)
            if (vm_uuid ==
                    propset_dict['config.extraConfig["nvp.vm-uuid"]'].value):
                cache.VCCache.add_vm_mor_for_uuid(vm_uuid, vm_mor.obj)
                return vm_mor.obj
    LOG.debug("Unable to retrieve VM information")
    return None


def get_host_mors_for_cluster(session, cluster_mor):
    """Return host mors from cluster mor."""

    try:
        host_mors = None
        host_ret = session._call_method(vim_util, "get_dynamic_property",
                                        cluster_mor,
                                        "ClusterComputeResource", "host")
        if hasattr(host_ret, "ManagedObjectReference"):
            host_mors = host_ret.ManagedObjectReference
        return host_mors
    except Exception as e:
        LOG.exception(_LE("Error retrieving cluster information"))
        raise Exception(e)


def get_extraconfigs_for_vm(session, vm_mor):
    """Return extra configurations from VM mor."""

    optvals = session._call_method(vim_util,
                                   "get_dynamic_property",
                                   vm_mor,
                                   "VirtualMachine",
                                   "config.extraConfig")
    optvals = optvals.OptionValue
    extraconfigs = {}
    for optval in optvals:
        extraconfigs[optval.key] = optval.value
    return extraconfigs


def get_cluster_mor_by_path(session, path):
    """Return cluster mor from cluster path."""

    search_index = session._call_method(vim_util, "get_search_index")
    mor = session._call_method(
        vim_util, "find_by_inventory_path", search_index, path)
    return mor


def _get_token(results):
    """Get the token from the property results."""
    return getattr(results, 'token', None)


def _get_object_for_value(results, value):
    """Get vm reference value from vm object."""

    for object in results:
        if object.propSet[0].val == value:
            return object.obj


def _get_object_from_results(session, results, value, func):
    """Get a specific vm object from list of vm objects."""

    while results:
        token = _get_token(results)
        object = func(results, value)

        if object:
            if token:
                session._call_method(vim_util,
                                     "cancel_retrieve",
                                     token)
            return object

        if token:
            results = session._call_method(vim_util,
                                           "continue_to_get_objects",
                                           token)
        else:
            return None


def get_vm_reference(session, vm_uuid):
    """Get vm reference from uuid."""

    vms = session._call_method(vim_util, "get_objects",
                               "VirtualMachine", ["name"])
    return _get_object_from_results(session, vms, vm_uuid,
                                    _get_object_for_value)
