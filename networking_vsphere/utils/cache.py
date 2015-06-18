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

import six


class VCCache(object):

    cluster_id_to_path = {}
    vm_uuid_to_mor = {}
    vm_moid_to_uuid = {}
    vm_uuid_to_model = {}
    cluster_switch_mapping = {}
    vm_uuid_to_esx_hostname = {}

    @classmethod
    def get_esx_hostname_for_vm(cls, vm_uuid):
        if vm_uuid in cls.vm_uuid_to_esx_hostname.keys():
            return cls.vm_uuid_to_esx_hostname.get(vm_uuid)
        return None

    @classmethod
    def add_esx_hostname_for_vm(cls, vm_uuid, hostname):
        cls.vm_uuid_to_esx_hostname[vm_uuid] = hostname

    @classmethod
    def get_cluster_mor_for_vm(cls, vm_uuid):
        return cls.vm_to_cluster.get(vm_uuid, None)

    @classmethod
    def add_cluster_mor_for_vm(cls, vm_uuid, clus_mor):
        # TODO(romilg): This line will be revisited with the extended team
        # before being removed if found redundant.
        if len(cls.vm_to_cluster) >= 1000:
            cls.vm_to_cluster.popitem()
        cls.vm_to_cluster[vm_uuid] = clus_mor

    @classmethod
    def get_cluster_path_for_id(cls, cluster_id):
        return cls.cluster_id_to_path.get(cluster_id, None)

    @classmethod
    def add_path_for_cluster_id(cls, cluster_id, cluster_path):
        cls.cluster_id_to_path[cluster_id] = cluster_path

    @classmethod
    def get_vm_mor_for_uuid(cls, uuid):
        return cls.vm_uuid_to_mor.get(uuid)

    @classmethod
    def add_vm_mor_for_uuid(cls, uuid, vm_mor):
        cls.vm_uuid_to_mor[uuid] = vm_mor
        cls.vm_moid_to_uuid[vm_mor.value] = uuid

    @classmethod
    def get_vm_model_for_uuid(cls, uuid):
        return cls.vm_uuid_to_model.get(uuid)

    @classmethod
    def add_vm_model_for_uuid(cls, uuid, vm):
        cls.vm_uuid_to_model[uuid] = vm

    @classmethod
    def get_switch_for_cluster_path(cls, cluster_path):
        return cls.cluster_switch_mapping.get(cluster_path)

    @classmethod
    def add_switch_for_cluster_path(cls, cluster_path, switch_name):
        cls.cluster_switch_mapping[cluster_path] = switch_name

    @classmethod
    def get_vmuuid_for_moid(cls, moid):
        return cls.vm_moid_to_uuid.get(moid)

    @classmethod
    def remove_vm_for_uuid(cls, uuid):
        cls.vm_to_cluster.pop(uuid, None)
        vm_mor = cls.vm_uuid_to_mor.pop(uuid, None)
        if vm_mor:
            cls.vm_moid_to_uuid.pop(vm_mor.value, None)
        cls.vm_uuid_to_model.pop(uuid, None)

    @classmethod
    def remove_cluster_path(cls, cluster_path):
        del cls.cluster_switch_mapping[cluster_path]

    @classmethod
    def remove_cluster_id(cls, cluster_id):
        cls.cluster_id_to_path.pop(cluster_id, None)

    @classmethod
    def get_cluster_id_for_path(cls, cluster_path):
        cluster_id = None
        for temp_id, temp_path in six.iteritems(cls.cluster_id_to_path):
            if cluster_path == temp_path:
                cluster_id = temp_id
                break
        return cluster_id

    @classmethod
    def get_cluster_switch_mapping(cls):
        return cls.cluster_switch_mapping

    @classmethod
    def reset(cls):
        cls.cluster_id_to_path = {}
        cls.vm_to_cluster = {}
        cls.vm_uuid_to_mor = {}
        cls.vm_moid_to_uuid = {}
        cls.vm_uuid_to_model = {}
        cls.cluster_switch_mapping = {}
        cls.vm_uuid_to_esx_hostname = {}
