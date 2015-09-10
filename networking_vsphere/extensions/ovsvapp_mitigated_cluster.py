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

import abc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper

from networking_vsphere.common import constants

RESOURCE_ATTRIBUTE_MAP = {
    'ovsvapp_mitigated_clusters': {
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': False},
        'vcenter_id': {'allow_post': True, 'allow_put': True,
                       'is_visible': True, 'default': ''},
        'cluster_id': {'allow_post': True, 'allow_put': True,
                       'is_visible': True, 'default': ''},
        'being_mitigated': {'allow_post': True, 'allow_put': True,
                            'is_visible': True, 'default': False,
                            'convert_to': attr.convert_to_boolean},
        'threshold_reached': {'allow_post': True, 'allow_put': True,
                              'is_visible': True, 'default': False,
                              'convert_to': attr.convert_to_boolean},
    }
}


class Ovsvapp_mitigated_cluster(extensions.ExtensionDescriptor):
    """Extension class supporting mitigation of clusters."""

    @classmethod
    def get_name(cls):
        return "ovsvapp-mitigated-cluster"

    @classmethod
    def get_alias(cls):
        return "ovsvapp-mitigated-cluster"

    @classmethod
    def get_description(cls):
        return "Configure mitigation properties of a Cluster"

    @classmethod
    def get_namespace(cls):
        return "ovsvapp-mitigated-cluster"

    @classmethod
    def get_updated(cls):
        return "2015-09-07T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        resources = resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            constants.OVSVAPP_PLUGIN)
        return resources

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class OVSvAppMitigatedClusterPluginBase(object):
    """REST API to operate the mitigation properties of a cluster.

    All of method must be in an admin context.
    """

    @abc.abstractmethod
    def get_ovsvapp_mitigated_cluster(self, context, vcenter_id, fields=None):
        pass

    @abc.abstractmethod
    def update_ovsvapp_mitigated_cluster(self, context, id,
                                         ovsvapp_mitigated_cluster):
        pass

    @abc.abstractmethod
    def get_ovsvapp_mitigated_clusters(self, context, filters=None,
                                       fields=None):
        pass

    @abc.abstractmethod
    def delete_ovsvapp_mitigated_cluster(self, context, id, filters=None):
        pass
