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
from neutron.api.v2 import attributes
from neutron.api.v2 import resource_helper

from networking_vsphere._i18n import _
from networking_vsphere.common import constants
import networking_vsphere.extensions

extensions.append_api_extensions_path(networking_vsphere.extensions.__path__)


def convert_none_to_empty_list(value):
    return [] if value is None else value


def validate_clusters_list(data, valid_values=None):
    """Validate the list of clusters."""
    if not data:
        # Clusters must be provided.
        msg = _("Cannot create a list of clusters from the given input.")
        return msg
    if type(data) is not list:
        msg = _("Given cluster details is not in the form of list.")
        return msg

RESOURCE_ATTRIBUTE_MAP = {
    'ovsvapp_clusters': {
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': False},
        'vcenter_id': {'allow_post': True, 'allow_put': True,
                       'is_visible': True, 'default': ''},
        'clusters': {'allow_post': True, 'allow_put': True,
                     'convert_to': convert_none_to_empty_list,
                     'validate': {'type:clusters_list': None},
                     'default': None, 'is_visible': True},
    }
}

attributes.validators['type:clusters_list'] = validate_clusters_list


class Ovsvapp_cluster(extensions.ExtensionDescriptor):
    """Extension class supporting OVSvApp-Cluster-Mappings."""

    @classmethod
    def get_name(cls):
        return "ovsvapp-cluster"

    @classmethod
    def get_alias(cls):
        return "ovsvapp-cluster"

    @classmethod
    def get_description(cls):
        return "Display OVSvApp-Cluster Mappings"

    @classmethod
    def get_namespace(cls):
        return "ovsvapp-cluster"

    @classmethod
    def get_updated(cls):
        return "2015-09-07T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attributes.PLURALS.update(plural_mappings)
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


class OVSvAppClusterPluginBase(object):
    """REST API to show OVSvApp Cluster Mappings.

    All of method must be in an admin context.
    """

    @abc.abstractmethod
    def get_ovsvapp_cluster(self, context, vcenter_id, fields=None):
        pass

    @abc.abstractmethod
    def get_ovsvapp_clusters(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_ovsvapp_cluster(self, context, ovsvapp_cluster):
        pass

    @abc.abstractmethod
    def update_ovsvapp_cluster(self, context, id, ovsvapp_cluster):
        pass
