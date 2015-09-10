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

from neutron import manager

from networking_vsphere.common import constants
from networking_vsphere.db import ovsvapp_db

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class OVSvAppServicePlugin(ovsvapp_db.OVSvAppClusterDbMixin,
                           ovsvapp_db.OVSvAppMitigatedClusterDbMixin):

    """Implementation of the Neutron OVSvApp Service Plugin.

    This class manages the workflow of OVSvApp request/response.
    """

    supported_extension_aliases = ["ovsvapp-cluster",
                                   "ovsvapp-mitigated-cluster"]

    def __init__(self):
        """Do the initialization for the OVSvApp service plugin here."""
        super(OVSvAppServicePlugin, self).__init__()
        LOG.debug("Starting OVSvApp Service Plugin.")

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def get_plugin_type(self):
        """Get type of the plugin."""
        return constants.OVSVAPP_PLUGIN

    def get_plugin_description(self):
        """Get description of the plugin."""
        return "OVSvApp Service Plugin."
