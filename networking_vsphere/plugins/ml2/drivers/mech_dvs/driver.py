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

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.openstack.common.gettextutils import _LI
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.mech_dvs import vmware_util

LOG = log.getLogger(__name__)


class VMwareDVSMechanismDriver(api.MechanismDriver):
    """Attach to networks using vmware agent.

    The VmwareMechanismDriver integrates the ml2 plugin with the
    vmware L2 agent. Port binding with this driver requires the vmware
    agent to be running on the port's host, and that agent to have
    connectivity to at least one segment of the port's network.
    """

    def initialize(self):
        LOG.info(_LI("VMware DVS mechanism driver initializing..."))
        self.vif_type = portbindings.VIF_TYPE_DVS
        self.vif_details = {portbindings.CAP_PORT_FILTER: False}
        self.vmware_util = vmware_util.VMWareUtil()
        LOG.info(_LI("VMware DVS mechanism driver initialized..."))

    def create_network_precommit(self, context):
        self.vmware_util.create_dvpg(context)

    def delete_network_precommit(self, context):
        self.vmware_util.delete_dvpg(context)

    def update_network_precommit(self, context):
        self.vmware_util.update_dvpg(context)

    def bind_port(self, context):
        LOG.info(_LI("Attempting to bind port %(port)s on "
                     "network %(network)s"),
                 {'port': context.current['id'],
                  'network': context.network.current['id']})
        for segment in context.network.network_segments:
            context.set_binding(segment[api.ID],
                                self.vif_type,
                                self.vif_details,
                                status=n_const.PORT_STATUS_ACTIVE)
