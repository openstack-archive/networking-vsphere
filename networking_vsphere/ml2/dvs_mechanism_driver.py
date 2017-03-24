#    Copyright 2015 Mirantis, Inc.
#    All Rights Reserved.
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
from time import sleep

from neutron.agent import securitygroups_rpc
from neutron.common import constants as n_const
from neutron import context
from neutron.extensions import portbindings
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.drivers import mech_agent
from oslo_log import log

from networking_vsphere._i18n import _LI
from networking_vsphere.common import constants as dvs_const
from networking_vsphere.common import dvs_agent_rpc_api
from networking_vsphere.common import exceptions
from networking_vsphere.common import vmware_conf as config
from networking_vsphere.utils import db

CONF = config.CONF
LOG = log.getLogger(__name__)


def port_belongs_to_vmware(func):
    @six.wraps(func)
    def _port_belongs_to_vmware(self, context):
        port = context.current
        try:
            if port['binding:vif_type'] == dvs_const.DVS:
                return func(self, context)
            elif port['binding:vif_type'] == 'unbound':
                try:
                    host = port['binding:host_id']
                except KeyError:
                    raise exceptions.HypervisorNotFound

                agent = db.get_agent_by_host(host)
                if not agent:
                    raise exceptions.HypervisorNotFound
            else:
                return False
        except exceptions.ResourceNotFound:
            return False
        return func(self, context)
    return _port_belongs_to_vmware


class VMwareDVSMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Ml2 Mechanism driver for vmware dvs."""

    def __init__(self):
        self.vif_type = dvs_const.DVS
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        self.vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled,
                            portbindings.OVS_HYBRID_PLUG: sg_enabled}
        self.context = context.get_admin_context_without_session()
        self.dvs_notifier = dvs_agent_rpc_api.DVSClientAPI(self.context)
        LOG.info(_LI('DVS_notifier'))
        super(VMwareDVSMechanismDriver, self).__init__(
            dvs_const.AGENT_TYPE_DVS,
            self.vif_type,
            self.vif_details)

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [constants.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('bridge_mappings', {})

    def create_network_precommit(self, context):
        if CONF.DVS.precreate_networks and self._check_net_type(context):
            LOG.info(_LI('Precreate network cast'))
            self.dvs_notifier.create_network_cast(context.current,
                                                  context.network_segments[0])
            # need to wait for agents. Cast message
            sleep(2)

    def update_network_precommit(self, context):
        if self._check_net_type(context):
            self.dvs_notifier.update_network_cast(
                context.current, context.network_segments[0], context.original)
            # need to wait for agents. Cast message
            sleep(2)

    def delete_network_postcommit(self, context):
        if self._check_net_type(context):
            self.dvs_notifier.delete_network_cast(
                context.current, context.network_segments[0])
            # need to wait for agents. Cast message
            sleep(2)

    @port_belongs_to_vmware
    def bind_port(self, context):
        if self._check_net_type(context.network):
            booked_port_info = self.dvs_notifier.bind_port_call(
                context.current,
                context.network.network_segments,
                context.network.current,
                context.host
            )
            vif_details = dict(self.vif_details)
            vif_details.update({
                'dvs_port_key': booked_port_info['key'],
                'dvs_id': booked_port_info['dvs_uuid'],
                'pg_id': booked_port_info['pg_key']
            })
            for segment in context.network.network_segments:
                context.set_binding(
                    segment[driver_api.ID],
                    self.vif_type,
                    vif_details,
                    status=n_const.PORT_STATUS_ACTIVE)
        else:
            nt = context.network.network_segments[0]['network_type']
            raise exceptions.NotSupportedNetworkType(network_type=nt)

    @port_belongs_to_vmware
    def update_port_precommit(self, context):
        if context.current['binding:vif_type'] == 'unbound':
            self.bind_port(context)

    @port_belongs_to_vmware
    def update_port_postcommit(self, context):
        if self._check_net_type(context.network):
            self.dvs_notifier.update_postcommit_port_call(
                context.current,
                context.original,
                context.network.network_segments[0],
                context.host
            )

            if (context.current['binding:vif_type'] == 'unbound' and
                    context.current['status'] == n_const.PORT_STATUS_DOWN):
                context._plugin.update_port_status(
                    context._plugin_context,
                    context.current['id'],
                    n_const.PORT_STATUS_ACTIVE)
            # Save AMQP on high load
            sleep(5)

    @port_belongs_to_vmware
    def delete_port_postcommit(self, context):
        if self._check_net_type(context.network):
            self.dvs_notifier.delete_port_call(
                context.current,
                context.original,
                context.network.network_segments[0],
                context.host)
            # Save AMQP on high load
            sleep(2)

    def _check_net_type(self, network_context):
        network_type = network_context.network_segments[0]['network_type']
        return network_type == constants.TYPE_VLAN

    def _get_security_group_info(self, context):
        current_security_group = list(set(context.current['security_groups']))
        ports = context._plugin.get_ports(context._plugin_context)
        for p in ports:
            if 'security_group_rules' not in p:
                p['security_group_rules'] = []
            if p['id'] == context.current['id']:
                p['security_groups'] = current_security_group
        port_dict = dict([(p['id'], p) for p in ports])
        sg_info = context._plugin.security_group_info_for_ports(
            context._plugin_context, port_dict)
        return {'devices': sg_info['devices'],
                'security_groups': sg_info['security_groups'],
                'sg_member_ips': sg_info['sg_member_ips']}
