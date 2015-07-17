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

import time

from oslo_log import log
import oslo_messaging
from sqlalchemy.orm import exc as sa_exc

from networking_vsphere.common import constants as ovsvapp_const
from networking_vsphere.common import utils as ovsvapp_utils
from networking_vsphere.db import ovsvapp_db

from neutron.common import exceptions as exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context

LOG = log.getLogger(__name__)


class OVSvAppServerRpcCallback(object):

    """Plugin side of the OVSvApp rpc.

    This class contains extra rpc callbacks to be served for use by the
    OVSvApp Agent.
    """
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, notifier=None):
        super(OVSvAppServerRpcCallback, self).__init__()
        self.notifier = notifier

    @property
    def plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_devices_info(self, devices):
        return dict(
            (port['id'], port)
            for port in self.plugin.get_ports_from_devices(devices)
            if port and not port['device_owner'].startswith('network:')
        )

    def get_ports_for_device(self, rpc_context, **kwargs):
        """RPC for getting port info.

        This method provides information about the network and port for
        a given device_id.
        """
        agent_id = kwargs.get('agent_id')
        host = kwargs.get('host')
        device = kwargs.get('device')
        device_id = device['id']
        vcenter_id = device['vcenter']
        cluster_id = device['cluster_id']
        LOG.debug("Device %(device_id)s details requested by agent "
                  "%(agent_id)s running on host %(host)s.",
                  {'device_id': device_id, 'agent_id': agent_id, 'host': host})
        if not device_id:
            return False
        try_count = 3
        try:
            while try_count > 0:
                ports = self.plugin.get_ports(rpc_context,
                                              filters={'device_id':
                                                       [device_id]})
                device_ports = []
                sg_port_ids = set()
                for port in ports:
                    network = self.plugin.get_network(rpc_context,
                                                      port['network_id'])
                    port.update(
                        {'network_type': network['provider:network_type'],
                         'segmentation_id':
                         network['provider:segmentation_id'],
                         'physical_network':
                         network['provider:physical_network']})

                    if port['network_type'] == 'vxlan':
                        port_info = {'port_id': port['id'],
                                     'vcenter_id': vcenter_id,
                                     'cluster_id': cluster_id,
                                     'network_id': port['network_id']}
                        lvid = ovsvapp_db.get_local_vlan(port_info)
                        if lvid:
                            port['lvid'] = lvid
                        else:
                            # Local VLANs are exhausted ! No point processing
                            # further.
                            LOG.error(_("No VLAN available in the cluster "
                                        "%(cluster)s for assignment to device "
                                        "%(device)s in vCenter %(vcenter)s."),
                                      {'device': device_id,
                                       'cluster': cluster_id,
                                       'vcenter': vcenter_id})
                            return False
                    else:
                        port['lvid'] = port['segmentation_id']
                    # Bind the port here. If binding succeeds, then
                    # add this port to process for security groups, otheriwse
                    # ignore it.
                    updated_port = self.update_port_binding(rpc_context,
                                                            agent_id=agent_id,
                                                            port_id=port['id'],
                                                            host=host)
                    if not updated_port:
                        LOG.error(_("Port binding failed for "
                                    "port %s."), port['id]'])
                        # process the next port for the device
                        continue
                    if 'security_groups' in port:
                        sg_port_ids.add(port['id'])
                    device_ports.append(port)
                if not device_ports:
                    try_count -= 1
                    LOG.debug("Port details could not be retrieved for "
                              "device %s ..retrying.", device_id)
                    time.sleep(3)
                else:
                    LOG.debug("Device details returned by server: "
                              "%s.", device_ports)
                    # Get the SG rules for the security enabled ports.
                    sg_payload = {}
                    if sg_port_ids:
                        ports = self._get_devices_info(sg_port_ids)
                        sg_rules = self.plugin.security_group_rules_for_ports(
                            rpc_context, ports)
                        sg_payload[device_id] = sg_rules
                    self.notifier.device_create(rpc_context, device,
                                                device_ports, sg_payload,
                                                cluster_id)
                    return True
        except Exception:
            LOG.exception(_("Failed to retrieve port details for "
                            "device: %s."), device_id)
        LOG.debug("Failed to retrieve ports for device: %s.", device_id)
        return False

    def update_port_binding(self, rpc_context, **kwargs):
        agent_id = kwargs.get('agent_id')
        port_id = kwargs.get('port_id')
        host = kwargs.get('host')
        LOG.debug("Port %(port_id)s update_port_binding() invoked by agent "
                  "%(agent_id)s for host %(host)s.",
                  {'port_id': port_id, 'agent_id': agent_id, 'host': host})
        port = {'port': {portbindings.HOST_ID: host}}
        updated_port = self.plugin.update_port(rpc_context, port_id, port)
        return updated_port

    def update_ports_binding(self, rpc_context, **kwargs):
        agent_id = kwargs.get('agent_id')
        ports = kwargs.get('ports')
        host = kwargs.get('host')
        updated_ports = set()
        for port_id in ports:
            # Update not required if the host hasn't changed.
            if self.plugin.port_bound_to_host(rpc_context, port_id, host):
                updated_ports.add(port_id)
                continue
            LOG.debug("Port %(port_id)s update_port invoked by agent "
                      "%(agent_id)s for host %(host)s.",
                      {'port_id': port_id, 'agent_id': agent_id,
                       'host': host})
            port = {'port': {portbindings.HOST_ID: host}}
            try:
                updated_port = self.plugin.update_port(rpc_context, port_id,
                                                       port)
                updated_ports.add(updated_port['id'])
            except Exception:
                LOG.exception(_("Failed to update binding for port %s "),
                              port_id)
        return updated_ports

    def _get_port_db(self, session, port_id, agent_id):
        try:
            port_db = (session.query(models_v2.Port).
                       enable_eagerloads(False).
                       filter(models_v2.Port.id.startswith(port_id)).
                       one())
            return port_db
        except sa_exc.NoResultFound:
            LOG.warning(_("Port %(port_id)s requested by agent "
                          "%(agent_id)s not found in database."),
                        {'port_id': port_id, 'agent_id': agent_id})
            return None
        except exc.MultipleResultsFound:
            LOG.error(_("Multiple ports have port_id starting with %s."),
                      port_id)
            return None

    def get_ports_details_list(self, rpc_context, **kwargs):
        """Agent requests device details."""
        agent_id = kwargs.get('agent_id')
        port_ids = kwargs.get('port_ids')
        vcenter_id = kwargs['vcenter_id']
        cluster_id = kwargs['cluster_id']
        LOG.debug("Port details requested by agent "
                  "%(agent_id)s for ports %(ports)s.",
                  {'ports': port_ids, 'agent_id': agent_id})
        out_ports = []
        for port_id in port_ids:
            port_db = self._get_port_db(rpc_context.session, port_id, agent_id)
            if not port_db:
                continue
            port = self.plugin._make_port_dict(port_db)
            network = self.plugin.get_network(rpc_context, port['network_id'])
            port_context = driver_context.PortContext(self.plugin,
                                                      rpc_context,
                                                      port,
                                                      network,
                                                      port_db.port_binding)
            segment = port_context.top_bound_segment
            # Reference: ML2  Driver API changes for hierarchical port binding.
            bound_port = port_context.current

            if not segment:
                LOG.warning(_("Port %(port_id)s requested by agent "
                              "%(agent_id)s on network %(network_id)s not "
                              "bound, vif_type: %(vif_type)s."),
                            {'port_id': port['id'],
                             'agent_id': agent_id,
                             'network_id': port['network_id'],
                             'vif_type': port[portbindings.VIF_TYPE]})
                continue
            bound_port['lvid'] = None
            if segment[api.NETWORK_TYPE] == 'vxlan':
                port_info = {'port_id': bound_port['id'],
                             'vcenter_id': vcenter_id,
                             'cluster_id': cluster_id,
                             'network_id': bound_port['network_id']}
                lvid = ovsvapp_db.get_local_vlan(port_info, False)
                if lvid:
                    bound_port['lvid'] = lvid
                else:
                    # Local VLANs are exhausted !! No point processing
                    # further.
                    LOG.error(_("Local VLAN not available in the cluster"
                                " %(cluster)s for port"
                                " %(port_id)s in vcenter %(vcenter)s."),
                              {'port_id': bound_port['id'],
                               'cluster': cluster_id,
                               'vcenter': vcenter_id})
                    continue
                    # Skip sending back this port as there is no lvid.
            else:
                bound_port['lvid'] = segment[api.SEGMENTATION_ID]

            entry = {'network_id': bound_port['network_id'],
                     'port_id': bound_port['id'],
                     'lvid': bound_port['lvid'],
                     'mac_address': bound_port['mac_address'],
                     'admin_state_up': bound_port['admin_state_up'],
                     'network_type': segment[api.NETWORK_TYPE],
                     'segmentation_id': segment[api.SEGMENTATION_ID],
                     'physical_network': segment[api.PHYSICAL_NETWORK],
                     'fixed_ips': bound_port['fixed_ips'],
                     'device_id': bound_port['device_id'],
                     'device_owner': bound_port['device_owner']}
            LOG.debug("Adding port detail: %s.", entry)
            out_ports.append(entry)
        return out_ports

    def update_lvid_assignment(self, rpc_context, **kwargs):
        net_info = kwargs.get('net_info')
        if net_info:
            try:
                ovsvapp_db.release_local_vlan(net_info)
            except Exception:
                LOG.exception(_("Failed to release the local vlan"))
        return


class OVSvAppAgentNotifyAPI(object):

    """Agent side of the OVSvApp rpc API."""

    def __init__(self, topic=topics.AGENT):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        self.topic = topic

    def _get_device_topic(self, action, cluster_id):
        cluster_device_topic = ovsvapp_utils.get_cluster_based_topic(
            cluster_id, ovsvapp_const.DEVICE)
        return topics.get_topic_name(self.topic,
                                     cluster_device_topic,
                                     action)

    def device_create(self, context, device, ports, sg_rules, cluster_id):
        cctxt = self.client.prepare(
            topic=self._get_device_topic(topics.CREATE, cluster_id),
            fanout=True)
        cctxt.cast(context, 'device_create', device=device, ports=ports,
                   sg_rules=sg_rules, cluster_id=cluster_id)

    def device_delete(self, context, network_info, host, cluster_id):
        cctxt = self.client.prepare(
            topic=self._get_device_topic(topics.DELETE, cluster_id))
        return cctxt.call(context, 'device_delete',
                          network_info=network_info, host=host,
                          cluster_id=cluster_id)
