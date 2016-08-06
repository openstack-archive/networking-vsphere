# Copyright (c) 2016 Hewlett-Packard Development Company, L.P.
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

from oslo_log import log

from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants as ovs_const  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import br_int  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import br_phys  # noqa
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import br_tun  # noqa

LOG = log.getLogger(__name__)


class OVSvAppIntegrationBridge(br_int.OVSIntegrationBridge):

    def provision_local_vlan(self, network_type, lvid, segmentation_id,
                             sec_ofport, int_ofport, tun_ofport):
        """Add integration bridge flows based on VLAN and physnet."""

        if network_type == p_const.TYPE_VLAN:
            self.add_flow(priority=4,
                          in_port=sec_ofport,
                          dl_vlan=lvid,
                          actions="output:%s"
                          % int_ofport)
            self.add_flow(priority=4,
                          in_port=int_ofport,
                          dl_vlan=segmentation_id,
                          actions="mod_vlan_vid:%s,output:%s"
                          % (lvid, sec_ofport))
        else:
            self.add_flow(priority=4,
                          in_port=sec_ofport,
                          dl_vlan=lvid,
                          actions="output:%s"
                          % tun_ofport)

    def reclaim_local_vlan(self, network_type, segmentation_id,
                           vlan, int_ofport, sec_ofport):
        if network_type == p_const.TYPE_VLAN:
            self.delete_flows(dl_vlan=segmentation_id,
                              in_port=int_ofport)
            self.delete_flows(dl_vlan=vlan,
                              in_port=sec_ofport)
        else:
            self.delete_flows(dl_vlan=vlan,
                              in_port=sec_ofport)


class OVSvAppPhysicalBridge(br_phys.OVSPhysicalBridge):

    def provision_local_vlan(self, lvid, segmentation_id,
                             phys_ofport, eth_ofport):
        """Add the drop flows for host owned ports."""
        self.add_flow(priority=4,
                      in_port=phys_ofport,
                      dl_vlan=lvid,
                      actions="mod_vlan_vid:%s,output:%s" % (
                              segmentation_id, eth_ofport))

    def add_drop_flows(self, vlan, mac_address,
                       eth_ofport):
        self.add_flow(priority=4,
                      in_port=eth_ofport,
                      dl_src=mac_address,
                      dl_vlan=vlan,
                      actions="drop")

    def delete_drop_flows(self, mac_address, vlan):
        self.delete_flows(dl_src=mac_address,
                          dl_vlan=vlan)

    def reclaim_local_vlan(self, vlan):
        self.delete_flows(dl_vlan=vlan)


class OVSvAppTunnelBridge(br_tun.OVSTunnelBridge):

    def provision_local_vlan(self, lvid, segmentation_id,
                             tun_ofports):
        if tun_ofports:
            self.add_flow(table=ovs_const.FLOOD_TO_TUN,
                          dl_vlan=lvid,
                          actions="strip_vlan,"
                          "set_tunnel:%s,output:%s" %
                          (segmentation_id, tun_ofports))
        self.add_flow(
            table=ovs_const.TUN_TABLE[p_const.TYPE_VXLAN],
            priority=1,
            tun_id=segmentation_id,
            actions="mod_vlan_vid:%s,resubmit(,%s)" %
            (lvid, ovs_const.LEARN_FROM_TUN))

    def reclaim_local_vlan(self, segmentation_id, vlan):
        self.delete_flows(
            table=ovs_const.TUN_TABLE[p_const.TYPE_VXLAN],
            tun_id=segmentation_id)
        self.delete_flows(dl_vlan=vlan)
