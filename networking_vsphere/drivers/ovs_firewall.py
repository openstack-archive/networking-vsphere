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

# import itertools
# import netaddr
import threading

from oslo.config import cfg

from neutron.agent import firewall
from neutron.agent.linux import ovs_lib
from neutron.common import constants
from neutron.openstack.common import log as logging
# from neutron.plugins.ovsvapp.agent import ovsvapp_agent

SG_DROPALL_PRI = 0
SG_DEFAULT_PRI = 1
SG_LOW_PRI = 5
SG_RULES_PRI = 10
SG_TP_PRI = 20
SG_TCP_FLAG_PRI = 25
SG_DROP_HIGH_PRI = 50

SG_DEFAULT_TABLE_ID = 0
SG_IP_TABLE_ID = 2
SG_TCP_TABLE_ID = 2
SG_UDP_TABLE_ID = 2
SG_ICMP_TABLE_ID = 2
SG_LEARN_TABLE_ID = 5

ICMP_ECHO_REQ = 8
ICMP_ECHO_REP = 0
ICMP_TIME_EXCEEDED = 11
ICMP_TS_REQ = 13
ICMP_TS_REP = 14
ICMP_INFO_REQ = 15
ICMP_INFO_REP = 16
ICMP_AM_REQ = 17
ICMP_AM_REP = 18
ICMP_DEST_UNREACH = 3

LOG = logging.getLogger(__name__)
INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
PROTOCOLS = {constants.PROTO_NAME_TCP: constants.PROTO_NAME_TCP,
             constants.PROTO_NUM_TCP: constants.PROTO_NAME_TCP,
             constants.PROTO_NAME_UDP: constants.PROTO_NAME_UDP,
             constants.PROTO_NUM_UDP: constants.PROTO_NAME_UDP,
             constants.PROTO_NAME_ICMP: constants.PROTO_NAME_ICMP,
             constants.PROTO_NUM_ICMP: constants.PROTO_NAME_ICMP,
             constants.PROTO_NAME_ICMP_V6: constants.PROTO_NAME_ICMP_V6,
             constants.PROTO_NUM_ICMP_V6: constants.PROTO_NAME_ICMP_V6}

ETHERTYPE = {constants.IPv4: "ip",
             constants.IPv6: "ip6"}

sg_conf = cfg.CONF.SECURITYGROUP

PORT_KEYS = ['security_group_source_groups',
             'mac_address',
             'network_id',
             'id',
             'security_groups',
             'segmentation_id']


class OVSFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through OVS flows."""

    def __init__(self):
        self.filtered_ports = {}
        # TODO(sudhakar-gariganti) un-comment the below code when
        # ovsvapp_agent has the code enabled
        # self.root_helper = cfg.CONF.AGENT.root_helper
        # For now initializing root helper to sudo
        self.root_helper = None
        if sg_conf.security_bridge is None:
            LOG.debug("Security_bridge not configured")
            return
        secbr_list = (sg_conf.security_bridge).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]
        self.sg_br = ovs_lib.OVSBridge(secbr_name, self.root_helper)
        self.phy_ofport = self.sg_br.get_port_ofport(secbr_phyname)
        # TODO(sudhakar-gariganti) un-comment the below code when
        # ovsvapp_agent has the code enabled
        # self.patch_ofport = self.sg_br.get_port_ofport(
        #    ovsvapp_agent.SEC_TO_INT_PATCH)
        # self.portCache = ovsvapp_agent.portCache()
        self._defer_apply = False
        if not cfg.CONF.OVSVAPPAGENT.agent_maintenance:
            self.setup_base_flows()
        self.locks = {}

    def get_lock(self, port_id):
        if port_id not in self.locks:
            LOG.debug("Creating lock for port %s" % port_id)
            self.locks[port_id] = threading.RLock()
        self.locks[port_id].acquire()

    def release_lock(self, port_id):
        if port_id in self.locks:
            self.locks[port_id].release()

    def remove_lock(self, port_id):
        if port_id in self.locks:
            self.locks.pop(port_id, None)

    @property
    def ports(self):
        return self.filtered_ports

    def _get_compact_port(self, port):
        new_port = {}
        new_port['device'] = port['id']
        for key in PORT_KEYS:
            if key in port:
                new_port[key] = port[key]
        return new_port

    def _add_ovs_flow(self, sg_br, pri, table_id, action,
                      protocol=None, dl_dest=None,
                      tcp_flag=None, icmp_req_type=None):
        """Helper method for adding OVS fLows

        Method which will help add an openflow rule with the given
        priority and action in the specified table
        """
        if protocol:
            sg_br.add_flow(table=table_id, priority=pri,
                           proto=protocol, actions=action)
        elif dl_dest:
            sg_br.add_flow(table=table_id, priority=pri,
                           dl_dst=dl_dest, actions=action)
        elif tcp_flag:
            sg_br.add_flow(table=table_id, priority=pri,
                           proto=constants.PROTO_NAME_TCP,
                           tcp_flags=tcp_flag, actions=action)
        elif icmp_req_type:
            sg_br.add_flow(table=table_id, priority=pri,
                           proto=constants.PROTO_NAME_ICMP,
                           icmp_type=icmp_req_type,
                           actions=action)
        else:
            sg_br.add_flow(table=table_id, priority=pri, actions=action)

    def _add_icmp_learn_flow(self, sec_br, reqType, resType,
                             pri=SG_TP_PRI):
        sec_br.add_flow(priority=pri,
                        table=SG_ICMP_TABLE_ID,
                        proto=constants.PROTO_NAME_ICMP,
                        icmp_type=reqType,
                        actions="learn(%s)" %
                        self._get_icmp_learn_flow(resType))

    def _get_icmp_learn_flow(self, resType):
        if resType is ICMP_DEST_UNREACH:
            ip_str = ""
        else:
            ip_str = "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
        return ("table=%s,"
                "priority=%s,"
                "idle_timeout=30,"
                "dl_type=0x0800,"
                "NXM_OF_VLAN_TCI[0..11],"
                "nw_proto=%s,"
                "icmp_type=%s,"
                "%s"
                "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                "output:NXM_OF_IN_PORT[]" %
                (SG_LEARN_TABLE_ID,
                 SG_TP_PRI,
                 constants.PROTO_NUM_ICMP,
                 resType, ip_str))

    def _setup_icmp_learn_flows(self, sec_br):
        # ICMP Learned flows
        self._add_icmp_learn_flow(sec_br, ICMP_ECHO_REQ, ICMP_ECHO_REP)
        self._add_icmp_learn_flow(sec_br, ICMP_TS_REQ, ICMP_TS_REP)
        self._add_icmp_learn_flow(sec_br, ICMP_INFO_REQ, ICMP_INFO_REP)
        self._add_icmp_learn_flow(sec_br, ICMP_AM_REQ, ICMP_AM_REP)

    def _setup_learning_flows(self, sec_br):
        """Helper method for adding learing fLows

        Method which will help setup the base learning flows at
        the start of the agent.
        These flows are populated in specific tables for
        TCP/UDP/ICMP
        """
        # First we chain the tables
        self._add_ovs_flow(sec_br, SG_DEFAULT_PRI,
                           SG_ICMP_TABLE_ID, "drop")
        # If DMAC is bcast or mcast, don't learn
        self._add_ovs_flow(sec_br, SG_DROP_HIGH_PRI,
                           SG_IP_TABLE_ID, "drop",
                           dl_dest="01:00:00:00:00:00/01:00:00:00:00:00")

        # Now we add learning flows one for TCP and another for UDP
        learned_tcp_flow = ("table=%s,"
                            "priority=%s,"
                            "fin_idle_timeout=1,"
                            "idle_timeout=7200,"
                            "nw_proto=%s,"
                            "NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],"
                            "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                            "dl_type=0x0800,"
                            "NXM_OF_VLAN_TCI[0..11],"
                            "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
                            "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                            "NXM_OF_TCP_SRC[]=NXM_OF_TCP_DST[],"
                            "NXM_OF_TCP_DST[]=NXM_OF_TCP_SRC[],"
                            "output:NXM_OF_IN_PORT[]" %
                            (SG_LEARN_TABLE_ID,
                             SG_TP_PRI,
                             constants.PROTO_NUM_TCP))
        self._add_ovs_flow(sec_br, SG_TP_PRI,
                           SG_TCP_TABLE_ID,
                           "learn(%s)" % learned_tcp_flow,
                           protocol=constants.PROTO_NAME_TCP)

        learned_udp_flow = ("table=%s,"
                            "priority=%s,"
                            "idle_timeout=300,"
                            "nw_proto=%s,"
                            "NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],"
                            "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                            "dl_type=0x0800,"
                            "NXM_OF_VLAN_TCI[0..11],"
                            "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
                            "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                            "NXM_OF_UDP_SRC[]=NXM_OF_UDP_DST[],"
                            "NXM_OF_UDP_DST[]=NXM_OF_UDP_SRC[],"
                            "output:NXM_OF_IN_PORT[]" %
                            (SG_LEARN_TABLE_ID,
                             SG_TP_PRI,
                             constants.PROTO_NUM_UDP))
        self._add_ovs_flow(sec_br, SG_TP_PRI,
                           SG_UDP_TABLE_ID,
                           "learn(%s)" % learned_udp_flow,
                           protocol=constants.PROTO_NAME_UDP)
        # Now setup the ICMP learn flows.
        self._setup_icmp_learn_flows(sec_br)

    def setup_base_flows(self):
        """Method for configuring the default flows in OVS bridge

        Method which will help setup the base flows at the start
        of the agent
        """
        try:
            with self.sg_br.deferred(full_ordered=True, order=(
                'del', 'mod', 'add')) as sec_br:
                self._add_ovs_flow(sec_br, SG_DEFAULT_PRI,
                                   SG_DEFAULT_TABLE_ID,
                                   "resubmit(,%s)" % SG_LEARN_TABLE_ID)
                self._add_ovs_flow(sec_br, SG_DROPALL_PRI,
                                   SG_LEARN_TABLE_ID, "drop")
                # Allow all ARP, parity with iptables
                self._add_ovs_flow(sec_br, SG_RULES_PRI,
                                   SG_DEFAULT_TABLE_ID,
                                   "normal", protocol="arp")
                # Allow all RARP, parity with iptables
                self._add_ovs_flow(sec_br, SG_RULES_PRI,
                                   SG_DEFAULT_TABLE_ID,
                                   "normal", protocol="rarp")
                # Rule to allow VMs to send DHCP requests (udp)
                sec_br.add_flow(priority=SG_RULES_PRI,
                                table=SG_DEFAULT_TABLE_ID,
                                proto="udp", tp_src="68", tp_dst="67",
                                actions="normal")
                # Always allow ICMP DestUnreach
                self._add_ovs_flow(sec_br, SG_TP_PRI,
                                   SG_DEFAULT_TABLE_ID, "normal",
                                   icmp_req_type=ICMP_DEST_UNREACH)

                # Always allow ICMP TTL Exceeded
                self._add_ovs_flow(sec_br, SG_TP_PRI,
                                   SG_DEFAULT_TABLE_ID, "normal",
                                   icmp_req_type=ICMP_TIME_EXCEEDED)
                # Always resubmit FIN pkts to learn table
                self._add_ovs_flow(sec_br, SG_TCP_FLAG_PRI,
                                   SG_DEFAULT_TABLE_ID,
                                   "resubmit(,%s),normal" % SG_LEARN_TABLE_ID,
                                   tcp_flag='+fin')
                # Always resubmit RST pkts to learn table
                self._add_ovs_flow(sec_br, SG_TCP_FLAG_PRI,
                                   SG_DEFAULT_TABLE_ID,
                                   "resubmit(,%s),normal" % SG_LEARN_TABLE_ID,
                                   tcp_flag='+rst')
                self._setup_learning_flows(sec_br)

        except Exception:
            LOG.exception(_("Unable to add base flows"))

    def prepare_port_filter(self, port):
        pass

    def update_port_filter(self, port):
        pass

    def remove_port_filter(self, port):
        pass

    def filter_defer_apply_on(self):
        if not self._defer_apply:
            self._defer_apply = True

    def filter_defer_apply_off(self):
        if self._defer_apply:
            self._defer_apply = False

    def get_cookie(self, port):
        return ("0x%x" % (hash(port['id']) & 0xffffffffffffffff))
