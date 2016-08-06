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

import itertools

import netaddr
from oslo_config import cfg
from oslo_log import log

from neutron.agent.common import ovs_lib
from neutron.agent import firewall
from neutron.common import constants

from networking_vsphere._i18n import _LE, _LW
from networking_vsphere.common import constants as ovsvapp_const

LOG = log.getLogger(__name__)

PROTOCOLS = {constants.PROTO_NAME_TCP: constants.PROTO_NAME_TCP,
             constants.PROTO_NUM_TCP: constants.PROTO_NAME_TCP,
             constants.PROTO_NAME_UDP: constants.PROTO_NAME_UDP,
             constants.PROTO_NUM_UDP: constants.PROTO_NAME_UDP,
             constants.PROTO_NAME_ICMP: constants.PROTO_NAME_ICMP,
             constants.PROTO_NUM_ICMP: constants.PROTO_NAME_ICMP,
             constants.PROTO_NAME_IPV6_ICMP: constants.PROTO_NAME_IPV6_ICMP,
             constants.PROTO_NUM_IPV6_ICMP: constants.PROTO_NAME_IPV6_ICMP}

ETHERTYPE = {constants.IPv4: "ip",
             constants.IPv6: "ipv6"}

INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'

sg_conf = cfg.CONF.SECURITYGROUP

PORT_KEYS = ['security_group_source_groups',
             'mac_address',
             'network_id',
             'id',
             'security_groups',
             'lvid']


class OVSFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through OVS flows."""

    def __init__(self):
        self.filtered_ports = {}
        self.provider_port_cache = set()
        if sg_conf.security_bridge_mapping is None:
            LOG.warning(_LW("Security bridge mapping not configured."))
            return
        secbr_list = (sg_conf.security_bridge_mapping).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]
        self.sg_br = ovs_lib.OVSBridge(secbr_name)
        self.phy_ofport = self.sg_br.get_port_ofport(secbr_phyname)
        self.patch_ofport = self.sg_br.get_port_ofport(
            ovsvapp_const.SEC_TO_INT_PATCH)
        self._defer_apply = False
        if not self.check_ovs_firewall_restart():
            self.setup_base_flows()

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        """Called when a security group is updated."""
        pass

    def check_ovs_firewall_restart(self):
        canary_flow = self.sg_br.dump_flows_for_table(
            ovsvapp_const.SG_CANARY_TABLE_ID)
        retval = False
        if canary_flow:
            canary_flow = '\n'.join(item for item in canary_flow.splitlines()
                                    if 'OFPST_FLOW' not in item)
        if canary_flow != '':
            retval = True
        return retval

    @property
    def ports(self):
        return self.filtered_ports

    def _get_compact_port(self, port):
        if 'lvid' not in port:
            if port['id'] in self.filtered_ports:
                old_port = self.filtered_ports[port['id']]
                port['lvid'] = old_port['lvid']
        new_port = {}
        new_port['device'] = port['id']
        for key in PORT_KEYS:
            if key in port:
                new_port[key] = port[key]
        return new_port

    def remove_ports_from_provider_cache(self, ports):
        if ports:
            LOG.debug("OVSF Clearing %s ports from provider "
                      "cache.", len(ports))
            self.provider_port_cache = self.provider_port_cache - set(ports)

    def _add_ovs_flow(self, sg_br, pri, table_id, action, in_port=None,
                      protocol=None, dl_dest=None, tcp_flag=None,
                      icmp_req_type=None):
        """Helper method for adding OVS flows.

        Method which will help add an openflow rule with the given
        priority and action in the specified table.
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
        elif in_port:
            sg_br.add_flow(table=table_id, priority=pri, in_port=in_port,
                           actions=action)
        else:
            sg_br.add_flow(table=table_id, priority=pri, actions=action)

    def _add_icmp_learn_flow(self, sec_br, reqType, resType,
                             pri=ovsvapp_const.SG_TP_PRI):
        sec_br.add_flow(priority=pri,
                        table=ovsvapp_const.SG_ICMP_TABLE_ID,
                        proto=constants.PROTO_NAME_ICMP,
                        icmp_type=reqType,
                        actions="learn(%s)" %
                        self._get_icmp_learn_flow(resType))

    def _get_icmp_learn_flow(self, resType):
        if resType is ovsvapp_const.ICMP_DEST_UNREACH:
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
                (ovsvapp_const.SG_LEARN_TABLE_ID,
                 ovsvapp_const.SG_TP_PRI,
                 constants.PROTO_NUM_ICMP,
                 resType, ip_str))

    def _setup_icmp_learn_flows(self, sec_br):
        # ICMP Learned flows
        self._add_icmp_learn_flow(sec_br, ovsvapp_const.ICMP_ECHO_REQ,
                                  ovsvapp_const.ICMP_ECHO_REP)
        self._add_icmp_learn_flow(sec_br, ovsvapp_const.ICMP_TS_REQ,
                                  ovsvapp_const.ICMP_TS_REP)
        self._add_icmp_learn_flow(sec_br, ovsvapp_const.ICMP_INFO_REQ,
                                  ovsvapp_const.ICMP_INFO_REP)
        self._add_icmp_learn_flow(sec_br, ovsvapp_const.ICMP_AM_REQ,
                                  ovsvapp_const.ICMP_AM_REP)

    def _setup_learning_flows(self, sec_br):
        """Helper method for adding learning flows.

        Method which will help setup the base learning flows at
        the start of the agent.
        These flows are populated in specific tables for
        TCP/UDP/ICMP.
        """
        # First we chain the tables.
        self._add_ovs_flow(sec_br, ovsvapp_const.SG_DEFAULT_PRI,
                           ovsvapp_const.SG_ICMP_TABLE_ID, "drop")
        # If DMAC is bcast or mcast, don't learn.
        self._add_ovs_flow(sec_br, ovsvapp_const.SG_DROP_HIGH_PRI,
                           ovsvapp_const.SG_IP_TABLE_ID, "drop",
                           dl_dest="01:00:00:00:00:00/01:00:00:00:00:00")

        # Now we add learning flows one for TCP and another for UDP.
        learned_tcp_flow = ("table=%s,"
                            "priority=%s,"
                            "fin_idle_timeout=1,"
                            "idle_timeout=7200,"
                            "NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],"
                            "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                            "dl_type=0x0800,"
                            "NXM_OF_VLAN_TCI[0..11],"
                            "nw_proto=%s,"
                            "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
                            "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                            "NXM_OF_TCP_SRC[]=NXM_OF_TCP_DST[],"
                            "NXM_OF_TCP_DST[]=NXM_OF_TCP_SRC[],"
                            "output:NXM_OF_IN_PORT[]" %
                            (ovsvapp_const.SG_LEARN_TABLE_ID,
                             ovsvapp_const.SG_TP_PRI,
                             constants.PROTO_NUM_TCP))
        self._add_ovs_flow(sec_br, ovsvapp_const.SG_TP_PRI,
                           ovsvapp_const.SG_TCP_TABLE_ID,
                           "learn(%s)" % learned_tcp_flow,
                           protocol=constants.PROTO_NAME_TCP)

        learned_udp_flow = ("table=%s,"
                            "priority=%s,"
                            "idle_timeout=300,"
                            "NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],"
                            "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                            "dl_type=0x0800,"
                            "NXM_OF_VLAN_TCI[0..11],"
                            "nw_proto=%s,"
                            "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
                            "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                            "NXM_OF_UDP_SRC[]=NXM_OF_UDP_DST[],"
                            "NXM_OF_UDP_DST[]=NXM_OF_UDP_SRC[],"
                            "output:NXM_OF_IN_PORT[]" %
                            (ovsvapp_const.SG_LEARN_TABLE_ID,
                             ovsvapp_const.SG_TP_PRI,
                             constants.PROTO_NUM_UDP))
        self._add_ovs_flow(sec_br, ovsvapp_const.SG_TP_PRI,
                           ovsvapp_const.SG_UDP_TABLE_ID,
                           "learn(%s)" % learned_udp_flow,
                           protocol=constants.PROTO_NAME_UDP)
        # Now setup the ICMP learn flows.
        self._setup_icmp_learn_flows(sec_br)

    def setup_base_flows(self):
        """Method for configuring the default flows in OVS bridge.

        Method which will help setup the base flows at the start
        of the agent.
        """
        try:
            sec_br = self.sg_br
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_DEFAULT_PRI,
                               ovsvapp_const.SG_DEFAULT_TABLE_ID,
                               "resubmit(,%s)" %
                               ovsvapp_const.SG_LEARN_TABLE_ID,
                               in_port=self.patch_ofport)
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_DEFAULT_PRI,
                               ovsvapp_const.SG_DEFAULT_TABLE_ID,
                               "resubmit(,%s)" %
                               ovsvapp_const.SG_EGRESS_TABLE_ID,
                               in_port=self.phy_ofport)
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_DROPALL_PRI,
                               ovsvapp_const.SG_EGRESS_TABLE_ID, "drop")
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_DROPALL_PRI,
                               ovsvapp_const.SG_CANARY_TABLE_ID, "drop")
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_DROPALL_PRI,
                               ovsvapp_const.SG_LEARN_TABLE_ID, "drop")
            # Allow all ARP, parity with iptables.
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_RULES_PRI,
                               ovsvapp_const.SG_DEFAULT_TABLE_ID,
                               "normal", protocol="arp")
            # Allow all RARP, parity with iptables.
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_RULES_PRI,
                               ovsvapp_const.SG_DEFAULT_TABLE_ID,
                               "normal", protocol="rarp")
            # Rule to allow VMs to send DHCP requests (udp).
            sec_br.add_flow(priority=ovsvapp_const.SG_RULES_PRI,
                            table=ovsvapp_const.SG_DEFAULT_TABLE_ID,
                            proto="udp", tp_src="68", tp_dst="67",
                            actions="normal")
            # Always allow ICMP DestUnreach.
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_TP_PRI,
                               ovsvapp_const.SG_DEFAULT_TABLE_ID,
                               "normal", icmp_req_type=ovsvapp_const.
                               ICMP_DEST_UNREACH)

            # Always allow ICMP TTL Exceeded.
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_TP_PRI,
                               ovsvapp_const.SG_DEFAULT_TABLE_ID, "normal",
                               icmp_req_type=ovsvapp_const.
                               ICMP_TIME_EXCEEDED)

            self._setup_learning_flows(sec_br)

            # Always resubmit FIN pkts to learn table.
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_TCP_FLAG_PRI,
                               ovsvapp_const.SG_DEFAULT_TABLE_ID,
                               "resubmit(,%s),normal" %
                               ovsvapp_const.SG_LEARN_TABLE_ID,
                               tcp_flag='+fin')
            # Always resubmit RST pkts to learn table.
            self._add_ovs_flow(sec_br, ovsvapp_const.SG_TCP_FLAG_PRI,
                               ovsvapp_const.SG_DEFAULT_TABLE_ID,
                               "resubmit(,%s),normal" %
                               ovsvapp_const.SG_LEARN_TABLE_ID,
                               tcp_flag='+rst')
        except Exception:
            LOG.exception(_LE("Unable to add base flows."))

    def add_ports_to_filter(self, ports):
        for port in ports:
            LOG.debug("OVSF Adding port: %s to filter.", port)
            self.filtered_ports[port['id']] = self._get_compact_port(port)

    def _get_port_vlan(self, port_id):
        if port_id:
            port = self.filtered_ports.get(port_id)
            LOG.debug("Filtered port: %s.", port)
            if port:
                return port['lvid']

    def _setup_aap_flows(self, sec_br, port):
        """Method to help setup rules for allowed address pairs."""
        vlan = self._get_port_vlan(port['id'])
        if not vlan:
            LOG.error(_LE("Missing VLAN information for "
                          "port: %s."), port['id'])
            return
        if isinstance(port.get('allowed_address_pairs'), list):
            for addr_pair in port['allowed_address_pairs']:
                if netaddr.IPNetwork(addr_pair["ip_address"]).version == 4:
                    ap_proto = "ip"
                else:
                    ap_proto = "ipv6"
                sec_br.add_flow(priority=ovsvapp_const.SG_RULES_PRI,
                                table=ovsvapp_const.SG_DEFAULT_TABLE_ID,
                                cookie=self.get_cookie(port['id']),
                                dl_dst=port["mac_address"],
                                in_port=self.patch_ofport,
                                dl_src=addr_pair["mac_address"],
                                dl_vlan=vlan,
                                proto=ap_proto,
                                nw_src=addr_pair["ip_address"],
                                actions="resubmit(,%s),output:%s" %
                                (ovsvapp_const.SG_IP_TABLE_ID,
                                 self.phy_ofport))

    def _get_net_prefix_len(self, ip_prefix):
        if ip_prefix:
            return netaddr.IPNetwork(ip_prefix).prefixlen
        else:
            return 0

    def _get_protocol(self, ethertype, proto):
        if ethertype == constants.IPv6 and (
            proto == constants.PROTO_NAME_ICMP):
            return ['icmp6']
        elif proto is not None:
            protocol = PROTOCOLS.get(proto)
            if protocol is None:
                return [ETHERTYPE.get(ethertype), proto]
            else:
                return [protocol]
        elif ethertype == constants.IPv4:
            return ['ip']
        elif ethertype == constants.IPv6:
            return ['ipv6']

    def _add_flows_to_sec_br(self, sec_br, port, flow, direction):
        if direction == EGRESS_DIRECTION:
            for ip in port['fixed_ips']:
                sec_br.add_flow(priority=ovsvapp_const.SG_DEFAULT_PRI,
                                table=ovsvapp_const.SG_EGRESS_TABLE_ID,
                                dl_src=flow['dl_src'],
                                dl_vlan=flow['dl_vlan'],
                                proto=flow['proto'],
                                nw_src=ip,
                                in_port=self.phy_ofport,
                                actions="resubmit(,%s)"
                                % ovsvapp_const.SG_LEARN_TABLE_ID)
                flow['nw_src'] = ip
                flow['table'] = ovsvapp_const.SG_EGRESS_TABLE_ID
                LOG.debug("OVSF adding flow: %s", flow)
                sec_br.add_flow(**flow)
        elif direction == INGRESS_DIRECTION:
                flow['table'] = ovsvapp_const.SG_DEFAULT_TABLE_ID
                LOG.debug("OVSF adding flow: %s", flow)
                sec_br.add_flow(**flow)

    def _add_flow_with_range(self, sec_br, port, flow, direction,
                             dest_port_min=None, dest_port_max=None,
                             src_port_min=None, src_port_max=None):
        if ((dest_port_min is None and dest_port_max is None) or
                (dest_port_min == 1 and dest_port_max == 65535)):
            dest_port_min = -1
            dest_port_max = -1
        if ((src_port_min is None and src_port_max is None) or
                (src_port_min == 1 and src_port_max == 65535)):
            src_port_min = -1
            src_port_max = -1

        for dest_port, src_port in itertools.product(
                range(dest_port_min, dest_port_max + 1),
                range(src_port_min, src_port_max + 1)):
            if dest_port >= 0:
                flow["tp_dst"] = dest_port
            if src_port >= 0:
                flow["tp_src"] = src_port
            self._add_flows_to_sec_br(sec_br, port, flow, direction)

    def _add_flows(self, sec_br, port, cookie, for_provider=False):
        egress_action = 'normal'
        ingress_action = 'output:%s' % self.phy_ofport

        if not for_provider:
            rules = port["security_group_rules"]
        else:
            rules = port["sg_provider_rules"]

        vlan = self._get_port_vlan(port['id'])
        if not vlan:
            LOG.error(_LE('Missing VLAN for port: %s.'), port['id'])
            return
        for rule in rules:
            direction = rule.get('direction')
            proto = rule.get('protocol')
            dest_port_min = rule.get('port_range_min')
            dest_port_max = rule.get('port_range_max')
            src_port_min = rule.get('source_port_range_min')
            src_port_max = rule.get('source_port_range_max')
            ethertype = rule.get('ethertype')
            src_ip_prefix = rule.get('source_ip_prefix')
            dest_ip_prefix = rule.get('dest_ip_prefix')
            flow = dict(priority=ovsvapp_const.SG_RULES_PRI)
            flow["cookie"] = cookie
            flow["dl_vlan"] = vlan
            # Fill the src and dest IPs match params.
            src_ip_prefixlen = self._get_net_prefix_len(src_ip_prefix)
            if src_ip_prefixlen > 0:
                flow["nw_src"] = src_ip_prefix
            dest_ip_prefixlen = self._get_net_prefix_len(dest_ip_prefix)
            if dest_ip_prefixlen > 0:
                flow["nw_dst"] = dest_ip_prefix
            # Fill the protocol related  match params.
            protocols = self._get_protocol(ethertype, proto)
            protocol = protocols[0]
            flow["proto"] = protocol
            if len(protocols) > 1:
                flow["nw_proto"] = protocols[1]
            # set source and destination params and action for the flow.
            if direction == INGRESS_DIRECTION:
                flow["dl_dst"] = port["mac_address"]
                flow["in_port"] = self.patch_ofport
                action = ingress_action
            elif direction == EGRESS_DIRECTION:
                flow["dl_src"] = port["mac_address"]
                flow["in_port"] = self.phy_ofport
                action = egress_action
            tcp_udp = set([constants.PROTO_NAME_TCP,
                           constants.PROTO_NAME_UDP])
            table_id = None
            if protocol in tcp_udp:
                flow["priority"] = ovsvapp_const.SG_TP_PRI
                if protocol == constants.PROTO_NAME_TCP:
                    table_id = ovsvapp_const.SG_TCP_TABLE_ID
                else:
                    table_id = ovsvapp_const.SG_UDP_TABLE_ID
                flow["actions"] = ("resubmit(,%s),%s" % (table_id, action))
                self._add_flow_with_range(sec_br, port, flow, direction,
                                          dest_port_min, dest_port_max,
                                          src_port_min, src_port_max)
                # Since we added the required flows in the above method
                # we just proceed to the next sg rule.
                continue
            elif protocol == constants.PROTO_NAME_ICMP:
                flow["priority"] = ovsvapp_const.SG_TP_PRI
                if dest_port_min is not None:
                    flow["icmp_type"] = dest_port_min
                if dest_port_max is not None:
                    flow["icmp_code"] = dest_port_max
                table_id = ovsvapp_const.SG_ICMP_TABLE_ID
            else:
                table_id = ovsvapp_const.SG_IP_TABLE_ID

            flow["actions"] = ("resubmit(,%s),%s" % (table_id, action))
            self._add_flows_to_sec_br(sec_br, port, flow, direction)

    def prepare_port_filter(self, port):
        """Method to add OVS rules for a newly created VM port."""
        LOG.debug("OVSF Preparing port %s filter.", port['id'])
        port_cookie = self.get_cookie(port['id'])
        port_provider_cookie = self.get_cookie('pr' + port['id'])
        try:
            with self.sg_br.deferred(full_ordered=True, order=(
                'del', 'mod', 'add')) as deferred_br:
                self._setup_aap_flows(deferred_br, port)
                if port['id'] not in self.provider_port_cache:
                    # Using provider string as cookie for normal rules.
                    self._add_flows(deferred_br, port,
                                    port_provider_cookie, True)
                    self.provider_port_cache.add(port['id'])
                # Using port id as cookie for normal rules.
                self._add_flows(deferred_br, port, port_cookie)
            self.filtered_ports[port['id']] = self._get_compact_port(port)
        except Exception:
            LOG.exception(_LE("Unable to add flows for %s."), port['id'])

    def _remove_flows(self, sec_br, port_id, del_provider_rules=False):
        """Remove all flows for a port."""
        LOG.debug("OVSF Removing flows start for port: %s.", port_id)
        try:
            sec_br.delete_flows(cookie="%s/-1" %
                                self.get_cookie(port_id))
            if del_provider_rules:
                sec_br.delete_flows(cookie="%s/-1" %
                                    self.get_cookie('pr' + port_id))
            port = self.filtered_ports.get(port_id)
            vlan = self._get_port_vlan(port_id)
            if 'mac_address' not in port or not vlan:
                LOG.debug("Invalid mac address or vlan for port "
                          "%s. Returning from _remove_flows.", port_id)
                return
            sec_br.delete_flows(table=ovsvapp_const.SG_LEARN_TABLE_ID,
                                dl_src=port['mac_address'],
                                vlan_tci="0x%04x/0x0fff" % vlan)
            sec_br.delete_flows(table=ovsvapp_const.SG_LEARN_TABLE_ID,
                                dl_dst=port['mac_address'],
                                vlan_tci="0x%04x/0x0fff" % vlan)
            sec_br.delete_flows(table=ovsvapp_const.SG_DEFAULT_TABLE_ID,
                                dl_src=port['mac_address'],
                                vlan_tci="0x%04x/0x0fff" % vlan)
            if del_provider_rules:
                sec_br.delete_flows(table=ovsvapp_const.SG_DEFAULT_TABLE_ID,
                                    dl_dst=port['mac_address'],
                                    vlan_tci="0x%04x/0x0fff" % vlan)
                sec_br.delete_flows(table=ovsvapp_const.SG_EGRESS_TABLE_ID,
                                    dl_src=port['mac_address'],
                                    vlan_tci="0x%04x/0x0fff" % vlan)
        except Exception:
            LOG.exception(_LE("Unable to remove flows %s."), port['id'])

    def clean_port_filters(self, ports, remove_port=False):
        """Method to remove OVS rules for an existing VM port."""
        LOG.debug("OVSF Cleaning filters for  %s ports.", len(ports))
        if not ports:
            return
        with self.sg_br.deferred() as deferred_sec_br:
            for port_id in ports:
                try:
                    if not self.filtered_ports.get(port_id):
                        LOG.debug("Attempted to remove port filter "
                                  "which is not in filtered %s.", port_id)
                        continue
                    if not remove_port:
                        self._remove_flows(deferred_sec_br, port_id)
                    else:
                        self._remove_flows(deferred_sec_br, port_id, True)
                        self.provider_port_cache.remove(port_id)
                        self.filtered_ports.pop(port_id, None)
                except Exception:
                    LOG.exception(_LE("Unable to delete flows for"
                                      " %s."), port_id)

    def update_port_filter(self, port):
        """Method to update OVS rules for an existing VM port."""
        LOG.debug("OVSF Updating port: %s filter.", port['id'])
        if port['id'] not in self.filtered_ports:
            LOG.warning(_LW("Attempted to update port filter which is not "
                            "filtered %s."), port['id'])
            return
        port_cookie = self.get_cookie(port['id'])
        port_provider_cookie = self.get_cookie('pr' + port['id'])
        try:
            with self.sg_br.deferred(full_ordered=True, order=(
                'del', 'mod', 'add')) as deferred_br:
                if port['id'] not in self.provider_port_cache:
                    self._remove_flows(deferred_br, port['id'], True)
                    self._add_flows(deferred_br, port,
                                    port_provider_cookie, True)
                    self.provider_port_cache.add(port['id'])
                else:
                    self._remove_flows(deferred_br, port['id'])
                self._setup_aap_flows(deferred_br, port)
                self._add_flows(deferred_br, port, port_cookie)
            self.filtered_ports[port['id']] = self._get_compact_port(port)
        except Exception:
            LOG.exception(_LE("Unable to update flows for %s."), port['id'])

    def filter_defer_apply_on(self):
        if not self._defer_apply:
            self._defer_apply = True

    def filter_defer_apply_off(self):
        if self._defer_apply:
            self._defer_apply = False

    def get_cookie(self, port_id):
        return ("0x%x" % (hash(port_id) & 0xffffffffffffffff))

    def remove_stale_port_flows(self, port_id, mac_address, vlan):
        """Remove all flows for a port."""

        LOG.debug("OVSF Removing flows for stale port: %s.", port_id)
        with self.sg_br.deferred() as deferred_sec_br:
            try:
                deferred_sec_br.delete_flows(cookie="%s/-1" %
                                             self.get_cookie(port_id))
                deferred_sec_br.delete_flows(cookie="%s/-1" %
                                             self.get_cookie('pr' + port_id))
                deferred_sec_br.delete_flows(
                    table=ovsvapp_const.SG_LEARN_TABLE_ID,
                    dl_src=mac_address,
                    dl_vlan=vlan)
                deferred_sec_br.delete_flows(
                    table=ovsvapp_const.SG_LEARN_TABLE_ID,
                    dl_dst=mac_address,
                    dl_vlan=vlan)
                deferred_sec_br.delete_flows(
                    table=ovsvapp_const.SG_LEARN_TABLE_ID,
                    dl_src=mac_address,
                    dl_vlan=vlan)
                deferred_sec_br.delete_flows(
                    table=ovsvapp_const.SG_LEARN_TABLE_ID,
                    dl_dst=mac_address,
                    dl_vlan=vlan)
                deferred_sec_br.delete_flows(
                    table=ovsvapp_const.SG_LEARN_TABLE_ID,
                    dl_src=mac_address,
                    dl_vlan=vlan)
            except Exception:
                LOG.exception(_LE("OVSF unable to remove flows for port: "
                                  "%s."), port_id)
