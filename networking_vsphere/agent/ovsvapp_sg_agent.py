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

import eventlet
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_utils import importutils
from pprint import pformat

import netaddr
import six
import threading
import time

from networking_vsphere._i18n import _LI, _LE
from networking_vsphere.common import constants as ovsvapp_const

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import rpc as n_rpc

LOG = log.getLogger(__name__)

ovsvapplock = threading.RLock()
sg_datalock = threading.RLock()

ADD_KEY = 'add'
DEL_KEY = 'del'
OVSVAPP_ID = 'OVSVAPP-'
DELETE_TIMEOUT_INTERVAL = 600
OVSVAPP_DEBUG_ENABLED = False


class OVSvAppSecurityGroupAgent(sg_rpc.SecurityGroupAgentRpc):
    """OVSvApp derived class from OVSSecurityGroupAgent

    This class is to override the default behavior of some methods.
    """
    def __init__(self, context, ovsvapp_sg_rpc, defer_apply):
        self.context = context
        self.ovsvapp_sg_rpc = ovsvapp_sg_rpc
        self.sgid_rules_dict = {}
        self.sgid_remote_rules_dict = {}
        self.sgid_devices_dict = {}
        self.device_sgids_dict = {}
        self.pending_rules_dict = {}
        self.deleted_devices_dict = {}
        self.init_firewall(defer_apply)
        self.t_pool = eventlet.GreenPool(ovsvapp_const.THREAD_POOL_SIZE)
        LOG.info(_LI("OVSvAppSecurityGroupAgent initialized."))

    @property
    def use_enhanced_rpc(self):
        if self._use_enhanced_rpc is None:
            self._use_enhanced_rpc = False
        return self._use_enhanced_rpc

    def init_firewall(self, defer_refresh_firewall=False):
        firewall_driver = cfg.CONF.SECURITYGROUP.ovsvapp_firewall_driver
        LOG.debug("Init firewall settings (driver=%s).", firewall_driver)
        if not firewall_driver:
            firewall_driver = 'neutron.agent.firewall.NoopFirewallDriver'
        self.firewall = importutils.import_object(firewall_driver)
        # The following flag will be set to true if port filter must not be
        # applied as soon as a rule or membership notification is received.
        self.defer_refresh_firewall = defer_refresh_firewall
        # Stores devices for which firewall should be refreshed when
        # deferred refresh is enabled.
        self.devices_to_refilter = set()
        # Flag raised when a global refresh is needed.
        self.global_refresh_firewall = False
        self._use_enhanced_rpc = None

    def security_groups_member_updated(self, security_groups):
        pass

    def sg_provider_updated(self, net_id):
        devices = []
        for device in self.firewall.ports.values():
            if net_id == device.get('network_id'):
                devices.append(device['device'])
                self._remove_device_sg_mapping(device['device'], False)
        if devices:
            LOG.info(_LI("Adding %s devices to the list of devices "
                         "for which firewall needs to be refreshed"),
                     len(devices))
            ovsvapplock.acquire()
            self.devices_to_refilter |= set(devices)
            self.firewall.remove_ports_from_provider_cache(devices)
            ovsvapplock.release()

    def add_devices_to_filter(self, devices):
        if not devices:
            return
        self.firewall.add_ports_to_filter(devices)

    def ovsvapp_sg_update(self, port_with_rules):
        for port_id in port_with_rules:
            if port_id in self.firewall.ports:
                self._update_device_port_sg_map(port_with_rules, port_id)
                self.firewall.prepare_port_filter(port_with_rules[port_id])
        LOG.debug("Port Cache 01: %s",
                  port_with_rules[port_id])

    def _expand_rules(self, rules):
        LOG.debug("_expand_rules: %s", rules)
        rules_list = []
        for rule in rules:
            remote = rule['remote_group_id']
            devices = self.sgid_devices_dict.get(remote)
            if devices is not None:
                for device in devices:
                    new_rule = rule.copy()
                    new_rule.pop('id')
                    direction = rule.get('direction')
                    direction_ip_prefix = (
                        ovsvapp_const.DIRECTION_IP_PREFIX[direction])
                    new_rule[direction_ip_prefix] = str(
                        netaddr.IPNetwork(device).cidr)
                    rules_list.append(new_rule)
        return rules_list

    def _expand_rule_for_device(self, rule, device):
        LOG.debug("_expand_rules_for_device: %s %s", device, rule)
        if device is not None:
            version = netaddr.IPNetwork(device).version
            ethertype = 'IPv%s' % version
            if rule['ethertype'] != ethertype:
                return
            new_rule = rule.copy()
            new_rule.pop('id')
            direction = rule.get('direction')
            direction_ip_prefix = (
                ovsvapp_const.DIRECTION_IP_PREFIX[direction])
            new_rule[direction_ip_prefix] = str(
                netaddr.IPNetwork(device).cidr)
            LOG.debug("_expand_rules_for_device returns: %s", new_rule)
            return new_rule

    def expand_sg_rules(self, ports_info):
        ips = ports_info.get('member_ips')
        ports = ports_info.get('ports')
        for port in ports.values():
            updated_rule = []
            for rule in port.get('sg_normal_rules'):
                remote_group_id = rule.get('remote_group_id')
                direction = rule.get('direction')
                direction_ip_prefix = (
                    ovsvapp_const.DIRECTION_IP_PREFIX[direction])
                if not remote_group_id:
                    updated_rule.append(rule)
                    continue

                port['security_group_source_groups'].append(remote_group_id)
                base_rule = rule
                for ip in ips[remote_group_id]:
                    if ip in port.get('fixed_ips', []):
                        continue
                    ip_rule = base_rule.copy()
                    ip_rule['id'] = OVSVAPP_ID + ip
                    version = netaddr.IPNetwork(ip).version
                    ethertype = 'IPv%s' % version
                    if base_rule['ethertype'] != ethertype:
                        continue
                    ip_rule[direction_ip_prefix] = str(
                        netaddr.IPNetwork(ip).cidr)
                    updated_rule.append(ip_rule)
            port['sg_provider_rules'] = port['security_group_rules']
            port['security_group_rules'] = updated_rule
        return ports

    def _fetch_and_apply_rules(self, dev_ids, update=False):
        ovsvapplock.acquire()
        #  This will help us prevent duplicate processing of same port
        #  when we get back to back updates for same SG or Network.
        self.devices_to_refilter = self.devices_to_refilter - set(dev_ids)
        ovsvapplock.release()
        sg_info = self.ovsvapp_sg_rpc.security_group_info_for_esx_devices(
            self.context, dev_ids)
        time.sleep(0)
        LOG.debug("Successfully serviced security_group_info_for_esx_devices "
                  "RPC for %s.", dev_ids)
        ports = sg_info.get('ports')
        for port_id in ports:
            if port_id in dev_ids:
                port_info = {'member_ips': sg_info.get('member_ips'),
                             'ports': {port_id: ports[port_id]}}
                port_sg_rules = self.expand_sg_rules(port_info)
                if len(port_sg_rules.get(port_id).get(
                       'sg_provider_rules')) == 0:
                    LOG.info(_LI("Missing Provider Rules for port %s"),
                             port_id)
                    self.devices_to_refilter.add(port_id)
                    return

                if self.deleted_devices_dict.get(port_id) is None:
                    self._update_device_port_sg_map(port_sg_rules,
                                                    port_id, update)
                    LOG.debug("Port Cache: %s",
                              port_sg_rules[port_id])
                    if len(port_sg_rules[port_id]['security_group_rules']) > 0 \
                        or \
                       port_sg_rules[port_id].get('security_group_rules_deleted') \
                       is not None:
                        LOG.info(_LI("Applying Changed Rules for Port %s"),
                                 port_id)
                        self.firewall.update_port_filter(
                            port_sg_rules[port_id]
                        )
                    else:
                        LOG.info(_LI("NO RULES CHANGED for Port %s"), port_id)

    def _process_port_set(self, devices, update=False):
        dev_list = list(devices)
        if len(dev_list) > ovsvapp_const.SG_RPC_BATCH_SIZE:
            sublists = ([dev_list[x:x + ovsvapp_const.SG_RPC_BATCH_SIZE]
                        for x in range(0, len(dev_list),
                                       ovsvapp_const.SG_RPC_BATCH_SIZE)])
        else:
            sublists = [dev_list]
        for dev_ids in sublists:
            self.t_pool.spawn_n(self._fetch_and_apply_rules, dev_ids, update)

    def _print_rules_cache(self, msg):
        if not OVSVAPP_DEBUG_ENABLED:
            return
        LOG.debug("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=")
        LOG.debug(msg)
        LOG.debug("sgid_devices_dict: %s", pformat(self.sgid_devices_dict))
        LOG.debug("device_sgids_dict: %s", pformat(self.device_sgids_dict))
        LOG.debug("sgid_rules_dict: %s", pformat(self.sgid_rules_dict))
        LOG.debug("sgid_remote_rules_dict: %s",
                  pformat(self.sgid_remote_rules_dict))
        LOG.debug("sgid_pending_rules_dict: %s",
                  pformat(self.pending_rules_dict))
        LOG.debug("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=")

    def _remove_device_sg_mapping(self, port_id, deleted=True):
        sg_datalock.acquire()
        try:
            LOG.debug("_remove_device_sg_mapping for port: %s", port_id)
            remove_list = []
            deleted_dev = None
            deleted_dev_group = None
            ip = None
            if port_id is not None:
                deleted_dev, deleted_dev_group = \
                    self._remove_from_sgid_device_map(
                        deleted_dev, deleted_dev_group, ip, port_id,
                        remove_list)
            self._remove_device_remote_rules(deleted_dev,
                                             deleted_dev_group)
            self._remove_device_pending_rules(deleted_dev, deleted_dev_group)
            for group in remove_list:
                self.sgid_devices_dict.pop(group)
                self.sgid_rules_dict.pop(group)
                self.sgid_remote_rules_dict.pop(group)
                dev_groups = self.device_sgids_dict.get(port_id)
                if dev_groups is not None:
                    if group in dev_groups:
                        dev_groups.remove(group)
                    if len(dev_groups) == 0:
                        self.device_sgids_dict.pop(port_id)
            if deleted:
                self.deleted_devices_dict[port_id] = time.time()
            self._print_rules_cache("After _remove_device_sg_mapping")
        finally:
            sg_datalock.release()

    def _remove_device_pending_rules(self, deleted_dev, deleted_dev_group):
        for port, rules in six.iteritems(self.pending_rules_dict):
            lst = []
            prules = self.pending_rules_dict.get(port)
            if prules[ADD_KEY] is not None:
                for rule in prules[ADD_KEY]:
                    remote_grp_id = rule.get('remote_group_id')
                    if remote_grp_id is not None:
                        if remote_grp_id == deleted_dev_group:
                            if rule.get('source_ip_prefix') is not None:
                                if deleted_dev in rule['source_ip_prefix']:
                                    lst.append(rule)
                if len(lst) > 0:
                    for r in lst:
                        prules[ADD_KEY].remove(r)

    def _remove_device_remote_rules(self, deleted_dev,
                                    deleted_dev_group):
        for ngroup, rules in six.iteritems(self.sgid_remote_rules_dict):
            if ngroup == deleted_dev_group:
                continue
            removed_rules = []
            for rule in rules:
                if rule['remote_group_id'] == deleted_dev_group:
                    ex_rule = self._expand_rule_for_device(rule,
                                                           deleted_dev)
                    if ex_rule is not None:
                        removed_rules.append(ex_rule)
            devs_list = self.sgid_devices_dict.get(ngroup)
            if devs_list is not None:
                for dev, ports_list in six.iteritems(devs_list):
                    for port_id in ports_list:
                        prules = self.pending_rules_dict.get(port_id)
                        if prules is None:
                            self.pending_rules_dict[port_id] = prules = {}
                            prules[ADD_KEY] = []
                            prules[DEL_KEY] = []
                        prules[DEL_KEY].extend(removed_rules)

    def _remove_from_sgid_device_map(self, deleted_dev, deleted_dev_group, ip,
                                     port_id, remove_list):
        for group, devices_dict in \
                six.iteritems(self.sgid_devices_dict):
            for ip, ports_list in six.iteritems(devices_dict):
                if port_id in ports_list:
                    deleted_dev = ip
                    deleted_dev_group = group
                    break
                else:
                    ip = None
            if ip is not None:
                if len(ports_list) == 1:
                    value = devices_dict.pop(ip, None)
                    if value is None:
                        LOG.info(_LI("KeyError for %s"), ip)
                        LOG.info(_LI("KeyError devices_dict %(ddict)s,"
                                     "%(deleted_dev)s"),
                                 {'ddict': devices_dict,
                                  'deleted_dev': deleted_dev})
                else:
                    ports_list.remove(port_id)
            if len(devices_dict) == 0:
                remove_list.append(group)
            dev_groups = self.device_sgids_dict.get(port_id)
            if dev_groups is not None:
                if deleted_dev_group in dev_groups:
                    dev_groups.remove(deleted_dev_group)
                if len(dev_groups) == 0:
                    self.device_sgids_dict.pop(port_id)
            if self.pending_rules_dict.get(port_id) is not None:
                self.pending_rules_dict.pop(port_id)
                LOG.debug("Deleted device ip and group are: %s, %s",
                          deleted_dev, deleted_dev_group)
        return deleted_dev, deleted_dev_group

    def _get_ip_rules(self, sgroup_id, device_ip):
        LOG.debug("_get_ip_rules: %s, %s", sgroup_id, device_ip)
        sgid_rules = self.sgid_remote_rules_dict[sgroup_id]
        updated_rules = []
        for rule in sgid_rules:
            remote_group_id = rule.get('remote_group_id')
            if not remote_group_id:
                continue
            direction = rule.get('direction')
            direction_ip_prefix = (
                ovsvapp_const.DIRECTION_IP_PREFIX[direction])
            base_rule = rule
            devices = self.sgid_devices_dict[sgroup_id]
            for device in devices:
                if device == device_ip:
                    ip_rule = base_rule.copy()
                    ip_rule['id'] = None
                    version = netaddr.IPNetwork(device).version
                    ethertype = 'IPv%s' % version
                    if base_rule['ethertype'] != ethertype:
                        continue
                    ip_rule[direction_ip_prefix] = str(
                        netaddr.IPNetwork(device).cidr)
                    updated_rules.append(ip_rule)
        return updated_rules

    def _update_sgid_devices_dict(self, group, sg_devices, port_id):
        """Maintain map of device ip addresses to security group

        :param group: security group id.
        :param sg_devices: fixed ips of the device.
        :param port_id: device port id.

        :returns fixed ip of device or None if device ip already exists in map.
        """
        new_device = None
        if self.sgid_devices_dict.get(group) is None:
            self.sgid_devices_dict[group] = devices = {}
            dev_groups = self.device_sgids_dict.get(port_id)
            if dev_groups is None:
                self.device_sgids_dict[port_id] = dev_groups = []
            if group not in dev_groups:
                dev_groups.append(group)
            for device in sg_devices:
                if devices.get(device) is None:
                    devices[device] = set()
                devices[device].add(port_id)
                new_device = device
        else:
            devices = self.sgid_devices_dict[group]
            dev_groups = self.device_sgids_dict.get(port_id)
            if dev_groups is None:
                self.device_sgids_dict[port_id] = dev_groups = []
            if group not in dev_groups:
                dev_groups.append(group)
            for device in sg_devices:
                if devices.get(device) is None:
                    devices[device] = set()
                if port_id not in devices[device]:
                    devices[device].add(port_id)
                    new_device = device
        return new_device

    def _check_and_update_pending_rules(self, group, port_id, added_rules,
                                        deleted_rules, new_arules,
                                        new_drules, remote=False):
        """Check and update added and removed list from the pending rules.

        Check and update added and removed list from the pending rules which
        might be updated for this security group.

        :param group: name of security group.
        :param port_id:  port id.
        :param added_rules: added rules list.
        :param deleted_rules:  removed rules list.
        :param new_arules: new rules to be update to pending map.
        :param new_drules: new rules to be removed from pending map.
        :param remote: remote group flag.
        """

        LOG.debug("_check_and_update_pending_rules: %s %s", group, port_id)
        devices = self.sgid_devices_dict[group]

        # First we check for pending rules and update added and removed rule
        # lists to apply on the security bridge
        skip = self._check_for_pending_rules(added_rules, deleted_rules,
                                             devices, port_id)
        # Now we check if new rules have to be added to pending list
        if not skip:
            self._update_pending_rules(devices, new_arules, new_drules,
                                       port_id, remote, skip)
        self._print_rules_cache("_check_and_update_pending_rules")

    def _update_pending_rules(self, devices, new_arules, new_drules, port_id,
                              remote, skip):
        for device in devices:
            if port_id not in devices[device]:
                if skip:
                    continue
                pending_ports = devices[device]
                prules = None
                if pending_ports is not None:
                    for pp in pending_ports:
                        prules = self.pending_rules_dict.get(pp)
                        if prules is None:
                            self.pending_rules_dict[pp] = prules = {}
                            prules[ADD_KEY] = []
                            prules[DEL_KEY] = []
                        if not remote:
                            for r in new_arules:
                                if r not in prules[ADD_KEY]:
                                    prules[ADD_KEY].append(r)
                            for r in new_drules:
                                if r not in prules[DEL_KEY]:
                                    prules[DEL_KEY].append(r)
                        else:
                            if len(new_arules) > 0:
                                prules[ADD_KEY].extend(
                                    self._expand_rules(new_arules))
                            if len(new_drules) > 0:
                                prules[DEL_KEY].extend(
                                    self._expand_rules(new_drules))

    def _check_for_pending_rules(self, added_rules, deleted_rules, devices,
                                 port_id):
        skip = False
        for device in devices:
            if port_id in devices[device]:
                prules = self.pending_rules_dict.get(port_id)
                if prules is not None:
                    if len(prules[ADD_KEY]) > 0:
                        # New rules to be added
                        LOG.debug("Pending rules will be processed(add)")
                        LOG.debug("02.Fol. rules are added for port: %s %s",
                                  port_id, prules[ADD_KEY])
                        for r in prules[ADD_KEY]:
                            if r not in added_rules:
                                added_rules.append(r)
                            else:
                                skip = True
                        # clear pending rules map after adding to list
                        prules[ADD_KEY] = []
                    if len(prules[DEL_KEY]) > 0:
                        LOG.debug("Pending rules will be processed(delete)")
                        LOG.debug("02.Fol. rules are deleted for port: %s %s",
                                  port_id, prules[DEL_KEY])
                        for r in prules[DEL_KEY]:
                            if r not in deleted_rules:
                                deleted_rules.append(r)
                            else:
                                skip = True
                        prules[DEL_KEY] = []
                break
        return skip

    def _update_sgid_rules_map(self, group, sg_rules, sg_normal_rules):
        LOG.debug("_update_sgid_rules_map: NEW SG %s", group)
        self.sgid_rules_dict[group] = {}
        self.sgid_remote_rules_dict[group] = []
        for rule in sg_rules:
            # Ignore rules to other hosts in same group
            if OVSVAPP_ID in rule['id']:
                continue
            sgid = rule['security_group_id']
            if group == sgid:
                self.sgid_rules_dict[sgid][rule['id']] = rule
        for rule in sg_normal_rules:
            if rule.get('remote_group_id') is not None:
                sgid = rule['security_group_id']
                if group == sgid:
                    self.sgid_remote_rules_dict[sgid].append(rule)

    def _check_and_process_rule(self, group, rule, new_rules,
                                mapped_rules, rules_map):
        """Process security group rule.

        Identify if it is new peer rule, or new sg rule or new remote
        sg member rule.

        :param group: Name of security group.
        :param rule:  Rule being processed
        :param new_rules: New rules list
        :param mapped_rules: Existing rules in map
        :param rules_map: New rules map
        :return: update_pending flag to indicate if other devices need
                 same rule update.

        Once we add rule to map,
        subsequent processing for other devices in same security group will
        find the rule already exists and we have to check and apply pending
        rules for the device in such cases.
        """
        update_pending = False
        if OVSVAPP_ID in rule['id']:
            ip_device = rule['id'].replace(OVSVAPP_ID, '')
            sgid = rule['security_group_id']
            srgid = rule['remote_group_id']
            if sgid == group and group == srgid:
                devices = self.sgid_devices_dict[group]
                if ip_device not in devices:
                    LOG.debug("_check_and_process_rule \
                        - New member added to our group: %s,\
                        %s", group, rule)
                    new_rules.append(rule)
            elif sgid == group and srgid != group:
                devices = self.sgid_devices_dict.get(srgid)
                if devices is not None:
                    if ip_device not in devices:
                        LOG.debug("_check_and_process_rule \
                            - New remote group member added:\
                            %s", ip_device)
                        new_rules.append(rule)
                        update_pending = True
                else:
                        LOG.debug("_check_and_process_rule\
                            New First remote group member \
                            added: %s", ip_device)
                        new_rules.append(rule)
        else:
            sgid = rule['security_group_id']
            if group == sgid:
                if rule['id'] not in mapped_rules:
                    new_rules.append(rule)
                    LOG.debug("_check_and_process_rule - \
                    NEW RULE ADDED TO SG: %s,\
                    %s", group, rule)
                    update_pending = True
                else:
                    mapped_rules.pop(rule['id'])
                    rules_map[rule['id']] = rule
        return update_pending

    def _is_groups_deleted(self, groups, port_id, deleted_groups):
        """check if any groups are removed for the port.

        :param groups: list of groups received in refresh
        :param port_id: port's id
        :param deleted_groups: return list containing deleted groups
        :return: True if groups deleted
        """
        deleted = False
        sgroups = []
        dev_groups = self.device_sgids_dict.get(port_id)
        if dev_groups is not None:
            for group in groups:
                if group in dev_groups:
                    sgroups.append(group)
                    dev_groups.remove(group)
            if len(dev_groups) > 0:
                deleted = True
                deleted_groups.extend(dev_groups)
            dev_groups.extend(sgroups)
        return deleted

    def _process_remote_group_rules(self, group, port_id, sg_normal_rules,
                                    added_rules, deleted_rules):
        """Check for remote group rule changes and update map accordingly.

        :param group: group name
        :param port_id: port id
        :param sg_normal_rules: sg_normal_rules for port
        :param added_rules: added rules list
        :param deleted_rules: deleted rules list
        :return: None
        """
        new_remote_rules = []
        remote_rules = []
        remote_list = []
        changed = False
        for rule in sg_normal_rules:
            rgroup = rule.get('remote_group_id')
            if rgroup is None:
                continue
            sgid = rule['security_group_id']
            if group == sgid:
                changed = True
                remote_rules = \
                    self.sgid_remote_rules_dict[sgid]
                if remote_rules is not None:
                    if rule not in remote_rules:
                        new_remote_rules.append(rule)
                    else:
                        remote_rules.remove(rule)
                        remote_list.append(rule)
        if len(new_remote_rules) > 0:
            LOG.debug("_process_remote_group_rules:\
                NEW REMOTE SG RULES ADDED:\
                %s", new_remote_rules)
            added_rules.extend(
                self._expand_rules(new_remote_rules)
            )
        if len(remote_rules) > 0:
            LOG.debug("_process_remote_group_rules:\
                REMOTE SG RULES REMOVED: \
                %s", remote_rules)
            deleted_rules.extend(self._expand_rules(remote_rules))
        if not changed and len(remote_rules) == 0:
            remote_rules = self.sgid_remote_rules_dict[group]
            if remote_rules is not None and \
                len(remote_rules) == 1:
                    deleted_rules.extend(self._expand_rules(remote_rules))
        self._check_and_update_pending_rules(
            group, port_id, added_rules, deleted_rules,
            new_remote_rules, remote_rules, True
        )
        remote_list.extend(new_remote_rules)
        self.sgid_remote_rules_dict[group] = remote_list

    def _has_remote_rules(self, sgroups, port_id, sg_rules):
        try:
            for group in sgroups:
                for rule in sg_rules:
                    if OVSVAPP_ID in rule['id']:
                        remote_g = rule.get('remote_group_id')
                        if remote_g is not None and remote_g != group:
                            return True
            for group in sgroups:
                remote_rules = self.sgid_remote_rules_dict.get(group)
# case when incoming dict has no remote rules but cache does(i.e rules removed)
                if remote_rules is not None and \
                    len(remote_rules) > 0:
                        for rule in remote_rules:
                            remote_g = rule.get('remote_group_id')
                            if remote_g is not None and remote_g != group:
                                return True
        except Exception as e:
            LOG.error(_LE("Exception in _has_remote_rules: %s"), e)
            # In case of exceptions better to clear and reapply rules to the
            # security bridge so return True.
            return True
        return False

    def _update_device_port_sg_map(self, port_info, port_id, update=False):
        sg_datalock.acquire()
        try:
            LOG.info(_LI("_update_device_port_sg_map: %(update)s"
                         " %(port_id)s"),
                     {'update': update, 'port_id': port_id})
            self._print_rules_cache("Before: _update_device_port_sg_map")
            added_rules = []
            deleted_rules = []
            sgroups = port_info[port_id]['security_groups']
            sg_rules = port_info[port_id]['security_group_rules']
            sg_normal_rules = port_info[port_id]['sg_normal_rules']
            sg_devices = port_info[port_id]['fixed_ips']
            if len(sgroups) == 0 and len(sg_rules) == 0:
                LOG.info(_LI("_update_device_port_sg_map:"
                         "Security groups cleared for device."))
                self._remove_devices_filter(port_id, False)
                return
            del_groups = []
            if self._is_groups_deleted(sgroups, port_id, del_groups):
                LOG.info(_LI("_update_device_port_sg_map:"
                         "Groups removed from port: %s"), del_groups)
                for group in del_groups:
                    self._remove_devices_filter(port_id, False)
            if self._has_remote_rules(sgroups, port_id, sg_rules):
                self._remove_devices_filter(port_id, False)
            for group in sgroups:
                new_rules = []
                rules_map = {}
                new_device = self._update_sgid_devices_dict(
                    group, sg_devices, port_id)
                if new_device is not None:
                    LOG.debug("_update_device_port_sg_map: NEW DEVICE: %s",
                              new_device)
                    # This is a new device, all the rules have to be
                    # applied to security bridge
                    added_rules.extend(sg_rules)
                    update = False
                # check and update security group to rules map
                if self.sgid_rules_dict.get(group) is None:
                    self._update_sgid_rules_map(group, sg_rules,
                                                sg_normal_rules)
                else:
                    # Only process existing devices
                    if new_device is not None:
                        continue
                    update_pending = False
                    rules = self.sgid_rules_dict.get(group)
                    for rule in sg_rules:
                        if self._check_and_process_rule(
                            group, rule, new_rules, rules, rules_map):
                            update_pending = True
                    if len(new_rules) > 0:
                        added_rules.extend(new_rules)
                        LOG.debug("01.Fol. rules are added for port: %s %s",
                                  port_id, new_rules)
                    if len(rules) > 0:
                        LOG.debug("01.Fol. rules are deleted for port: %s %s",
                                  port_id, rules)
                        deleted_rules.extend(rules.values())
                        update_pending = True
                    # add new rules to map
                    for rule in new_rules:
                        if OVSVAPP_ID not in rule['id']:
                            rules_map[rule['id']] = rule
                    self.sgid_rules_dict[group] = rules_map

                    if update_pending:
                        self._check_and_update_pending_rules(
                            group, port_id, added_rules, deleted_rules,
                            new_rules, rules.values()
                        )
                    if len(rules) > 0 or len(new_rules) > 0:
                        LOG.debug("Foll ports need to be updated with above \
                            rules: %s", self.pending_rules_dict)

                # Now process remote group rules
                self._process_remote_group_rules(group, port_id,
                                                 sg_normal_rules,
                                                 added_rules,
                                                 deleted_rules)

            LOG.debug("_update_device_port_sg_map - \
                Added Rules %s", added_rules)
            LOG.debug("_update_device_port_sg_map - \
                Removed Rules %s", deleted_rules)
            self._print_rules_cache("After: _update_device_port_sg_map")
            t1 = time.time()
            # We maintain deleted devices dict to prevent spurious re-addition
            # of device as new device after it is deleted (may be on the
            # refresh list and will get added back without this check)
            del_ports = []
            for port, ptime in six.iteritems(self.deleted_devices_dict):
                if int(t1 - ptime) > DELETE_TIMEOUT_INTERVAL:
                    del_ports.append(port)
            for port in del_ports:
                self.deleted_devices_dict.pop(port)
            port_info[port_id]['security_group_rules'] = added_rules
            if len(deleted_rules) > 0:
                port_info[port_id]['security_group_rules_deleted'] = \
                    deleted_rules
        finally:
            sg_datalock.release()

    def remove_devices_from_sg_map(self, devices):
        sg_datalock.acquire()
        try:
            for group, sg_devices in six.iteritems(self.sgid_devices_dict):
                for device in devices:
                    deleted_dev = None
                    if device in sg_devices.values():
                        for dev, port in six.iteritems(sg_devices):
                            if device == port:
                                deleted_dev = dev
                                break
                    if deleted_dev:
                        sg_devices.pop(deleted_dev)
        finally:
            sg_datalock.release()

    def _remove_devices_filter(self, device_id, deleted):
        if not device_id:
            return
        self.firewall.clean_port_filters([device_id])
        self._remove_device_sg_mapping(device_id, deleted)

    def remove_devices_filter(self, device_id):
        if not device_id:
            return
        self.firewall.clean_port_filters([device_id], True)
        self._remove_device_sg_mapping(device_id)

    def prepare_firewall(self, device_ids):
        """Puts in new rules for input port_ids.

        This routine puts in new rules for the
        input ports shippped as device_ids.

        :param device_ids: set of port_ids for which firewall rules
        need to be created.
        """
        LOG.info(_LI("Prepare firewall rules for %s ports."), len(device_ids))
        self._process_port_set(device_ids)

    def refresh_firewall(self, device_ids=None):
        """Removes all rules for input port_ids and puts in new rules for them.

        This routine erases all rules and puts in new rules for the
        input ports shippped as device_ids.

        :param device_ids: set of port_ids for which firewall rules
        need to be refreshed.
        """
        if not device_ids:
            device_ids = self.firewall.ports.keys()
            if not device_ids:
                LOG.info(_LI("No ports here to refresh firewall."))
                return
        LOG.info(_LI("Refresh firewall rules for %s ports."), len(device_ids))
        self._process_port_set(set(device_ids), True)

    def refresh_port_filters(self, own_devices, other_devices):
        """Update port filters for devices.

        This routine refreshes firewall rules when devices have been
        updated, or when there are changes in security group membership
        or rules.

        :param own_devices: set containing identifiers for devices
        belonging to this ESX host.
        :param other_devices: set containing identifiers for
        devices belonging to other ESX hosts within the Cluster.
        """
        # These data structures are cleared here in order to avoid
        # losing updates occurring during firewall refresh.
        devices_to_refilter = self.devices_to_refilter
        global_refresh_firewall = self.global_refresh_firewall
        self.devices_to_refilter = set()
        self.global_refresh_firewall = False
        LOG.info(_LI("Going to refresh for devices: %s."),
                 len(devices_to_refilter))
        if global_refresh_firewall:
            LOG.info(_LI("Refreshing firewall for all filtered devices."))
#            self.firewall.clean_port_filters(other_devices)
#            self.remove_devices_from_sg_map(other_devices)
            self.refresh_firewall()
        else:
            own_devices = (own_devices & devices_to_refilter)
            other_devices = (other_devices & devices_to_refilter)
#            self.firewall.clean_port_filters(other_devices)
#            self.remove_devices_from_sg_map(other_devices)
            if own_devices:
                LOG.info(_LI("Refreshing firewall for %d own devices."),
                         len(own_devices))
                self.refresh_firewall(own_devices)
            if other_devices:
                LOG.info(_LI("Refreshing firewall for %d other devices."),
                         len(other_devices))
                self.prepare_firewall(other_devices)
        LOG.info(_LI("Finished refresh for devices: %s."),
                 len(devices_to_refilter))


class OVSvAppSecurityGroupServerRpcApi(object):
    """RPC client for security group methods in the plugin."""

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def security_group_info_for_esx_devices(self, context, devices):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'security_group_info_for_esx_devices',
                          devices=devices)
