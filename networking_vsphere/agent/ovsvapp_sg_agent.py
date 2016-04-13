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

import netaddr
import threading
import time

from networking_vsphere._i18n import _LI
from networking_vsphere.common import constants as ovsvapp_const

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import rpc as n_rpc

LOG = log.getLogger(__name__)

ovsvapplock = threading.RLock()


class OVSvAppSecurityGroupAgent(sg_rpc.SecurityGroupAgentRpc):
    """OVSvApp derived class from OVSSecurityGroupAgent

    This class is to override the default behavior of some methods.
    """
    def __init__(self, context, ovsvapp_sg_rpc, defer_apply):
        self.context = context
        self.ovsvapp_sg_rpc = ovsvapp_sg_rpc
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

    def security_groups_provider_updated(self, devices_to_update):
        LOG.info(_LI("Ignoring default security_groups_provider_updated RPC."))

    def sg_provider_updated(self, net_id):
        devices = []
        for device in self.firewall.ports.values():
            if net_id == device.get('network_id'):
                devices.append(device['device'])
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
                self.firewall.prepare_port_filter(port_with_rules[port_id])

    def remove_devices_filter(self, device_id):
        if not device_id:
            return
        self.firewall.clean_port_filters([device_id], True)

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
                if update:
                    self.firewall.update_port_filter(port_sg_rules[port_id])
                else:
                    self.firewall.prepare_port_filter(port_sg_rules[port_id])

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
            self.firewall.clean_port_filters(other_devices)
            self.refresh_firewall()
        else:
            own_devices = (own_devices & devices_to_refilter)
            other_devices = (other_devices & devices_to_refilter)
            self.firewall.clean_port_filters(other_devices)
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
