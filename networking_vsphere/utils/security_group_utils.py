# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
import six

from neutron.i18n import _LI, _LW
from oslo_log import log
from oslo_vmware import exceptions as vmware_exceptions

from networking_vsphere.common import constants as dvs_const
from networking_vsphere.common import exceptions
from networking_vsphere.utils import dvs_util

LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class TrafficRuleBuilder(object):
    action = 'ns0:DvsAcceptNetworkRuleAction'
    direction = 'both'
    reverse_class = None
    _backward_port_range = (None, None)
    _port_range = (None, None)

    def __init__(self, spec_factory, ethertype, protocol, name=None):
        self.factory = spec_factory

        self.rule = self.factory.create('ns0:DvsTrafficRule')
        self.rule.action = self.factory.create(self.action)

        self.ip_qualifier = self.factory.create(
            'ns0:DvsIpNetworkRuleQualifier'
        )
        self.ethertype = ethertype
        if ethertype:
            any_ip = '0.0.0.0/0' if ethertype == 'IPv4' else '::/0'
            self.ip_qualifier.sourceAddress = self._cidr_spec(any_ip)
            self.ip_qualifier.destinationAddress = self._cidr_spec(any_ip)

        self.protocol = protocol
        if protocol:
            int_exp = self.factory.create('ns0:IntExpression')
            int_exp.value = dvs_const.PROTOCOL.get(protocol, protocol)
            int_exp.negate = 'false'
            self.ip_qualifier.protocol = int_exp

        self.name = name

    def reverse(self, cidr_bool):
        """Returns reversed rule"""
        name = 'reversed' + ' ' + (self.name or '')
        rule = self.reverse_class(self.factory, self.ethertype,
                                  self.protocol, name=name.strip())
        if cidr_bool:
            rule.cidr = self.cidr
        else:
            rule.cidr = '0.0.0.0/0'
        rule.port_range = self.backward_port_range
        rule.backward_port_range = self.port_range
        return rule

    def build(self, sequence):
        self.rule.qualifier = [self.ip_qualifier]
        self.rule.direction = self.direction
        self.rule.sequence = sequence
        self.name = str(sequence) + '. ' + (self.name or '')
        self.name = self.name.strip()
        self.rule.description = self.name.strip()
        return self.rule

    @property
    def port_range(self):
        return self._port_range

    @property
    def backward_port_range(self):
        return self._backward_port_range

    @property
    def cidr(self):
        return self._cidr

    def _port_range_spec(self, begin, end):
        if begin == end:
            result = self.factory.create('ns0:DvsSingleIpPort')
            result.portNumber = begin
        else:
            result = self.factory.create('ns0:DvsIpPortRange')
            result.startPortNumber = begin
            result.endPortNumber = end
        return result

    def _cidr_spec(self, cidr):
        try:
            ip, mask = cidr.split('/')
        except ValueError:
            ip = cidr
            mask = '32'
        result = self.factory.create('ns0:IpRange')
        result.addressPrefix = ip
        result.prefixLength = mask
        return result

    def _has_port(self, min_port):
        if min_port:
            if self.protocol == 'icmp':
                LOG.info(_LI('Vmware dvs driver does not support '
                             '"type" and "code" for ICMP protocol.'))
                return False
            else:
                return True
        else:
            return False


class IngressRule(TrafficRuleBuilder):
    direction = 'incomingPackets'

    def __init__(self, spec_factory, ethertype, protocol, name=None):
        super(IngressRule, self).__init__(
            spec_factory, ethertype, protocol, name)
        self.reverse_class = EgressRule

    @TrafficRuleBuilder.port_range.setter
    def port_range(self, range_):
        begin, end = self._port_range = range_
        if begin:
            self.ip_qualifier.destinationIpPort = self._port_range_spec(begin,
                                                                        end)

    @TrafficRuleBuilder.backward_port_range.setter
    def backward_port_range(self, range_):
        begin, end = self._backward_port_range = range_
        if begin:
            self.ip_qualifier.sourceIpPort = self._port_range_spec(begin, end)

    @TrafficRuleBuilder.cidr.setter
    def cidr(self, cidr):
        self._cidr = cidr
        if cidr:
            self.ip_qualifier.sourceAddress = self._cidr_spec(cidr)


class EgressRule(TrafficRuleBuilder):
    direction = 'outgoingPackets'

    def __init__(self, spec_factory, ethertype, protocol, name=None):
        super(EgressRule, self).__init__(
            spec_factory, ethertype, protocol, name)
        self.reverse_class = IngressRule

    @TrafficRuleBuilder.port_range.setter
    def port_range(self, range_):
        begin, end = self._port_range = range_
        if begin:
            self.ip_qualifier.destinationIpPort = self._port_range_spec(begin,
                                                                        end)

    @TrafficRuleBuilder.backward_port_range.setter
    def backward_port_range(self, range_):
        begin, end = self._backward_port_range = range_
        if begin:
            self.ip_qualifier.sourceIpPort = self._port_range_spec(begin, end)

    @TrafficRuleBuilder.cidr.setter
    def cidr(self, cidr):
        self._cidr = cidr
        if cidr:
            self.ip_qualifier.destinationAddress = self._cidr_spec(cidr)


class DropAllRule(TrafficRuleBuilder):
    action = 'ns0:DvsDropNetworkRuleAction'


@dvs_util.wrap_retry
def update_port_rules(dvs, ports):
    try:
        builder = dvs_util.SpecBuilder(dvs.connection.vim.client.factory)
        port_config_list = []
        for port in ports:
            try:
                if port['binding:vif_details'].get('dvs_port_key') is not None:
                    port_info = dvs._get_port_info_by_portkey(
                        port['binding:vif_details']['dvs_port_key'])
                else:
                    port_info = dvs.get_port_info_by_name(port['id'])
            except exceptions.PortNotFound:
                LOG.warn(_LW("Port %s was not found. Security rules can not be"
                             " applied."), port['id'])
                continue

            port_config = port_configuration(builder,
                                             str(port_info['key']),
                                             port['security_group_rules'])
            port_config.configVersion = port_info['config']['configVersion']
            port_config_list.append(port_config)
        if port_config_list:
            task = dvs.connection.invoke_api(
                dvs.connection.vim,
                'ReconfigureDVPort_Task',
                dvs._dvs,
                port=port_config_list
            )
            return dvs.connection.wait_for_task(task)
    except vmware_exceptions.VimException as e:
        raise exceptions.wrap_wmvare_vim_exception(e)


def port_configuration(builder, port_key, sg_rules):
    rules = []
    reversed_rules = []
    seq = 0
    for rule_info in sg_rules:
        rule = _create_rule(builder, rule_info, name='regular')
        rules.append(rule.build(seq))
        seq += 10
        cidr_revert = True
        if rule.ethertype == 'IPv4' and rule.direction == \
                'incomingPackets' and rule.protocol == 'udp':
            if rule.backward_port_range == (67, 67) and rule.port_range == \
                (68, 68):
                cidr_revert = False
        reversed_rules.append(rule.reverse(cidr_revert))

    for r in reversed_rules:
        rules.append(r.build(seq))
        seq += 10

    for i, protocol in enumerate(dvs_const.PROTOCOL.values()):
        rules.append(
            DropAllRule(builder.factory, None, protocol,
                        name='drop all').build(seq + i * 10))

    filter_policy = builder.filter_policy(rules)
    setting = builder.port_setting()
    setting.filterPolicy = filter_policy

    spec = builder.factory.create('ns0:DVPortConfigSpec')
    spec.operation = 'edit'
    spec.setting = setting
    spec.key = port_key
    return spec


def _create_rule(builder, rule_info, ip=None, name=None):
    if rule_info['direction'] == 'ingress':
        rule_class = IngressRule
        cidr = rule_info.get('source_ip_prefix')
    else:
        rule_class = EgressRule
        cidr = rule_info.get('dest_ip_prefix')
    rule = rule_class(
        spec_factory=builder.factory,
        ethertype=rule_info['ethertype'],
        protocol=rule_info.get('protocol'),
        name=name
    )
    rule.cidr = ip or cidr

    if rule_info.get('protocol') in ('tcp', 'udp'):
        rule.port_range = (rule_info.get('port_range_min'),
                           rule_info.get('port_range_max'))
        rule.backward_port_range = (
            rule_info.get('source_port_range_min') or 32768,
            rule_info.get('source_port_range_max') or 65535)
    return rule
