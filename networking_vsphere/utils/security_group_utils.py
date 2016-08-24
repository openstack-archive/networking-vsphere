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
import copy
import netaddr
import six

from oslo_log import log
from oslo_vmware import exceptions as vmware_exceptions

from networking_vsphere._i18n import _LI
from networking_vsphere.common import constants as dvs_const
from networking_vsphere.common import exceptions
from networking_vsphere.utils import dvs_util
from networking_vsphere.utils import spec_builder

LOG = log.getLogger(__name__)


HASHED_RULE_INFO_KEYS = [
    'source_ip_prefix',
    'dest_ip_prefix',
    'protocol',
    'direction',
    'ethertype',
    'port_range_min',
    'port_range_max',
    'source_port_range_min',
    'source_port_range_max'
]


class PortConfigSpecBuilder(spec_builder.SpecBuilder):
    def __init__(self, spec_factory):
        super(PortConfigSpecBuilder, self).__init__(spec_factory)
        self.rule_obj = self.factory.create('ns0:DvsTrafficRule')

    def traffic_rule(self):
        return copy.copy(self.rule_obj)

    def create_spec(self, spec_type):
        return self.factory.create(spec_type)


@six.add_metaclass(abc.ABCMeta)
class TrafficRuleBuilder(object):
    action = 'ns0:DvsAcceptNetworkRuleAction'
    direction = 'both'
    reverse_class = None
    _backward_port_range = (None, None)
    _port_range = (None, None)

    def __init__(self, spec_builder, ethertype, protocol, name=None):
        self.spec_builder = spec_builder

        self.rule = spec_builder.traffic_rule()
        self.rule.action = self.spec_builder.create_spec(self.action)

        self.ip_qualifier = self.spec_builder.create_spec(
            'ns0:DvsIpNetworkRuleQualifier')

        self.ethertype = ethertype
        if ethertype:
            any_ip = '0.0.0.0/0' if ethertype == 'IPv4' else '::/0'
            self.ip_qualifier.sourceAddress = self._cidr_spec(any_ip)
            self.ip_qualifier.destinationAddress = self._cidr_spec(any_ip)

        self.protocol = protocol
        if protocol:
            int_exp = self.spec_builder.create_spec('ns0:IntExpression')
            int_exp.value = dvs_const.PROTOCOL.get(protocol, protocol)
            int_exp.negate = 'false'
            self.ip_qualifier.protocol = int_exp

        self.name = name

    def reverse(self, cidr_bool):
        """Returns reversed rule"""
        name = 'reversed' + ' ' + (self.name or '')
        rule = self.reverse_class(self.spec_builder, self.ethertype,
                                  self.protocol, name=name.strip())
        if cidr_bool:
            if (self.ethertype == 'IPv6' and self.protocol == 'ipv6-icmp' and
                    self.type == 134):
                LOG.error(str(self.type))
                rule.cidr = 'FF02::2/128'
            else:
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
            result = self.spec_builder.create_spec('ns0:DvsSingleIpPort')
            result.portNumber = begin
        else:
            result = self.spec_builder.create_spec('ns0:DvsIpPortRange')
            result.startPortNumber = begin
            result.endPortNumber = end
        return result

    def _cidr_spec(self, cidr):
        cidr = netaddr.IPNetwork(cidr)
        result = self.spec_builder.create_spec('ns0:IpRange')
        result.addressPrefix = str(cidr.ip)
        result.prefixLength = str(cidr.prefixlen)
        return result

    def _has_port(self, min_port):
        if min_port:
            if self.protocol == 'icmp' or self.protocol == 'ipv6-icmp':
                LOG.info(_LI('Vmware dvs driver does not support '
                             '"type" and "code" for ICMP/ipv6-icmp protocol.'))
                return False
            else:
                return True
        else:
            return False


class IngressRule(TrafficRuleBuilder):
    direction = 'incomingPackets'

    def __init__(self, spec_builder, ethertype, protocol, name=None):
        super(IngressRule, self).__init__(
            spec_builder, ethertype, protocol, name)
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

    def __init__(self, spec_builder, ethertype, protocol, name=None):
        super(EgressRule, self).__init__(
            spec_builder, ethertype, protocol, name)
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


def filter_port_sg_rules_by_ethertype(port_info):
    port_ethertypes = set('IPv%s' % netaddr.IPNetwork(ip).version
                          for ip in port_info['fixed_ips'])
    port_info['security_group_rules'] = [
        rule for rule in port_info['security_group_rules']
        if rule['ethertype'] in port_ethertypes
    ]
    return port_info


@dvs_util.wrap_retry
def update_port_rules(dvs, ports):
    try:
        builder = PortConfigSpecBuilder(dvs.connection.vim.client.factory)
        port_config_list = []
        hashed_rules = {}
        for port in ports:
            key = port.get('binding:vif_details', {}).get('dvs_port_key')
            if key:
                port_config = port_configuration(
                    builder, key, port['security_group_rules'], hashed_rules)
                port_config_list.append(port_config)
        if port_config_list:
            task = dvs.connection.invoke_api(
                dvs.connection.vim,
                'ReconfigureDVPort_Task',
                dvs._dvs,
                port=port_config_list
            )
            dvs.connection.wait_for_task(task)
    except vmware_exceptions.VimException as e:
        if 'The object or item referred to could not be found' in str(e):
            pass
        else:
            raise exceptions.wrap_wmvare_vim_exception(e)


def port_configuration(builder, port_key, sg_rules, hashed_rules):
    rules = []
    seq = 0
    reverse_seq = len(sg_rules) * 10
    for rule_info in sg_rules:
        rule_hash = _get_rule_hash(rule_info)
        if rule_hash in hashed_rules:
            rule, reverse_rule = hashed_rules[rule_hash]
            built_rule = copy.copy(rule)
            built_reverse_rule = copy.copy(reverse_rule)
            built_rule.description = str(seq) + '. regular'
            built_rule.sequence = seq
            built_reverse_rule.description = '%s. reversed %s' % (
                str(reverse_seq), built_rule.description)
            built_reverse_rule.sequence = reverse_seq
        else:
            rule = _create_rule(builder, rule_info, name='regular')
            built_rule = rule.build(seq)
            cidr_revert = not _rule_excepted(rule)
            reverse_rule = rule.reverse(cidr_revert)
            built_reverse_rule = reverse_rule.build(reverse_seq)
            hashed_rules[rule_hash] = (built_rule, built_reverse_rule)

        rules.extend([built_rule, built_reverse_rule])
        seq += 10
        reverse_seq += 10

    seq = len(rules) * 10

    rules.append(DropAllRule(builder, 'IPv4', None,
                             name='drop all').build(seq))
    seq += 10
    rules.append(DropAllRule(builder, 'IPv6', None,
                             name='drop all').build(seq))

    filter_policy = builder.filter_policy(rules)
    setting = builder.port_setting()
    setting.filterPolicy = filter_policy
    spec = builder.port_config_spec(setting=setting)
    spec.key = port_key
    return spec


def _rule_excepted(rule):
    if rule.direction == 'incomingPackets' and rule.protocol == 'udp':
        if (rule.ethertype == 'IPv4' and rule.port_range == (68, 68) and
                rule.backward_port_range == (67, 67)):
            return True
        if (rule.ethertype == 'IPv6' and rule.port_range == (546, 546) and
                rule.backward_port_range == (547, 547)):
            return True
    return False


def _get_rule_hash(rule):
    rule_tokens = []
    for k in sorted(rule):
        if k in HASHED_RULE_INFO_KEYS:
            rule_tokens.append('%s:%s' % (k, rule[k]))
    return ','.join(rule_tokens)


def _create_rule(builder, rule_info, ip=None, name=None):
    if rule_info['direction'] == 'ingress':
        rule_class = IngressRule
        cidr = rule_info.get('source_ip_prefix')
    else:
        rule_class = EgressRule
        cidr = rule_info.get('dest_ip_prefix')
    rule = rule_class(
        spec_builder=builder,
        ethertype=rule_info['ethertype'],
        protocol=rule_info.get('protocol'),
        name=name
    )
    rule.cidr = ip or cidr

    if rule_info.get('protocol') in ('tcp', 'udp'):
        rule.port_range = (rule_info.get('port_range_min'),
                           rule_info.get('port_range_max'))
        rule.backward_port_range = (
            rule_info.get(
                'source_port_range_min') or dvs_const.MIN_EPHEMERAL_PORT,
            rule_info.get(
                'source_port_range_max') or dvs_const.MAX_EPHEMERAL_PORT)
    if rule_info.get('protocol') in ('ipv6-icmp', 'icmp'):
        rule.type = rule_info.get('source_port_range_min')
    return rule
