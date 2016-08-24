# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

import mock
from neutron.tests import base
import six

from networking_vsphere.common import constants as dvs_const
from networking_vsphere.tests.unit.utils import test_dvs_util
from networking_vsphere.utils import security_group_utils as sg_util


class TrafficRuleBuilderBaseTestCase(test_dvs_util.UtilBaseTestCase):

    def setUp(self):
        super(TrafficRuleBuilderBaseTestCase, self).setUp()
        self.spec_factory = self._get_factory_mock((
            'ns0:IntExpression',
            'ns0:DvsTrafficRule',
            'ns0:DvsAcceptNetworkRuleAction',
            'ns0:DvsIpNetworkRuleQualifier',
            'ns0:IpRange',
            'ns0:SingleIp',
            'ns0:DvsSingleIpPort',
            'ns0:DvsIpPortRange'))
        self.spec_builder = sg_util.PortConfigSpecBuilder(self.spec_factory)


class TrafficRuleBuilderTestCase(TrafficRuleBuilderBaseTestCase):
    def setUp(self):
        super(TrafficRuleBuilderTestCase, self).setUp()
        self.sequence = 20

    def _create_builder(self, ethertype=None, protocol=None, name=None):
        class ConcreteTrafficRuleBuilder(sg_util.TrafficRuleBuilder):

            def port_range(self, start, end):
                pass

            def cidr(self, cidr):
                pass

        return ConcreteTrafficRuleBuilder(
            self.spec_builder, ethertype, protocol, name)

    def test_build_sequence(self):
        name = '_name_'
        builder = self._create_builder(name=name)
        rule = builder.build(self.sequence)
        self.assertEqual(self.sequence, rule.sequence)
        self.assertEqual(str(self.sequence) + '. ' + name, rule.description)

    def test_build_ethertype_IPv4(self):
        builder = self._create_builder(ethertype='IPv4')
        rule = builder.build(self.sequence)
        qualifier = rule.qualifier[0]
        self.assertEqual('0.0.0.0', qualifier.sourceAddress.addressPrefix)
        self.assertEqual('0', qualifier.sourceAddress.prefixLength)
        self.assertEqual('0.0.0.0', qualifier.destinationAddress.addressPrefix)
        self.assertEqual('0', qualifier.destinationAddress.prefixLength)

    def test_build_ethertype_IPv6(self):
        builder = self._create_builder(ethertype='IPv6')
        rule = builder.build(self.sequence)
        qualifier = rule.qualifier[0]
        self.assertEqual('::', qualifier.sourceAddress.addressPrefix)
        self.assertEqual('0', qualifier.sourceAddress.prefixLength)
        self.assertEqual('::', qualifier.destinationAddress.addressPrefix)
        self.assertEqual('0', qualifier.destinationAddress.prefixLength)

    def test_build_ethertype_protocol(self):
        for name, rfc in six.iteritems(dvs_const.PROTOCOL):
            builder = self._create_builder(protocol=name)
            rule = builder.build(self.sequence)
            qualifier = rule.qualifier[0]
            self.assertEqual(rfc,
                             qualifier.protocol.value,
                             'Wrong value for %s protocol' % name)

        builder = self._create_builder(protocol='not_described')
        rule = builder.build(self.sequence)
        qualifier = rule.qualifier[0]
        self.assertEqual('not_described',
                         qualifier.protocol.value)

    def test__has_port_for_icmp(self):
        builder = self._create_builder(protocol='icmp')
        self.assertFalse(builder._has_port(None))
        self.assertFalse(builder._has_port(123))

    def test__has_port_for_tcp(self):
        builder = self._create_builder(protocol='tcp')
        self.assertFalse(builder._has_port(None))
        self.assertTrue(builder._has_port(123))

    def test__cidr_spec_for_ip_range(self):
        builder = self._create_builder()
        cidr_spec = builder._cidr_spec('192.168.0.2/24')
        self.assertEqual('ns0:IpRange', cidr_spec._mock_name)
        self.assertEqual('192.168.0.2', cidr_spec.addressPrefix)
        self.assertEqual('24', cidr_spec.prefixLength)

    def test__cidr_spec_for_single_ip(self):
        builder = self._create_builder()
        cidr_spec = builder._cidr_spec('192.168.0.2')
        self.assertEqual('ns0:IpRange', cidr_spec._mock_name)
        self.assertEqual('192.168.0.2', cidr_spec.addressPrefix)
        self.assertEqual('32', cidr_spec.prefixLength)

    def test__port_spec_for_single_port(self):
        builder = self._create_builder()
        port_spec = builder._port_range_spec(22, 22)
        self.assertEqual('ns0:DvsSingleIpPort', port_spec._mock_name)
        self.assertEqual(22, port_spec.portNumber)

    def test__port_spec_for_port_range(self):
        builder = self._create_builder()
        port_spec = builder._port_range_spec(22, 121)
        self.assertEqual('ns0:DvsIpPortRange', port_spec._mock_name)
        self.assertEqual(22, port_spec.startPortNumber)
        self.assertEqual(121, port_spec.endPortNumber)


class SpecBuilderSecurityGroupsTestCase(base.BaseTestCase):

    def setUp(self):
        super(SpecBuilderSecurityGroupsTestCase, self).setUp()
        self.spec = mock.Mock(name='spec')
        self.factory = mock.Mock(name='factory')
        self.factory.create.return_value = self.spec
        self.builder = sg_util.PortConfigSpecBuilder(self.factory)

    def test__create_rule_egress(self):
        rule = self._create_rule(direction='egress')
        self.assertEqual(rule.direction, 'outgoingPackets')

    def test__create_rule_ingress(self):
        rule = self._create_rule(direction='ingress')
        self.assertEqual(rule.direction, 'incomingPackets')

    def test__create_rule_ingress_port_range(self):
        rule = self._create_rule(direction='ingress',
                                 port_range_min=22,
                                 port_range_max=23)
        qualifier = rule.qualifier[0]
        self.assertEqual(qualifier.sourceIpPort.startPortNumber, 32768)
        self.assertEqual(qualifier.sourceIpPort.endPortNumber, 65535)
        self.assertEqual(qualifier.destinationIpPort.startPortNumber, 22)
        self.assertEqual(qualifier.destinationIpPort.endPortNumber, 23)

    def test__create_rule_egress_port_range(self):
        rule = self._create_rule(direction='egress',
                                 port_range_min=22,
                                 port_range_max=23)
        qualifier = rule.qualifier[0]
        self.assertEqual(qualifier.destinationIpPort.startPortNumber, 22)
        self.assertEqual(qualifier.destinationIpPort.endPortNumber, 23)

    def test__create_rule_ingress_cidr(self):
        rule = self._create_rule(direction='ingress',
                                 source_ip_prefix='192.168.0.1/24')
        qualifier = rule.qualifier[0]
        self.assertEqual('192.168.0.1', qualifier.sourceAddress.addressPrefix)
        self.assertEqual('0.0.0.0', qualifier.destinationAddress.addressPrefix)

    def test__create_rule_egress_cidr(self):
        rule = self._create_rule(direction='egress',
                                 dest_ip_prefix='192.168.0.1/24')
        qualifier = rule.qualifier[0]
        self.assertEqual('192.168.0.1',
                         qualifier.destinationAddress.addressPrefix)
        self.assertEqual('0.0.0.0', qualifier.sourceAddress.addressPrefix)

    def test__create_rule_egress_ip(self):
        rule = self._create_rule(direction='egress',
                                 dest_ip_prefix='192.168.0.1/24',
                                 ip='10.20.0.2')
        qualifier = rule.qualifier[0]
        self.assertEqual('10.20.0.2',
                         qualifier.destinationAddress.addressPrefix)
        self.assertEqual('32', qualifier.destinationAddress.prefixLength)
        self.assertEqual('0.0.0.0', qualifier.sourceAddress.addressPrefix)

    def test__create_rule_ingress_ip(self):
        rule = self._create_rule(direction='ingress',
                                 dest_ip_prefix='192.168.0.1/24',
                                 ip='10.20.0.2')
        qualifier = rule.qualifier[0]
        self.assertEqual('0.0.0.0',
                         qualifier.destinationAddress.addressPrefix)
        self.assertEqual('10.20.0.2', qualifier.sourceAddress.addressPrefix)
        self.assertEqual('32', qualifier.sourceAddress.prefixLength)

    def _create_rule(self, ip=None, **kwargs):
        def side_effect(name):
            return mock.Mock(name=name)

        self.factory.create.side_effect = side_effect

        rule_info = {'direction': 'egress',
                     'protocol': 'tcp',
                     'ethertype': 'IPv4'}

        sequence = 25
        rule_info.update(kwargs)
        rule = sg_util._create_rule(self.builder, rule_info, ip)
        result = rule.build(sequence)
        self.assertEqual(result.sequence, sequence)
        return result
