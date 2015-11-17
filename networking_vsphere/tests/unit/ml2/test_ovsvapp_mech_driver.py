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
#
# Unit test for OVSvApp Mechanism Driver.

from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.ovsvapp import mech_driver
from neutron.tests.unit.plugins.ml2 import _test_mech_agent as base

# TODO(romilg): Revisit to minimize dependency on ML2 tests.

from networking_vsphere.common import constants


class OVSvAppAgentMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OTHER
    CAP_PORT_FILTER = True
    AGENT_TYPE = constants.AGENT_TYPE_OVSVAPP

    GOOD_MAPPINGS = {'fake_physical_network': 'fake_bridge'}
    GOOD_TUNNEL_TYPES = ['vxlan']
    GOOD_CONFIGS = {'bridge_mappings': GOOD_MAPPINGS,
                    'tunnel_types': GOOD_TUNNEL_TYPES}

    BAD_MAPPINGS = {'wrong_physical_network': 'wrong_bridge'}
    BAD_TUNNEL_TYPES = ['bad_tunnel_type']
    BAD_CONFIGS = {'bridge_mappings': BAD_MAPPINGS,
                   'tunnel_types': BAD_TUNNEL_TYPES}

    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS,
               'host': 'host'}]
    AGENTS_DEAD = [{'alive': False,
                    'configurations': GOOD_CONFIGS,
                    'host': 'dead_host'}]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS,
                   'host': 'bad_host_1'},
                  {'alive': True,
                   'configurations': BAD_CONFIGS,
                   'host': 'bad_host_2'}]

    def setUp(self):
        super(OVSvAppAgentMechanismBaseTestCase, self).setUp()
        self.driver = mech_driver.OVSvAppAgentMechanismDriver()
        self.driver.initialize()


class OVSvAppAgentMechanismGenericTestCase(
    OVSvAppAgentMechanismBaseTestCase,
    base.AgentMechanismGenericTestCase):
    pass


class OVSvAppAgentMechanismVlanTestCase(
    OVSvAppAgentMechanismBaseTestCase,
    base.AgentMechanismVlanTestCase):
    pass


class OVSvAppAgentMechanismVxlanTestCase(
    OVSvAppAgentMechanismBaseTestCase,
    base.AgentMechanismBaseTestCase):
    VXLAN_SEGMENTS = [{api.ID: 'unknown_segment_id',
                       api.NETWORK_TYPE: 'no_such_type'},
                      {api.ID: 'vxlan_segment_id',
                       api.NETWORK_TYPE: 'vxlan',
                       api.SEGMENTATION_ID: 1234}]

    def test_type_vxlan(self):
        context = base.FakePortContext(self.AGENT_TYPE,
                                       self.AGENTS,
                                       self.VXLAN_SEGMENTS)
        self.driver.bind_port(context)
        self._check_bound(context, self.VXLAN_SEGMENTS[1])

    def test_type_vxlan_bad(self):
        context = base.FakePortContext(self.AGENT_TYPE,
                                       self.AGENTS_BAD,
                                       self.VXLAN_SEGMENTS)
        self.driver.bind_port(context)
        self._check_unbound(context)
