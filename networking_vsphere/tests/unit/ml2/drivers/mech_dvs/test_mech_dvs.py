# Copyright 2014 IBM Corp.
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

import mock
import unittest

from neutron.plugins.ml2.drivers.mech_dvs import driver
from neutron.plugins.ml2.drivers.mech_dvs import vmware_util
from neutron.tests.unit.ml2.drivers.mech_dvs import fake


class VMWareUtilTestCase(unittest.TestCase):
    def setUp(self):
        super(VMWareUtilTestCase, self).setUp()
        self.dvs_mech_driver = driver.VMwareDVSMechanismDriver()

    def test_initialize(self):
        with mock.patch.object(vmware_util, "VMWareUtil") as fake_util:
            self.dvs_mech_driver.initialize()
            fake_util.assert_call_once()

    def test_create_network_precommit(self):
        self.test_initialize()
        with mock.patch.object(self.dvs_mech_driver,
                               "vmware_util") as fake_util:
            fake_context = mock.Mock()
            self.dvs_mech_driver.create_network_precommit(fake_context)
            fake_util.create_dvpg.assert_called_with(fake_context)

    def test_delete_network_precommit(self):
        self.test_initialize()
        with mock.patch.object(self.dvs_mech_driver,
                               "vmware_util") as fake_util:
            fake_context = mock.Mock()
            self.dvs_mech_driver.delete_network_precommit(fake_context)
            fake_util.delete_dvpg.assert_called_with(fake_context)

    def test_update_network_precommit(self):
        self.test_initialize()
        with mock.patch.object(self.dvs_mech_driver,
                               "vmware_util") as fake_util:
            fake_context = mock.Mock()
            self.dvs_mech_driver.update_network_precommit(fake_context)
            fake_util.update_dvpg.assert_called_with(fake_context)

    def test_bind_port(self):
        self.test_initialize()
        fake_net_context = fake.NetworkContext()
        fake_net = {"name": "net1",
                    "id": "847f6079-dc07-4445-9e2a-17d16278cc90"}
        fake_segms = [{"id": "545423da-dc07-4445-9e2a-17d16278cc90",
                       "network_type": "vlan",
                       "physical_network": "physnet1",
                       "segmentation_id": 100}]
        fake_net_context.set("current", fake_net)
        fake_net_context.set("network_segments", fake_segms)\

        fake_port_context = fake.PortContext()
        fake_port = {"id": "847f6079-dc07-4445-9e2a-17d162sdfc91"}
        fake_port_context.set("current", fake_port)
        fake_port_context.set("network", fake_net_context)
        with mock.patch.object(fake_port_context,
                               "set_binding") as fake_set_binding:
            self.dvs_mech_driver.bind_port(fake_port_context)
            fake_set_binding.assert_called_with(
                fake_segms[0]['id'],
                self.dvs_mech_driver.vif_type,
                self.dvs_mech_driver.vif_details,
                status='ACTIVE')
