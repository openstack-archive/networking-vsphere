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

from networking_vsphere.common import exceptions
from networking_vsphere.utils import compute_util


class ComputeUtilTestCase(base.BaseTestCase):
    _hypervisor_host_index = 0

    def setUp(self):
        super(ComputeUtilTestCase, self).setUp()
        self.config = mock.Mock()

    @mock.patch('networking_vsphere.utils.compute_util._make_nova_client')
    def test_get_hypervisor_by_host(self, make_client):
        expected_hostname = 'expected-host'
        hosts = [
            self._make_hypervisor(expected_hostname),
            self._make_hypervisor(),
            self._make_hypervisor()]
        make_client.return_value = client = mock.Mock()
        client.hypervisors.list.return_value = hosts

        actual = compute_util.get_hypervisors_by_host(
            self.config, expected_hostname)

        self.assertEqual(hosts[0], actual)

    @mock.patch('networking_vsphere.utils.compute_util._make_nova_client')
    def test_get_hypervisor_by_host_not_found(self, make_client):
        expected_hostname = 'expected-host'
        hosts = [
            self._make_hypervisor(),
            self._make_hypervisor(),
            self._make_hypervisor()]
        make_client.return_value = client = mock.Mock()
        client.hypervisors.list.return_value = hosts

        self.assertRaises(
            exceptions.HypervisorNotFound,
            compute_util.get_hypervisors_by_host,
            self.config, expected_hostname)

    def _make_hypervisor(self, host=None):
        if not host:
            self._hypervisor_host_index += 1
            host = '_node-{}_'.format(self._hypervisor_host_index)

        return mock.Mock(service={
            'host': host})
