# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
# All Rights Reserved
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

import sys

import mock

from networking_vsphere.neutronclient import (
    _vcenter_cluster as vcenter_cluster)

from neutronclient import shell
from neutronclient.tests.unit import test_cli20


class CLITestV20ExtensionVcenterClusterJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        # need to mock before super because extensions loaded on instantiation
        self._mock_extension_loading()
        super(CLITestV20ExtensionVcenterClusterJSON, self).setUp(
            plurals={'tags': 'tag'})

    def _create_patch(self, name, func=None):
        patcher = mock.patch(name)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def _mock_extension_loading(self):
        ext_pkg = 'neutronclient.common.extension'
        contrib = self._create_patch(ext_pkg + '._discover_via_entry_points')
        contrib.return_value = [("_vcenter_cluster",
                                 vcenter_cluster)]
        return contrib

    def test_ext_cmd_loaded(self):
        """Tests vsphere-vcenter-cluster  commands loaded."""
        shell.NeutronShell('2.0')
        ext_cmd = {'vsphere-vcenter-cluster-list':
                   vcenter_cluster.VcenterClusterList,
                   'vsphere-vcenter-cluster-show':
                   vcenter_cluster.VcenterClusterShow}
        self.assertDictContainsSubset(ext_cmd, shell.COMMANDS['2.0'])

    def test_list_vcenter_clusters(self):
        """Test List vcenter clusters."""

        resources = "vcenter_clusters"
        contents = [{'vcenter-id': 'myid1', }]
        cmd = vcenter_cluster.VcenterClusterList(
            test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True,
                                  response_contents=contents)

    def test_show_vceneter_cluster(self):
        """Test Show vcenter cluster."""

        resource = 'vcenter_cluster'
        cmd = vcenter_cluster.VcenterClusterShow(
            test_cli20.MyApp(sys.stdout), None)
        args = [self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args)
