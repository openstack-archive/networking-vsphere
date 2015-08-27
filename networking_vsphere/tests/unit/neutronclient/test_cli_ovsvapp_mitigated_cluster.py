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
    _ovsvapp_mitigated_cluster as ovsvapp_mitigated_cluster)

from neutronclient import shell
from neutronclient.tests.unit import test_cli20


class CLITestV20ExtensionOVSvAppMitigatedClusterJSON(
    test_cli20.CLITestV20Base):
    def setUp(self):
        # need to mock before super because extensions loaded on instantiation.
        self._mock_extension_loading()
        self.vcenter_cluster_id = 'vcenter_id:cluster_id'
        super(CLITestV20ExtensionOVSvAppMitigatedClusterJSON, self).setUp(
            plurals={'tags': 'tag'})

    def _create_patch(self, name, func=None):
        patcher = mock.patch(name)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def _mock_extension_loading(self):
        ext_pkg = 'neutronclient.common.extension'
        contrib = self._create_patch(ext_pkg + '._discover_via_entry_points')
        contrib.return_value = [("_ovsvapp_mitigated_cluster",
                                 ovsvapp_mitigated_cluster)]
        return contrib

    def test_ext_cmd_loaded(self):
        """Tests ovsvapp-mitigated-cluster commands loaded."""

        shell.NeutronShell('2.0')
        ext_cmd = {'ovsvapp-mitigated-cluster-list':
                   ovsvapp_mitigated_cluster.OVSvAppMitigatedClusterList,
                   'ovsvapp-mitigated-cluster-show':
                   ovsvapp_mitigated_cluster.OVSvAppMitigatedClusterShow,
                   'ovsvapp-mitigated-cluster-update':
                   ovsvapp_mitigated_cluster.OVSvAppMitigatedClusterUpdate,
                   'ovsvapp-mitigated-cluster-delete':
                   ovsvapp_mitigated_cluster.OVSvAppMitigatedClusterDelete}
        self.assertDictContainsSubset(ext_cmd, shell.COMMANDS['2.0'])

    def test_list_ovsvapp_mitigated_clusters(self):
        """Test List OVSvApp mitigated clusters."""

        resources = "ovsvapp_mitigated_clusters"
        contents = [{'vcenter-id': 'vcenter-123', }]
        cmd = ovsvapp_mitigated_cluster.OVSvAppMitigatedClusterList(
            test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True,
                                  response_contents=contents)

    def test_delete_mitigated_cluster(self):
        """Test Delete OVSvApp mitigated cluster."""

        resource = 'ovsvapp_mitigated_cluster'
        cmd = ovsvapp_mitigated_cluster.OVSvAppMitigatedClusterDelete(
            test_cli20.MyApp(sys.stdout), None)
        args = ['--vcenter-id', 'vcenter_id', '--cluster-id', 'cluster_id']
        self._test_delete_resource(resource, cmd, self.vcenter_cluster_id,
                                   args)

    def test_show_ovsvapp_mitigated_cluster(self):
        """Test Show OVSvApp mitigated cluster"""

        resource = 'ovsvapp_mitigated_cluster'
        cmd = ovsvapp_mitigated_cluster.OVSvAppMitigatedClusterShow(
            test_cli20.MyApp(sys.stdout), None)
        args = ['--vcenter-id', 'vcenter_id', '--cluster-id', 'cluster_id']
        self._test_show_resource(resource, cmd, self.vcenter_cluster_id, args,
                                 [])

    def test_update_ovsvapp_mitigated_cluster(self):
        """Test Update OVSvApp mitigated cluster."""

        resource = 'ovsvapp_mitigated_cluster'
        cmd = ovsvapp_mitigated_cluster.OVSvAppMitigatedClusterUpdate(
            test_cli20.MyApp(sys.stdout), None)
        args = ['--vcenter-id', 'vcenter_id', '--cluster-id', 'cluster_id',
                '--being-mitigated', 'True']
        values = {"being_mitigated": "True", "cluster_id": "cluster_id",
                  "vcenter_id": "vcenter_id"}
        self._test_update_resource(resource, cmd, self.vcenter_cluster_id,
                                   args, values)
