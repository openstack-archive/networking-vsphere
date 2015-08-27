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

import mock

from neutron.common import exceptions as exc
from neutron import context
from neutron.tests.unit import testlib_api

from networking_vsphere.db import ovsvapp_db


class VcenterClusterDBTestCase(testlib_api.SqlTestCase):

    """Unit test for Vcenter Cluster DB support."""

    def setUp(self):
        super(VcenterClusterDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.mixin = ovsvapp_db.VcenterClusterDbMixin()

    def _create_vcenter_cluster(self, vcenter_cluster):
        """Create vcenter_cluster helper method."""
        with self.ctx.session.begin(subtransactions=True):
            return self.mixin.create_vcenter_cluster(self.ctx, vcenter_cluster)

    def _get_vcenter_cluster_data(self, vcenter_id, clusters):
        """Get vcenter_cluster  data helper method."""
        data = {"vcenter_cluster": {"vcenter_id": vcenter_id,
                                    "clusters": clusters}}
        return data

    def test_vcenter_cluster_create(self):
        """Test vcenter_cluster create."""
        vcenter_id = "vcenter-123"
        clusters = ["DC1/Cluster1", "DC1/Cluster2"]
        data = self._get_vcenter_cluster_data(vcenter_id, clusters)
        result = self._create_vcenter_cluster(data)
        self.assertEqual(result['vcenter_id'], vcenter_id)

    def _get_vcenter_clusters(self, filters=None):
        """Update vcenter_cluster helper."""
        with self.ctx.session.begin(subtransactions=True):
            return self.mixin.get_vcenter_clusters(self.ctx, filters)

    def test_vcenter_cluster_show(self):
        """Test vcenter_cluster show."""
        vcenter_id1 = "vcenter-123"
        clusters1 = ["DC1/Cluster1", "DC1/Cluster2"]
        data = self._get_vcenter_cluster_data(vcenter_id1, clusters1)
        self._create_vcenter_cluster(data)
        vcenter_id2 = "vcenter-456"
        clusters2 = ["DC2/Cluster1"]
        data = self._get_vcenter_cluster_data(vcenter_id2, clusters2)
        self._create_vcenter_cluster(data)
        result = self.mixin.get_vcenter_cluster(self.ctx, vcenter_id1)
        self.assertEqual(clusters1, result['clusters'])
        result = self.mixin.get_vcenter_cluster(self.ctx, vcenter_id2)
        self.assertEqual(clusters2, result['clusters'])

    def test_vcenter_cluster_list(self):
        """Test vcenter_cluster list."""
        vcenter_id = "vcenter-123"
        clusters = ["DC1/Cluster1", "DC1/Cluster2"]
        data = self._get_vcenter_cluster_data(vcenter_id, clusters)
        self._create_vcenter_cluster(data)
        result = self._get_vcenter_clusters()
        self.assertIn('vcenter_id', result[0])

    def _update_vcenter_cluster(self, id, vcenter_cluster):
        """Update vcenter_cluster helper."""
        with self.ctx.session.begin(subtransactions=True):
            return self.mixin.update_vcenter_cluster(self.ctx, id,
                                                     vcenter_cluster)

    def test_vcenter_cluster_delete(self):
        """Test vcenter_cluster delete."""
        vcenter_id = "vcenter-123"
        clusters = ["DC1/Cluster1", "DC1/Cluster2"]
        data = self._get_vcenter_cluster_data(vcenter_id, clusters)
        result = self._create_vcenter_cluster(data)
        all_results = self._get_vcenter_clusters()
        self.assertEqual(result['vcenter_id'], all_results[0]['vcenter_id'])
        self._update_vcenter_cluster(vcenter_id, data)
        all_results = self._get_vcenter_clusters()
        self.assertEqual(0, len(all_results))

    def test_vcenter_cluster_show_invalid_vcenter_id(self):
        """Test vcenter_cluster show with invalid Vcenter ID."""
        vcenter_id = "vcenter-123"
        clusters = ["DC1/Cluster1", "DC1/Cluster2"]
        data = self._get_vcenter_cluster_data(vcenter_id, clusters)
        self._create_vcenter_cluster(data)
        self.assertRaises(exc.InvalidInput, self.mixin.get_vcenter_cluster,
                          self.ctx, "vcenter-456")

    def test_vcenter_cluster_list_invalid_filter(self):
        """Test vcenter_cluster list with invalid filter."""
        vcenter_id = "vcenter-123"
        clusters = ["DC1/Cluster1", "DC1/Cluster2"]
        data = self._get_vcenter_cluster_data(vcenter_id, clusters)
        self._create_vcenter_cluster(data)
        self.assertRaises(exc.InvalidInput, self._get_vcenter_clusters,
                          filters={'dummy_filter': ['vcenter-123']})

    def test_vcenter_cluster_create_raise_exception(self):
        """Test vcenter_cluster create and raise exception"""
        vcenter_id = "vcenter-123"
        clusters = ["DC1/Cluster1", "DC1/Cluster2"]
        data = self._get_vcenter_cluster_data(vcenter_id, clusters)
        fake = 'networking_vsphere.db.ovsvapp_db._initialize_lvids_for_cluster'
        with mock.patch(fake, return_value=False):
            self.assertRaises(exc.InvalidInput,
                              self.mixin.create_vcenter_cluster,
                              self.ctx, data)
