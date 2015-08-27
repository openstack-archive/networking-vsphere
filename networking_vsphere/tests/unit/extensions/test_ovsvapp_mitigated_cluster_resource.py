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


from neutron.common import exceptions as exc
from neutron import context
from neutron.db import api as db_api
from neutron.tests.unit import testlib_api

from networking_vsphere.db import ovsvapp_db
from networking_vsphere.db import ovsvapp_models

VCENTER_ID1 = "vcenter-123"
DC1_CLUSTER1 = "DC1/Cluster1"
VCENTER_ID2 = "vcenter-456"
DC1_CLUSTER2 = "DC2/Cluster1"


class OVSvAppMitigatedClusterDBTestCase(testlib_api.SqlTestCase):
    """Unit test for OVSvApp Mitigated Cluster DB support."""

    def setUp(self):
        super(OVSvAppMitigatedClusterDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.mixin = ovsvapp_db.OVSvAppMitigatedClusterDbMixin()

    def _create_ovsvapp_mitigated_cluster(self, ovsvapp_mitigated_cluster):
        """Create mitigated_cluster helper method."""
        session = db_api.get_session()
        db_entry_dict = ovsvapp_mitigated_cluster['ovsvapp_mitigated_cluster']
        db_entry = {'vcenter_id': db_entry_dict['vcenter_id'],
                    'cluster_id': db_entry_dict['cluster_id'],
                    'threshold_reached': db_entry_dict['threshold_reached'],
                    'being_mitigated': db_entry_dict['being_mitigated']}
        session.execute(ovsvapp_models.OVSvAppClusters.__table__.insert(),
                        db_entry)
        return ovsvapp_mitigated_cluster['ovsvapp_mitigated_cluster']

    def _get_ovsvapp_mitigated_cluster_data(self, vcenter_id, cluster_id,
                                            being_mitigated=False,
                                            threshold_reached=False):
        """Get ovsvapp_mitigated_cluster  data helper method."""
        data = {"ovsvapp_mitigated_cluster":
                {"vcenter_id": vcenter_id,
                 "cluster_id": cluster_id,
                 "being_mitigated": being_mitigated,
                 "threshold_reached": threshold_reached}}
        return data

    def _get_ovsvapp_mitigated_clusters(self, filters=None):
        """Update ovsvapp_mitigated_cluster helper."""
        with self.ctx.session.begin(subtransactions=True):
            return self.mixin.get_ovsvapp_mitigated_clusters(self.ctx, filters)

    def test_ovsvapp_mitigated_cluster_show(self):
        """Test ovsvapp_mitigated_cluster show."""
        data = self._get_ovsvapp_mitigated_cluster_data(VCENTER_ID1,
                                                        DC1_CLUSTER1)
        self._create_ovsvapp_mitigated_cluster(data)
        mitigated_cluster1 = VCENTER_ID1 + ':' + DC1_CLUSTER1.replace('/', '|')
        mitigated_cluster2 = VCENTER_ID2 + ':' + DC1_CLUSTER2.replace('/', '|')
        data = self._get_ovsvapp_mitigated_cluster_data(VCENTER_ID2,
                                                        DC1_CLUSTER2)
        self._create_ovsvapp_mitigated_cluster(data)
        result = self.mixin.get_ovsvapp_mitigated_cluster(self.ctx,
                                                          mitigated_cluster1)
        self.assertEqual(DC1_CLUSTER1, result['cluster_id'])
        result = self.mixin.get_ovsvapp_mitigated_cluster(self.ctx,
                                                          mitigated_cluster2)
        self.assertEqual(DC1_CLUSTER2, result['cluster_id'])

    def test_ovsvapp_mitigated_cluster_list(self):
        """Test ovsvapp_mitigated_cluster list."""
        data = self._get_ovsvapp_mitigated_cluster_data(VCENTER_ID1,
                                                        DC1_CLUSTER1)
        self._create_ovsvapp_mitigated_cluster(data)
        result = self._get_ovsvapp_mitigated_clusters()
        self.assertIn('vcenter_id', result[0])

    def _update_ovsvapp_mitigated_cluster(self, id, ovsvapp_mitigated_cluster):
        """Update ovsvapp_mitigated_cluster helper."""
        with self.ctx.session.begin(subtransactions=True):
            return self.mixin.update_ovsvapp_mitigated_cluster(
                self.ctx, id, ovsvapp_mitigated_cluster)

    def _delete_ovsvapp_mitigated_cluster(self, vcenter_id, cluster_id):
        """Delete ovsvapp_mitigated_cluster helper."""
        with self.ctx.session.begin(subtransactions=True):
            vc = vcenter_id + ':' + cluster_id.replace('/', '|')
            return self.mixin.delete_ovsvapp_mitigated_cluster(self.ctx, vc)

    def test_ovsvapp_mitigated_cluster_delete(self):
        """Test ovsvapp_mitigated_cluster delete."""
        data = self._get_ovsvapp_mitigated_cluster_data(VCENTER_ID1,
                                                        DC1_CLUSTER1)
        result = self._create_ovsvapp_mitigated_cluster(data)
        all_results = self._get_ovsvapp_mitigated_clusters()
        self.assertEqual(result['vcenter_id'], all_results[0]['vcenter_id'])
        self._delete_ovsvapp_mitigated_cluster(VCENTER_ID1, DC1_CLUSTER1)
        all_results = self._get_ovsvapp_mitigated_clusters()
        self.assertEqual(0, len(all_results))

    def test_ovsvapp_mitigated_cluster_update(self):
        """Test ovsvapp_mitigated_cluster update."""
        data = self._get_ovsvapp_mitigated_cluster_data(VCENTER_ID1,
                                                        DC1_CLUSTER1)
        result = self._create_ovsvapp_mitigated_cluster(data)
        all_results = self._get_ovsvapp_mitigated_clusters()
        self.assertEqual(result['vcenter_id'], all_results[0]['vcenter_id'])
        self.assertEqual(all_results[0]['being_mitigated'], False)
        self.assertEqual(all_results[0]['threshold_reached'], False)
        data['ovsvapp_mitigated_cluster']['being_mitigated'] = True
        data['ovsvapp_mitigated_cluster']['threshold_reached'] = True
        mitigated_cluster = VCENTER_ID1 + ':' + DC1_CLUSTER1.replace('/', '|')
        self._update_ovsvapp_mitigated_cluster(mitigated_cluster, data)
        all_results = self._get_ovsvapp_mitigated_clusters()
        self.assertEqual(all_results[0]['vcenter_id'], VCENTER_ID1)
        self.assertEqual(all_results[0]['being_mitigated'], True)
        self.assertEqual(all_results[0]['threshold_reached'], True)

    def test_ovsvapp_mitigated_cluster_show_invalid_vcenter_id(self):
        """Test ovsvapp_mitigaed_cluster show with invalid Vcenter ID."""
        data = self._get_ovsvapp_mitigated_cluster_data(VCENTER_ID1,
                                                        DC1_CLUSTER1)
        self._create_ovsvapp_mitigated_cluster(data)
        self.assertRaises(exc.InvalidInput,
                          self.mixin.get_ovsvapp_mitigated_cluster,
                          self.ctx, "vcenter-456:DC/Cluster1")
