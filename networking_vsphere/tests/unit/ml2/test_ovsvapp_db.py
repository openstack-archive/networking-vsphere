# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
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

from neutron.tests.unit import testlib_api

from networking_vsphere.db import ovsvapp_db


class OVSvAppDBTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(OVSvAppDBTestCase, self).setUp()

    def _form_port_info_dict(self, vcenter, cluster, network):
        return {'vcenter_id': vcenter,
                'cluster_id': cluster,
                'network_id': network,
                'port_id': 'fake_port'}

    def test_get_local_vlan_first_network_first_port(self):
        net1_port1_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        lvid = ovsvapp_db.get_local_vlan(net1_port1_info)
        self.assertEqual(1, lvid)

    def test_get_local_vlan_second_network_first_port(self):
        net1_port1_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        ovsvapp_db.get_local_vlan(net1_port1_info)

        net2_port1_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net2')

        lvid = ovsvapp_db.get_local_vlan(net2_port1_info)
        self.assertEqual(2, lvid)

    def test_get_local_vlan_first_network_second_port(self):
        net1_port_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        ovsvapp_db.get_local_vlan(net1_port_info)

        net2_port1_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net2')
        ovsvapp_db.get_local_vlan(net2_port1_info)

        lvid = ovsvapp_db.get_local_vlan(net1_port_info)
        self.assertEqual(1, lvid)

    def test_get_local_vlan_read_before_write(self):
        net1_port1_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        lvid = ovsvapp_db.get_local_vlan(net1_port1_info, False)
        self.assertIsNone(lvid)

    def test_get_local_vlan_write_and_read(self):
        net1_port1_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        ovsvapp_db.get_local_vlan(net1_port1_info)
        lvid = ovsvapp_db.get_local_vlan(net1_port1_info, False)
        self.assertEqual(1, lvid)

    def test_get_local_vlan_initialize_error(self):
        net1_port_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        with mock.patch('networking_vsphere.db.ovsvapp_db.'
                        '_initialize_lvids_for_cluster', return_value=False):
            lvid = ovsvapp_db.get_local_vlan(net1_port_info)
            self.assertIsNone(lvid)

    def test_check_to_reclaim_local_vlan(self):
        net1_port1_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        ovsvapp_db.get_local_vlan(net1_port1_info)

        lvid = ovsvapp_db.check_to_reclaim_local_vlan(net1_port1_info)
        self.assertEqual(1, lvid)

    def test_check_to_reclaim_local_vlan_multiple_ports(self):
        net1_port_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        ovsvapp_db.get_local_vlan(net1_port_info)
        ovsvapp_db.get_local_vlan(net1_port_info)
        ovsvapp_db.get_local_vlan(net1_port_info)

        lvid = ovsvapp_db.check_to_reclaim_local_vlan(net1_port_info)
        self.assertEqual(-1, lvid)
        lvid = ovsvapp_db.check_to_reclaim_local_vlan(net1_port_info)
        self.assertEqual(-1, lvid)
        lvid = ovsvapp_db.check_to_reclaim_local_vlan(net1_port_info)
        self.assertEqual(1, lvid)

    def test_release_local_vlan_already_released_network(self):
        net1_port_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        with mock.patch('networking_vsphere.db.ovsvapp_db.'
                        'LOG.error') as error_log:
            ovsvapp_db.release_local_vlan(net1_port_info)
            self.assertTrue(error_log.called)

    def test_release_local_vlan(self):
        net1_port_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        # Allocate network.
        ovsvapp_db.get_local_vlan(net1_port_info)

        # Setup for release.
        lvid = ovsvapp_db.check_to_reclaim_local_vlan(net1_port_info)
        self.assertEqual(1, lvid)
        with mock.patch('networking_vsphere.db.ovsvapp_db.'
                        'LOG.error') as error_log:
            ovsvapp_db.release_local_vlan(net1_port_info)
            self.assertFalse(error_log.called)

    def test_get_stale_local_vlans_for_network(self):
        net1_port1_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster1', 'net1')
        ovsvapp_db.get_local_vlan(net1_port1_info)

        net1_port2_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster2', 'net1')
        ovsvapp_db.get_local_vlan(net1_port2_info)
        lvid = ovsvapp_db.check_to_reclaim_local_vlan(net1_port1_info)
        self.assertEqual(1, lvid)
        lvid = ovsvapp_db.check_to_reclaim_local_vlan(net1_port2_info)
        self.assertEqual(1, lvid)
        ret_val = ovsvapp_db.get_stale_local_vlans_for_network('net1')
        self.assertEqual([('fake_vcenter', 'fake_cluster1', 1),
                          ('fake_vcenter', 'fake_cluster2', 1)], ret_val)

    def test_get_stale_local_vlans_for_network_no_stale_networks(self):
        net1_port_info = self._form_port_info_dict(
            'fake_vcenter', 'fake_cluster', 'net1')
        # Allocate network.
        ovsvapp_db.get_local_vlan(net1_port_info)

        # Setup for release.
        lvid = ovsvapp_db.check_to_reclaim_local_vlan(net1_port_info)
        self.assertEqual(1, lvid)
        ovsvapp_db.release_local_vlan(net1_port_info)
        ret_val = ovsvapp_db.get_stale_local_vlans_for_network('net1')
        self.assertIsNone(ret_val)

    def test_update_and_get_cluster_lock_first_host(self):
        with mock.patch('networking_vsphere.db.ovsvapp_db.'
                        'LOG.info') as info_log:
            ret = ovsvapp_db.update_and_get_cluster_lock('fake_vcenter',
                                                         'fake_cluster')
        self.assertEqual('1', ret)
        self.assertTrue(info_log.called)

    def test_update_and_get_cluster_lock_second_host_no_lock(self):
        ret = ovsvapp_db.update_and_get_cluster_lock('fake_vcenter',
                                                     'fake_cluster')
        self.assertEqual('1', ret)
        with mock.patch('networking_vsphere.db.ovsvapp_db.'
                        'LOG.info') as info_log:
            ret_1 = ovsvapp_db.update_and_get_cluster_lock('fake_vcenter',
                                                           'fake_cluster')
        self.assertEqual('0', ret_1)
        self.assertTrue(info_log.called)

    def test_update_and_get_cluster_lock_second_host_lock_released(self):
        ret = ovsvapp_db.update_and_get_cluster_lock('fake_vcenter',
                                                     'fake_cluster')
        self.assertEqual('1', ret)
        ovsvapp_db.release_cluster_lock('fake_vcenter', 'fake_cluster')
        with mock.patch('networking_vsphere.db.ovsvapp_db.'
                        'LOG.info') as info_log:
            ret_1 = ovsvapp_db.update_and_get_cluster_lock('fake_vcenter',
                                                           'fake_cluster')
        self.assertEqual('1', ret_1)
        self.assertTrue(info_log.called)

    def test_update_and_get_cluster_lock_threshold_reached(self):
        ret = ovsvapp_db.update_and_get_cluster_lock('fake_vcenter',
                                                     'fake_cluster')
        self.assertEqual('1', ret)
        ovsvapp_db.set_cluster_threshold('fake_vcenter', 'fake_cluster')
        with mock.patch('networking_vsphere.db.ovsvapp_db.'
                        'LOG.warning') as warn_log:
            ret_1 = ovsvapp_db.update_and_get_cluster_lock('fake_vcenter',
                                                           'fake_cluster')
        self.assertEqual('-1', ret_1)
        self.assertTrue(warn_log.called)
