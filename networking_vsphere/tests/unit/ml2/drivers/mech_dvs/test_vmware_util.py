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

import contextlib
import mock
import mox
import unittest

from neutron.plugins.ml2.drivers.mech_dvs import vmware_util
from neutron.tests.unit.ml2.drivers.mech_dvs import fake


class VMWareUtilTestCase(unittest.TestCase):
    def setUp(self):
        super(VMWareUtilTestCase, self).setUp()

    def test_get_datacenter(self):
        with mock.patch.object(vmware_util.VMWareUtil, "_create_session"):
            _util = vmware_util.VMWareUtil()
            with mock.patch.object(_util, "_session") as mock_session:
                with mock.patch.object(mock_session,
                                       "invoke_api") as mock_invoke_api:
                    fake_dc = fake.Datacenter("mydc")
                    fake_obj_content = fake.ObjectContent(fake_dc)
                    result = fake.FakeRetrieveResult()
                    result.add_object(fake_obj_content)
                    mock_invoke_api.return_value = result
                    r = _util.get_datacenter()
                    self.assertEqual("mydc", r.name, "Got Datacenter Failure!")

    def test_get_network_folder(self):
        with mock.patch.object(vmware_util.VMWareUtil, "_create_session"):
            _util = vmware_util.VMWareUtil()
            _util.get_datacenter = mock.Mock()
            with mock.patch.object(_util, "_session") as mock_session:
                with mock.patch.object(mock_session,
                                       "invoke_api") as mock_invoke_api:
                    fake_net_folder = fake.NetworkFolder("netfolder")
                    mock_invoke_api.return_value = fake_net_folder
                    r = _util.get_network_folder()
                    self.assertTrue(_util.get_datacenter.called,
                                    "Needed Function Not Called!")
                    self.assertEqual("netfolder", r.value,
                                     "Got Network Folder Failure!")

    def test_get_dvs(self):
        with mock.patch.object(vmware_util.VMWareUtil, "_create_session"):
            _util = vmware_util.VMWareUtil()
            _util.get_network_folder = mock.Mock()
            with mock.patch.object(_util,
                                   "_session") as mock_session:
                m = mox.Mox()
                m.StubOutWithMock(mock_session, "invoke_api")
                fake_net = fake.Network("net1")
                fake_dvpg = fake.DistributedVirtualPortgroup("dvpg1")
                fake_dvs = fake.VmwareDistributedVirtualSwitch("dvs1")
                results = fake.ResultCollection()
                results.reset()
                results.add(fake_net)
                results.add(fake_dvpg)
                results.add(fake_dvs)
                mock_session.invoke_api(mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg()).AndReturn(results)
                mock_session.invoke_api(mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg()).AndReturn("dvs1")
                m.ReplayAll()
                r = _util.get_dvs("dvs1")
                self.assertTrue(_util.get_network_folder.called,
                                "Method Needed Not Called!")
                self.assertEqual(fake_dvs, r, "Got DVS Failure!")

    def test_get_dvpg_by_name(self):
        with mock.patch.object(vmware_util.VMWareUtil, "_create_session"):
            _util = vmware_util.VMWareUtil()
            _util.get_datacenter = mock.Mock()
            with mock.patch.object(_util,
                                   "_session") as mock_session:
                m = mox.Mox()
                m.StubOutWithMock(mock_session, "invoke_api")
                fake_net = fake.Network("net1")
                fake_dvpg = fake.DistributedVirtualPortgroup("dvpg1")
                fake_dvs = fake.VmwareDistributedVirtualSwitch("dvs1")
                results = fake.ResultCollection()
                results.reset()
                results.add(fake_net)
                results.add(fake_dvpg)
                results.add(fake_dvs)
                mock_session.invoke_api(mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg()).AndReturn(results)
                mock_session.invoke_api(mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg()).AndReturn("dvpg1")
                m.ReplayAll()
                r = _util.get_dvpg_by_name("dvpg1")
                self.assertTrue(_util.get_datacenter.called,
                                "Method Needed Not Called!")
                self.assertEqual(fake_dvpg, r, "Got DV Portgroup Failure!")

    def test_get_dvpg_by_name_negative(self):
        with mock.patch.object(vmware_util.VMWareUtil, "_create_session"):
            _util = vmware_util.VMWareUtil()
            _util.get_datacenter = mock.Mock()
            with mock.patch.object(_util,
                                   "_session") as mock_session:
                m = mox.Mox()
                m.StubOutWithMock(mock_session, "invoke_api")
                fake_net = fake.Network("net1")
                fake_dvpg = fake.DistributedVirtualPortgroup("dvpg1")
                fake_dvs = fake.VmwareDistributedVirtualSwitch("dvs1")
                results = fake.ResultCollection()
                results.reset()
                results.add(fake_net)
                results.add(fake_dvpg)
                results.add(fake_dvs)
                mock_session.invoke_api(mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg()).AndReturn(results)
                mock_session.invoke_api(mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg(), mox.IgnoreArg(),
                                        mox.IgnoreArg()).AndReturn("dvpg1")
                m.ReplayAll()
                r = _util.get_dvpg_by_name("dvpg2")
                self.assertTrue(_util.get_datacenter.called,
                                "Method Needed Not Called!")
                self.assertEqual(None, r, "Got DV Portgroup Failure!")

    def test_create_dvpg(self):
        with mock.patch.object(vmware_util.VMWareUtil, "_create_session"):
            _util = vmware_util.VMWareUtil()
            with contextlib.nested(
                mock.patch.object(_util, "_session"),
                mock.patch.object(_util, "get_dvs"),
                mock.patch.object(_util, "build_pg_spec"),
                mock.patch.object(vmware_util, "CONF")
            ) as (mock_session, fake_get_dvs, fake_build_pg_spec, mock_conf):
                with contextlib.nested(
                    mock.patch.object(mock_session, "invoke_api"),
                    mock.patch.object(mock_session, "wait_for_task")
                ) as (mock_invoke_api, mock_wait_for_task):
                    mock_conf.ml2_vmware.network_maps = ["physnet1:dvSwitch"]
                    fake_context = fake.NetworkContext()
                    fake_net = {"name": "net1",
                                "id": "847f6079-dc07-4445-9e2a-17d16278cc90"}
                    fake_segms = [{"network_type": "vlan",
                                   "physical_network": "physnet1",
                                   "segmentation_id": 100}]
                    fake_context.set("current", fake_net)
                    fake_context.set("network_segments", fake_segms)
                    fake_get_dvs.return_value = mock_dvs = mock.Mock()
                    fake_build_pg_spec.return_value = mock_spec = mock.Mock()
                    mock_invoke_api.return_value = mock_task = mock.Mock()
                    _util.create_dvpg(fake_context)
                    fake_get_dvs.assert_called_with("dvSwitch")
                    fake_build_pg_spec.assert_called_once()
                    mock_invoke_api.assert_called_with(
                        mock_session.vim,
                        "CreateDVPortgroup_Task",
                        mock_dvs,
                        spec=mock_spec)
                    mock_wait_for_task.assert_called_with(mock_task)

    def test_delete_dvpg(self):
        with mock.patch.object(vmware_util.VMWareUtil, "_create_session"):
            _util = vmware_util.VMWareUtil()
            with contextlib.nested(
                mock.patch.object(_util, "_session"),
                mock.patch.object(_util, "get_dvpg_by_name"),
            ) as (mock_session, fake_get_dvpg_by_name):
                with contextlib.nested(
                    mock.patch.object(mock_session, "invoke_api"),
                    mock.patch.object(mock_session, "wait_for_task")
                ) as (mock_invoke_api, mock_wait_for_task):
                    fake_context = fake.NetworkContext()
                    fake_net = {"name": "net1",
                                "id": "847f6079-dc07-4445-9e2a-17d16278cc90"}
                    fake_segms = [{"network_type": "vlan",
                                   "physical_network": "physnet1",
                                   "segmentation_id": 100}]
                    fake_context.set("current", fake_net)
                    fake_context.set("network_segments", fake_segms)
                    fake_get_dvpg_by_name.return_value = mock_dvpg \
                                                       = mock.Mock()
                    mock_invoke_api.return_value = mock_task = mock.Mock()
                    _util.delete_dvpg(fake_context)
                    fake_get_dvpg_by_name.assert_called_with(
                        "%(name)s-%(id)s" % fake_net)
                    mock_invoke_api.assert_called_with(mock_session.vim,
                                                       "Destroy_Task",
                                                       mock_dvpg)
                    mock_wait_for_task.assert_called_with(mock_task)

    def test_update_dvpg(self):
        with mock.patch.object(vmware_util.VMWareUtil, "_create_session"):
            _util = vmware_util.VMWareUtil()
            with contextlib.nested(
                mock.patch.object(_util, "_session"),
                mock.patch.object(_util, "get_dvpg_by_name"),
            ) as (mock_session, fake_get_dvpg_by_name):
                with contextlib.nested(
                    mock.patch.object(mock_session, "invoke_api"),
                    mock.patch.object(mock_session, "wait_for_task")
                ) as (mock_invoke_api, mock_wait_for_task):
                    fake_context = fake.NetworkContext()
                    fake_net = {"name": "net1",
                                "id": "847f6079-dc07-4445-9e2a-17d16278cc90"}
                    fake_net_orig = {
                        "name": "net-orig",
                        "id": "847f6079-dc07-4445-9e2a-17d16278cc91"}
                    fake_segms = [{"network_type": "vlan",
                                   "physical_network": "physnet1",
                                   "segmentation_id": 100}]
                    fake_context.set("current", fake_net)
                    fake_context.set("original", fake_net_orig)
                    fake_context.set("network_segments", fake_segms)
                    current_name = "%(name)s-%(id)s" % fake_net
                    orig_name = "%(name)s-%(id)s" % fake_net_orig
                    fake_get_dvpg_by_name.return_value = mock_dvpg \
                                                       = mock.Mock()
                    mock_invoke_api.return_value = mock_task = mock.Mock()
                    _util.update_dvpg(fake_context)
                    fake_get_dvpg_by_name.assert_called_with(orig_name)
                    mock_invoke_api.assert_called_with(mock_session.vim,
                                                       "Rename_Task",
                                                       mock_dvpg,
                                                       newName=current_name)
                    mock_wait_for_task.assert_called_with(mock_task)
