# Copyright (c) 2016 Hewlett-Packard Development Company, L.P.
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
import uuid

from oslo_concurrency import lockutils
from oslo_config import fixture as config_fixture
from oslo_utils import uuidutils
from oslo_vmware import vim_util as vutil
from oslotest import moxstubout

from networking_vsphere.nova.virt.vmwareapi import ovsvapp_vc_driver

from nova.compute import power_state
from nova import context
from nova import exception
from nova.image import glance
from nova import objects
from nova import test
from nova.tests.unit import fake_instance
from nova.tests.unit.image import fake as image_fake
from nova.tests.unit import test_flavors
from nova.tests.unit import utils
from nova.tests.unit.virt.vmwareapi import fake as vmwareapi_fake
from nova.tests.unit.virt.vmwareapi import stubs
from nova.virt.vmwareapi import vm_util


NETWORK_NAME = str(uuid.uuid4())
PG_KEY = str(uuid.uuid4())
SWITCH_UUID = str(uuid.uuid4())


class DistributedVirtualPortgroup(vmwareapi_fake.ManagedObject):
    """DistributedVirtualPortgroup fake class."""
    def __init__(self):
        super(DistributedVirtualPortgroup, self).__init__(
            "DistributedVirtualPortgroup")
        config = vmwareapi_fake.DataObject()
        config.key = PG_KEY
        config.name = NETWORK_NAME
        self.set("config", config)


class VmwareDistributedVirtualSwitch(vmwareapi_fake.ManagedObject):
    """VmwareDistributedVirtualSwitch fake class."""
    def __init__(self):
        super(VmwareDistributedVirtualSwitch, self).__init__(
            "VmwareDistributedVirtualSwitch")
        self.set("uuid", SWITCH_UUID)
        pg = (vmwareapi_fake.
              _db_content["DistributedVirtualPortgroup"].values()[0])
        pg_config = pg.config
        pg_config.distributedVirtualSwitch = self.obj
        pg_object = vmwareapi_fake.DataObject()
        pg_object.ManagedObjectReference = [pg]
        self.set("portgroup", pg_object)


def create_distributed_virtual_portgroup():
    pg = DistributedVirtualPortgroup()
    vmwareapi_fake._create_object("DistributedVirtualPortgroup", pg)


def create_distributed_virtual_switch():
    dvs = VmwareDistributedVirtualSwitch()
    vmwareapi_fake._create_object("VmwareDistributedVirtualSwitch", dvs)


def reset_fakes():
    vmwareapi_fake.reset()
    vmwareapi_fake._db_content["DistributedVirtualPortgroup"] = {}
    vmwareapi_fake._db_content["VmwareDistributedVirtualSwitch"] = {}
    create_distributed_virtual_portgroup()
    create_distributed_virtual_switch()

    # Add DistributedVirtualPortgroup reference to existing HostSystem Object
    host_ref = (vmwareapi_fake._db_content["HostSystem"]
                [vmwareapi_fake._db_content["HostSystem"].keys()[0]])
    for prop in host_ref.propSet:
        if prop.name == "network":
            net_key = (vmwareapi_fake.
                       _db_content["DistributedVirtualPortgroup"].keys()[0])
            net_ref = (vmwareapi_fake.
                       _db_content["DistributedVirtualPortgroup"][net_key].obj)
            prop.val.ManagedObjectReference.append(net_ref)
            break


class OVSvAppVCDriverTestCase(test.TestCase):
    """Test Cases for ovsvapp_vc_driver.OVSvAppVCDriver."""

    def setUp(self):
        super(OVSvAppVCDriverTestCase, self).setUp()
        self.fixture = self.useFixture(config_fixture.Config(lockutils.CONF))
        self.fixture.config(disable_process_locking=True,
                            group='oslo_concurrency')
        self.user_id = 'test_user_id'
        self.project_id = 'test_project_id'
        self.context = context.RequestContext(self.user_id, self.project_id,
                                              is_admin=False)
        reset_fakes()
        vm_util.vm_refs_cache_reset()
        stubs.set_stubs(self)
        image_fake.stub_out_image_service(self)
        image_ref = image_fake.get_valid_image_id()
        (image_service, image_id) = glance.get_remote_image_service(
            self.context, image_ref)
        metadata = image_service.show(self.context, image_id)
        self.image = {
            'id': image_ref,
            'disk_format': 'vmdk',
            'size': int(metadata['size']),
        }
        self.fake_image_uuid = self.image['id']
        self.image = objects.ImageMeta.from_dict(self.image)
        self.vnc_host = 'ha-host'
        self.flags(host_ip='test_url',
                   host_username='test_username',
                   host_password='test_pass',
                   use_linked_clone=False,
                   cluster_name='test_cluster',
                   task_poll_interval=10, datastore_regex='.*',
                   vmwareapi_nic_attach_retry_count=1,
                   group='vmware')
        self.flags(enabled=False, group='vnc')
        self.flags(image_cache_subdirectory_name='vmware_base',
                   my_ip='')
        self.vnc_host = 'ha-host'
        self.conn = ovsvapp_vc_driver.OVSvAppVCDriver(None)
        self.node_name = self.conn._nodename
        mox_fixture = self.useFixture(moxstubout.MoxStubout())
        self.mox = mox_fixture.mox

    def _get_network_info(self, network_id=NETWORK_NAME):
        """Gets network_info from the test utils and then change the network id

           which is set to None. This should not not be None as this id is

           same as portgroup name.

           """
        network_info = utils.get_test_network_info(1)
        network_info[0]['network']['id'] = network_id
        return network_info

    def _get_instance_type_by_name(self, type):
        for instance_type in test_flavors.DEFAULT_FLAVORS:
            if instance_type['name'] == type:
                return instance_type
        if type == 'm1.micro':
            return {'memory_mb': 128, 'root_gb': 0, 'deleted_at': None,
                    'name': 'm1.micro', 'deleted': 0, 'created_at': None,
                    'ephemeral_gb': 0, 'updated_at': None,
                    'disabled': False, 'vcpus': 1, 'extra_specs': {},
                    'swap': 0, 'rxtx_factor': 1.0, 'is_public': True,
                    'flavorid': '1', 'vcpu_weight': None, 'id': 2}

    def _create_instance(self, node=None, set_image_ref=True,
                         uuid=None, instance_type='m1.large',
                         ephemeral=None, instance_type_updates=None):
        if not node:
            node = self.node_name
        if not uuid:
            uuid = uuidutils.generate_uuid()
        self.type_data = self._get_instance_type_by_name(instance_type)
        if instance_type_updates:
            self.type_data.update(instance_type_updates)
        if ephemeral is not None:
            self.type_data['ephemeral_gb'] = ephemeral
        values = {'name': 'fake_name',
                  'id': 1,
                  'uuid': uuid,
                  'project_id': self.project_id,
                  'user_id': self.user_id,
                  'kernel_id': "fake_kernel_uuid",
                  'ramdisk_id': "fake_ramdisk_uuid",
                  'mac_address': "de:ad:be:ef:be:ef",
                  'Flavor': instance_type,
                  'node': node,
                  'memory_mb': self.type_data['memory_mb'],
                  'root_gb': self.type_data['root_gb'],
                  'ephemeral_gb': self.type_data['ephemeral_gb'],
                  'vcpus': self.type_data['vcpus'],
                  'swap': self.type_data['swap'],
                  'expected_attrs': ['system_metadata'],
                  }
        if set_image_ref:
            values['image_ref'] = self.fake_image_uuid
        self.instance_node = node
        self.uuid = uuid
        self.instance = fake_instance.fake_instance_obj(
            self.context, **values)
        self.instance.flavor = objects.Flavor(**self.type_data)

    def _create_vm(self, node=None, num_instances=1, uuid=None,
                   instance_type='m1.large', powered_on=True,
                   ephemeral=None, bdi=None, instance_type_updates=None):
        """Create and spawn the VM."""
        if not node:
            node = self.node_name
        self._create_instance(node=node, uuid=uuid,
                              instance_type=instance_type,
                              ephemeral=ephemeral,
                              instance_type_updates=instance_type_updates)
        self.assertIsNone(vm_util.vm_ref_cache_get(self.uuid))
        self.conn.spawn(self.context, self.instance, self.image,
                        injected_files=[], admin_password=None,
                        network_info=self.network_info,
                        block_device_info=bdi)
        self._check_vm_record(num_instances=num_instances,
                              powered_on=powered_on,
                              uuid=uuid)
        self.assertIsNotNone(vm_util.vm_ref_cache_get(self.uuid))

    def _get_vm_record(self):
        # Get record for VM
        vms = vmwareapi_fake._get_objects("VirtualMachine")
        for vm in vms.objects:
            if vm.get('name') == self.uuid:
                return vm
        self.fail('Unable to find VM backing!')

    def _get_info(self, uuid=None, node=None, name=None):
        uuid = uuid if uuid else self.uuid
        node = node if node else self.instance_node
        name = name if node else '1'
        return self.conn.get_info(fake_instance.fake_instance_obj(
            None,
            **{'uuid': uuid,
               'name': name,
               'node': node}))

    def _check_vm_record(self, num_instances=1, powered_on=True, uuid=None):
        """Check if the spawned VM's properties correspond to the instance in

           the db.

           """
        instances = self.conn.list_instances()
        if uuidutils.is_uuid_like(uuid):
            self.assertEqual(len(instances), num_instances)

        # Get Nova record for VM
        vm_info = self._get_info()
        vm = self._get_vm_record()

        # Check that m1.large above turned into the right thing.
        mem_kib = long(self.type_data['memory_mb']) << 10
        vcpus = self.type_data['vcpus']
        self.assertEqual(vm_info.max_mem_kb, mem_kib)
        self.assertEqual(vm_info.mem_kb, mem_kib)
        self.assertEqual(vm.get("summary.config.instanceUuid"), self.uuid)
        self.assertEqual(vm.get("summary.config.numCpu"), vcpus)
        self.assertEqual(vm.get("summary.config.memorySizeMB"),
                         self.type_data['memory_mb'])

        if vm.get("config.hardware.device").VirtualDevice:
            self.assertEqual(
                vm.get("config.hardware.device").VirtualDevice[2].obj_name,
                "ns0:VirtualE1000")
        if powered_on:
            # Check that the VM is running according to Nova
            self.assertEqual(power_state.RUNNING, vm_info.state)

            # Check that the VM is running according to vSphere API.
            self.assertEqual('poweredOn', vm.get("runtime.powerState"))
        else:
            # Check that the VM is not running according to Nova
            self.assertEqual(power_state.SHUTDOWN, vm_info.state)

            # Check that the VM is not running according to vSphere API.
            self.assertEqual('poweredOff', vm.get("runtime.powerState"))

        found_vm_uuid = False
        found_iface_id = False
        extras = vm.get("config.extraConfig")
        for c in extras.OptionValue:
            if (c.key == "nvp.vm-uuid" and c.value == self.instance['uuid']):
                found_vm_uuid = True
            if (c.key == "nvp.iface-id.0" and c.value == "vif-xxx-yyy-zzz"):
                found_iface_id = True

        self.assertTrue(found_vm_uuid)
        if vm.get("config.hardware.device").VirtualDevice:
            self.assertTrue(found_iface_id)

    def _check_vm_info(self, info, pwr_state=power_state.RUNNING):
        """Check if the get_info returned values correspond to the instance

           object in the db.

           """
        mem_kib = long(self.type_data['memory_mb']) << 10
        self.assertEqual(info.state, pwr_state)
        self.assertEqual(info.max_mem_kb, mem_kib)
        self.assertEqual(info.mem_kb, mem_kib)
        self.assertEqual(info.num_cpu, self.type_data['vcpus'])

    def test_create_vm_with_nic(self):
        """Creates a VM with network.VM should be

           created with a NIC and should be powered on.

           """
        self.network_info = self._get_network_info()
        self._create_vm()
        info = self._get_info()
        self._check_vm_info(info, power_state.RUNNING)

    def _spawn_power_state(self, power_on):
        self._spawn = self.conn._vmops.spawn
        self._power_on = power_on

        def _fake_spawn(context, instance, image_meta, injected_files,
                        admin_password, network_info, block_device_info=None,
                        power_on=True):
            return self._spawn(context, instance, image_meta,
                               injected_files, admin_password, network_info,
                               block_device_info=block_device_info,
                               power_on=self._power_on)

        with (
            mock.patch.object(self.conn._vmops, 'spawn', _fake_spawn)
        ):
            self._create_vm(powered_on=power_on)
            info = self._get_info()
            if power_on:
                self._check_vm_info(info, power_state.RUNNING)
            else:
                self._check_vm_info(info, power_state.SHUTDOWN)

    def test_create_vm_powered_off_without_nic(self):
        self.network_info = None
        self._spawn_power_state(False)

    def test_create_vm_powered_on_without_nic(self):
        self.network_info = None
        self._spawn_power_state(True)

    def test_create_vm_with_invalid_portgroup(self):
        """Creates a VM with network but portgroup does not exists on ESX.

           NetworkNotCreated Exception would be raised.

           """
        self.network_info = self._get_network_info(
            network_id="expected_network")
        self.assertRaises(exception.NetworkNotCreated, self._create_vm)

    def test_wait_and_get_portgroup_details_None(self):
        cfg = ovsvapp_vc_driver.CONF
        orig_cnt = cfg.vmware.vmwareapi_nic_attach_retry_count
        cfg.vmware.vmwareapi_nic_attach_retry_count = -1
        self.network_info = None
        self._create_vm()
        vss = vmwareapi_fake._get_objects("Network").objects[0]
        vm_ref = vmwareapi_fake._get_objects("VirtualMachine").objects[0].obj
        network_obj = (self.conn._wait_and_get_portgroup_details
                       (self.conn._session, vm_ref, vss.get('summary.name'),
                        self.instance))
        self.assertTrue(network_obj is None)
        cfg.vmware.vmwareapi_nic_attach_retry_count = orig_cnt

    def test_wait_and_get_portgroup_details_None_networks(self):
        self.network_info = None
        self._create_vm()
        vm_ref = vmwareapi_fake._db_content["VirtualMachine"].values()[0]
        host = vmwareapi_fake._db_content["HostSystem"].values()[0]
        vss = vmwareapi_fake._db_content["Network"].values()[0]
        vss._type = "Network"
        networks = vmwareapi_fake.DataObject()
        networks.ManagedObjectReference = []

        with mock.patch.object(vutil, "get_object_property",
                               return_value=host) as mock_get_host, \
                mock.patch.object(vutil, "get_object_property",
                                  return_value=networks) as mock_get_network:
            mock_get_host.assert_called_once_with(mock.ANY,
                                                  vm_ref,
                                                  "runtime.host")
            mock_get_network.assert_called_once_with(mock.ANY,
                                                     host,
                                                     "network")
        network_obj = self.conn._wait_and_get_portgroup_details(
            self.conn._session, vm_ref, vss.get('summary.name'), self.instance)
        self.assertTrue(network_obj is None)

    def test_wait_and_get_portgroup_details_some_network_type(self):
        self.network_info = None
        self._create_vm()
        vm_ref = vmwareapi_fake._db_content["VirtualMachine"].values()[0]
        host = vmwareapi_fake._db_content["HostSystem"].values()[0]
        vss = vmwareapi_fake._db_content["Network"].values()[0]
        vss._type = "some_Network"
        networks = vmwareapi_fake.DataObject()
        networks.ManagedObjectReference = [vss]

        with mock.patch.object(vutil, "get_object_property",
                               return_value=host) as mock_get_host, \
                mock.patch.object(vutil, "get_object_property",
                                  return_value=networks) as mock_get_network:
            mock_get_host.assert_called_once_with(mock.ANY,
                                                  vm_ref,
                                                  "runtime.host")
            mock_get_network.assert_called_once_with(mock.ANY,
                                                     host,
                                                     "network")
        network_obj = (self.conn._wait_and_get_portgroup_details
                       (self.conn._session, vm_ref, vss.get('summary.name'),
                        self.instance))
        self.assertTrue(network_obj is None)

    def test_wait_and_get_portgroup_details_with_network(self):
        self.network_info = None
        self._create_vm()
        mocked_props = mock.Mock()
        mocked_props.name = "pg2"
        mocked_dvs_props = mock.Mock()
        vm_ref = vmwareapi_fake._db_content["VirtualMachine"].values()[0]
        host = vmwareapi_fake._db_content["HostSystem"].values()[0]
        vss = vmwareapi_fake._db_content["Network"].values()[0]
        vss._type = "DistributedVirtualPortgroup"
        networks = vmwareapi_fake.DataObject()
        vss2 = vmwareapi_fake._db_content["Network"].values()[0]
        vss2._type = "DistributedVirtualPortgroup"
        vss2.set("summary.name", ["pg1", "pg2"])
        networks.ManagedObjectReference = [vss, vss2]

        with mock.patch.object(vutil, "get_object_property",
                               return_value=host) as mock_get_host, \
                mock.patch.object(vutil, "get_object_property",
                                  return_value=networks) as mock_get_network, \
                mock.patch.object(vutil, "get_object_property",
                                  return_value=mocked_props
                                  ) as mock_get_props, \
                mock.patch.object(vutil, "get_object_property",
                                  return_value=mocked_dvs_props
                                  ) as mock_get_dvs_props:
            mock_get_host.assert_called_once_with(mock.ANY,
                                                  vm_ref,
                                                  "runtime.host")
            mock_get_network.assert_called_once_with(mock.ANY,
                                                     host,
                                                     "network")
            mock_get_props.assert_called_once_with(mock.ANY,
                                                   vss,
                                                   "config")
            mock_get_dvs_props.assert_called_once_with(
                mock.ANY, mocked_props.distributedVirtualSwitch, "uuid")
        network_obj = (self.conn._wait_and_get_portgroup_details
                       (self.conn._session, vm_ref, vss.get('summary.name'),
                        self.instance))
        self.assertTrue(network_obj is not None)

    def test_create_vm_portgroup_None(self):
        """Creates a VM with network_info as None.VM should be

           created without a NIC and should be powered on.

           """
        self.network_info = self._get_network_info()
        self.stubs.Set(self.conn, "_wait_and_get_portgroup_details",
                       lambda *args, **kwargs: None)
        try:
            self._create_vm()
        except exception.NetworkNotCreated:
            pass
        else:
            self.fail('Exception not raised')

    def test_network_binding_host_id(self):
        expected = None
        host_id = self.conn.network_binding_host_id(self.context,
                                                    fake_instance)
        self.assertEqual(expected, host_id)

    def test_get_mo_id_from_instance(self):
        cluster_moid = "domain-1001"
        vcenter_uuid = "14594e20-5f0c-44ae-b5db-253ccf711483"
        node_name = '%s.%s' % (cluster_moid, vcenter_uuid)
        self._create_instance(node=node_name)
        actual = self.conn._get_mo_id_from_instance(self.instance)
        self.assertEqual(cluster_moid, actual)

    def tearDown(self):
        super(OVSvAppVCDriverTestCase, self).tearDown()
        vmwareapi_fake.cleanup()
