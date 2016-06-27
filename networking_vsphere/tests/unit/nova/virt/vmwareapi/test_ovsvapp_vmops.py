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
from oslo_utils import units
from oslo_utils import uuidutils
from oslo_vmware import vim_util as vutil
import six

from nova import context
from nova import exception
from nova import objects
from nova import test
from nova.tests.unit import fake_instance
import nova.tests.unit.image.fake
from nova.tests.unit.virt.vmwareapi import fake as vmwareapi_fake
from nova import version
from nova.virt.vmwareapi import constants
from nova.virt.vmwareapi import driver
from nova.virt.vmwareapi import ds_util
from nova.virt.vmwareapi import images
from nova.virt.vmwareapi import vm_util
from nova.virt.vmwareapi import vmops

from networking_vsphere.nova.virt.vmwareapi import ovsvapp_vmops


class OVSvAppVMOpsTestCase(test.NoDBTestCase):
    def setUp(self):
        super(OVSvAppVMOpsTestCase, self).setUp()
        fake_ds_ref = vmwareapi_fake.ManagedObjectReference('fake-ds')
        vmwareapi_fake.reset()
        cluster = vmwareapi_fake.create_cluster('fake_cluster', fake_ds_ref)
        self.flags(enabled=True, group='vnc')
        self.flags(image_cache_subdirectory_name='vmware_base',
                   my_ip='',
                   flat_injected=True)
        self._context = context.RequestContext('fake_user', 'fake_project')
        self._session = driver.VMwareAPISession()

        self._virtapi = mock.Mock()
        self._image_id = nova.tests.unit.image.fake.get_valid_image_id()
        self._instance_values = {
            'name': 'fake_name',
            'display_name': 'fake_display_name',
            'uuid': self._uuid,
            'vcpus': 1,
            'memory_mb': 512,
            'image_ref': self._image_id,
            'root_gb': 10,
            'node': '%s(%s)' % (cluster.mo_id, cluster.name),
            'expected_attrs': ['system_metadata'],
        }
        self._instance = fake_instance.fake_instance_obj(
            self._context, **self._instance_values)
        self._image_meta = objects.ImageMeta.from_dict({'id': self._image_id})
        self._flavor = objects.Flavor(name='m1.small', memory_mb=512, vcpus=1,
                                      root_gb=10, ephemeral_gb=0, swap=0,
                                      extra_specs={})
        self._instance.flavor = self._flavor
        self._vmops = ovsvapp_vmops.OVSvAppVMOps(self._session, self._virtapi,
                                                 None, cluster=cluster.obj)

    def _get_metadata(self, is_image_used=True):
        if is_image_used:
            image_id = '70a599e0-31e7-49b7-b260-868f441e862b'
        else:
            image_id = None
        return ("name:fake_display_name\n"
                "userid:fake_user\n"
                "username:None\n"
                "projectid:fake_project\n"
                "projectname:None\n"
                "flavor:name:m1.small\n"
                "flavor:memory_mb:512\n"
                "flavor:vcpus:1\n"
                "flavor:ephemeral_gb:0\n"
                "flavor:root_gb:10\n"
                "flavor:swap:0\n"
                "imageid:%(image_id)s\n"
                "package:%(version)s\n" % {
                    'image_id': image_id,
                    'version': version.version_string_with_package()})

    @mock.patch.object(vm_util, 'rename_vm')
    @mock.patch.object(vmops.VMwareVMOps, '_create_folders',
                       return_value='fake_vm_folder')
    @mock.patch('nova.virt.vmwareapi.vm_util.power_on_instance')
    @mock.patch.object(vmops.VMwareVMOps, '_use_disk_image_as_linked_clone')
    @mock.patch.object(vmops.VMwareVMOps, '_fetch_image_if_missing')
    @mock.patch(
        'nova.virt.vmwareapi.imagecache.ImageCacheManager.enlist_image')
    @mock.patch.object(vmops.VMwareVMOps, 'build_virtual_machine')
    @mock.patch.object(vmops.VMwareVMOps, '_get_vm_config_info')
    @mock.patch.object(vmops.VMwareVMOps, '_get_extra_specs')
    @mock.patch.object(nova.virt.vmwareapi.images.VMwareImage,
                       'from_image')
    def test_spawn_non_root_block_device(self, from_image,
                                         get_extra_specs,
                                         get_vm_config_info,
                                         build_virtual_machine,
                                         enlist_image, fetch_image,
                                         use_disk_image,
                                         power_on_instance,
                                         create_folders,
                                         rename_vm):
        self._instance.flavor = self._flavor
        extra_specs = get_extra_specs.return_value
        connection_info1 = {'data': 'fake-data1', 'serial': 'volume-fake-id1'}
        connection_info2 = {'data': 'fake-data2', 'serial': 'volume-fake-id2'}
        bdm = [{'connection_info': connection_info1,
                'disk_bus': constants.ADAPTER_TYPE_IDE,
                'mount_device': '/dev/sdb'},
               {'connection_info': connection_info2,
                'disk_bus': constants.DEFAULT_ADAPTER_TYPE,
                'mount_device': '/dev/sdc'}]
        bdi = {'block_device_mapping': bdm, 'root_device_name': '/dev/sda'}
        self.flags(flat_injected=False)
        self.flags(enabled=False, group='vnc')

        image_size = (self._instance.root_gb) * units.Gi / 2
        image_info = images.VMwareImage(image_id=self._image_id,
                                        file_size=image_size)
        vi = get_vm_config_info.return_value
        from_image.return_value = image_info
        build_virtual_machine.return_value = 'fake-vm-ref'
        with mock.patch.object(self._vmops, '_volumeops') as volumeops:
            self._vmops.spawn(self._context, self._instance, self._image_meta,
                              injected_files=None, admin_password=None,
                              network_info=[], block_device_info=bdi)

            from_image.assert_called_once_with(self._instance.image_ref,
                                               self._image_meta)
            get_vm_config_info.assert_called_once_with(self._instance,
                                                       image_info, extra_specs)
            build_virtual_machine.assert_called_once_with(self._instance,
                                                          image_info,
                                                          vi.dc_info,
                                                          vi.datastore, [],
                                                          extra_specs,
                                                          self._get_metadata())
            enlist_image.assert_called_once_with(image_info.image_id,
                                                 vi.datastore, vi.dc_info.ref)
            fetch_image.assert_called_once_with(self._context, vi)
            use_disk_image.assert_called_once_with('fake-vm-ref', vi)
            volumeops.attach_volume.assert_any_call(
                connection_info1, self._instance, constants.ADAPTER_TYPE_IDE)
            volumeops.attach_volume.assert_any_call(
                connection_info2, self._instance,
                constants.DEFAULT_ADAPTER_TYPE)

    @mock.patch.object(vm_util, 'rename_vm')
    @mock.patch.object(vmops.VMwareVMOps, '_create_folders',
                       return_value='fake_vm_folder')
    @mock.patch('nova.virt.vmwareapi.vm_util.power_on_instance')
    @mock.patch.object(vmops.VMwareVMOps, 'build_virtual_machine')
    @mock.patch.object(vmops.VMwareVMOps, '_get_vm_config_info')
    @mock.patch.object(vmops.VMwareVMOps, '_get_extra_specs')
    @mock.patch.object(nova.virt.vmwareapi.images.VMwareImage,
                       'from_image')
    def test_spawn_with_no_image_and_block_devices(self, from_image,
                                                   get_extra_specs,
                                                   get_vm_config_info,
                                                   build_virtual_machine,
                                                   power_on_instance,
                                                   create_folders,
                                                   rename_vm):
        self._instance.image_ref = None
        self._instance.flavor = self._flavor
        extra_specs = get_extra_specs.return_value

        connection_info1 = {'data': 'fake-data1', 'serial': 'volume-fake-id1'}
        connection_info2 = {'data': 'fake-data2', 'serial': 'volume-fake-id2'}
        connection_info3 = {'data': 'fake-data3', 'serial': 'volume-fake-id3'}
        bdm = [{'boot_index': 0,
                'connection_info': connection_info1,
                'disk_bus': constants.ADAPTER_TYPE_IDE},
               {'boot_index': 1,
                'connection_info': connection_info2,
                'disk_bus': constants.DEFAULT_ADAPTER_TYPE},
               {'boot_index': 2,
                'connection_info': connection_info3,
                'disk_bus': constants.ADAPTER_TYPE_LSILOGICSAS}]
        bdi = {'block_device_mapping': bdm}
        self.flags(flat_injected=False)
        self.flags(enabled=False, group='vnc')

        image_info = mock.sentinel.image_info
        vi = get_vm_config_info.return_value
        from_image.return_value = image_info
        build_virtual_machine.return_value = 'fake-vm-ref'

        with mock.patch.object(self._vmops, '_volumeops') as volumeops:
            self._vmops.spawn(self._context, self._instance, self._image_meta,
                              injected_files=None, admin_password=None,
                              network_info=[], block_device_info=bdi)

            from_image.assert_called_once_with(self._instance.image_ref,
                                               self._image_meta)
            get_vm_config_info.assert_called_once_with(self._instance,
                                                       image_info, extra_specs)
            build_virtual_machine.assert_called_once_with(
                self._instance, image_info, vi.dc_info, vi.datastore, [],
                extra_specs, self._get_metadata(is_image_used=False))
            volumeops.attach_root_volume.assert_called_once_with(
                connection_info1, self._instance, vi.datastore.ref,
                constants.ADAPTER_TYPE_IDE)
            volumeops.attach_volume.assert_any_call(
                connection_info2, self._instance,
                constants.DEFAULT_ADAPTER_TYPE)
            volumeops.attach_volume.assert_any_call(
                connection_info3, self._instance,
                constants.ADAPTER_TYPE_LSILOGICSAS)

    @mock.patch.object(vmops.VMwareVMOps, '_create_folders',
                       return_value='fake_vm_folder')
    @mock.patch('nova.virt.vmwareapi.vm_util.power_on_instance')
    @mock.patch.object(vmops.VMwareVMOps, 'build_virtual_machine')
    @mock.patch.object(vmops.VMwareVMOps, '_get_vm_config_info')
    @mock.patch.object(vmops.VMwareVMOps, '_get_extra_specs')
    @mock.patch.object(nova.virt.vmwareapi.images.VMwareImage,
                       'from_image')
    def test_spawn_unsupported_hardware(self, from_image,
                                        get_extra_specs,
                                        get_vm_config_info,
                                        build_virtual_machine,
                                        power_on_instance,
                                        create_folders):
        self._instance.image_ref = None
        self._instance.flavor = self._flavor
        extra_specs = get_extra_specs.return_value
        connection_info = {'data': 'fake-data', 'serial': 'volume-fake-id'}
        bdm = [{'boot_index': 0,
                'connection_info': connection_info,
                'disk_bus': 'invalid_adapter_type'}]
        bdi = {'block_device_mapping': bdm}
        self.flags(flat_injected=False)
        self.flags(enabled=False, group='vnc')

        image_info = mock.sentinel.image_info
        vi = get_vm_config_info.return_value
        from_image.return_value = image_info
        build_virtual_machine.return_value = 'fake-vm-ref'

        self.assertRaises(exception.UnsupportedHardware, self._vmops.spawn,
                          self._context, self._instance, self._image_meta,
                          injected_files=None,
                          admin_password=None, network_info=[],
                          block_device_info=bdi)

        from_image.assert_called_once_with(self._instance.image_ref,
                                           self._image_meta)
        get_vm_config_info.assert_called_once_with(
            self._instance, image_info, extra_specs)
        build_virtual_machine.assert_called_once_with(
            self._instance, image_info, vi.dc_info, vi.datastore, [],
            extra_specs, self._get_metadata(is_image_used=False))

    def _verify_spawn_method_calls(self, mock_call_method, extras=None):
        # TODO(vui): More explicit assertions of spawn() behavior
        # are waiting on additional refactoring pertaining to image
        # handling/manipulation. Till then, we continue to assert on the
        # sequence of VIM operations invoked.
        expected_methods = ['get_object_property',
                            'SearchDatastore_Task',
                            'CreateVirtualDisk_Task',
                            'DeleteDatastoreFile_Task',
                            'MoveDatastoreFile_Task',
                            'DeleteDatastoreFile_Task',
                            'SearchDatastore_Task',
                            'ExtendVirtualDisk_Task',
                            ]
        if extras:
            expected_methods.extend(extras)

        # Last call should be renaming the instance
        expected_methods.append('Rename_Task')
        recorded_methods = [c[1][1] for c in mock_call_method.mock_calls]
        self.assertEqual(expected_methods, recorded_methods)

    @mock.patch.object(vmops.VMwareVMOps, '_create_folders',
                       return_value='fake_vm_folder')
    @mock.patch(
        'nova.virt.vmwareapi.vmops.VMwareVMOps._update_vnic_index')
    @mock.patch(
        'nova.virt.vmwareapi.vmops.VMwareVMOps._configure_config_drive')
    @mock.patch('nova.virt.vmwareapi.ds_util.get_datastore')
    @mock.patch(
        'nova.virt.vmwareapi.vmops.VMwareVMOps.get_datacenter_ref_and_name')
    @mock.patch('nova.virt.vmwareapi.vif.get_vif_info',
                return_value=[])
    @mock.patch('nova.utils.is_neutron',
                return_value=False)
    @mock.patch('nova.virt.vmwareapi.vm_util.get_vm_create_spec',
                return_value='fake_create_spec')
    @mock.patch('nova.virt.vmwareapi.vm_util.create_vm',
                return_value='fake_vm_ref')
    @mock.patch('nova.virt.vmwareapi.ds_util.mkdir')
    @mock.patch('nova.virt.vmwareapi.vmops.VMwareVMOps._set_machine_id')
    @mock.patch(
        'nova.virt.vmwareapi.imagecache.ImageCacheManager.enlist_image')
    @mock.patch.object(vmops.VMwareVMOps, '_get_and_set_vnc_config')
    @mock.patch('nova.virt.vmwareapi.vm_util.power_on_instance')
    @mock.patch('nova.virt.vmwareapi.vm_util.copy_virtual_disk')
    # TODO(dims): Need to add tests for create_virtual_disk after the
    #             disk/image code in spawn gets refactored
    def _test_spawn(self,
                    mock_copy_virtual_disk,
                    mock_power_on_instance,
                    mock_get_and_set_vnc_config,
                    mock_enlist_image,
                    mock_set_machine_id,
                    mock_mkdir,
                    mock_create_vm,
                    mock_get_create_spec,
                    mock_is_neutron,
                    mock_get_vif_info,
                    mock_get_datacenter_ref_and_name,
                    mock_get_datastore,
                    mock_configure_config_drive,
                    mock_update_vnic_index,
                    mock_create_folders,
                    block_device_info=None,
                    extra_specs=None,
                    config_drive=False):

        if extra_specs is None:
            extra_specs = vm_util.ExtraSpecs()

        image_size = (self._instance.root_gb) * units.Gi / 2
        image = {
            'id': self._image_id,
            'disk_format': 'vmdk',
            'size': image_size,
        }
        image = objects.ImageMeta.from_dict(image)
        image_info = images.VMwareImage(
            image_id=self._image_id,
            file_size=image_size)
        vi = self._vmops._get_vm_config_info(
            self._instance, image_info, extra_specs)

        self._vmops._volumeops = mock.Mock()
        network_info = mock.Mock()
        mock_get_datastore.return_value = self._ds
        mock_get_datacenter_ref_and_name.return_value = self._dc_info
        mock_call_method = mock.Mock(return_value='fake_task')

        if extra_specs is None:
            extra_specs = vm_util.ExtraSpecs()

        with test.nested(
                mock.patch.object(self._session, '_wait_for_task'),
                mock.patch.object(self._session, '_call_method',
                                  mock_call_method),
                mock.patch.object(uuidutils, 'generate_uuid',
                                  return_value='tmp-uuid'),
                mock.patch.object(images, 'fetch_image'),
                mock.patch('nova.image.api.API.get'),
                mock.patch.object(vutil, 'get_inventory_path',
                                  return_value=self._dc_info.name),
                mock.patch.object(self._vmops, '_get_extra_specs',
                                  return_value=extra_specs),
                mock.patch.object(self._vmops, '_get_instance_metadata',
                                  return_value='fake-metadata')
        ) as (_wait_for_task, _call_method, _generate_uuid, _fetch_image,
              _get_img_svc, _get_inventory_path, _get_extra_specs,
              _get_instance_metadata):
            self._vmops.spawn(self._context, self._instance, image,
                              injected_files='fake_files',
                              admin_password='password',
                              network_info=network_info,
                              block_device_info=block_device_info)

            mock_is_neutron.assert_called_once_with()

            self.assertEqual(2, mock_mkdir.call_count)

            mock_get_vif_info.assert_called_once_with(
                self._session, self._cluster.obj, False,
                constants.DEFAULT_VIF_MODEL, network_info)
            mock_get_create_spec.assert_called_once_with(
                self._session.vim.client.factory, self._instance,
                'fake_ds', [], extra_specs, constants.DEFAULT_OS_TYPE,
                profile_spec=None,
                metadata='fake-metadata')
            mock_create_vm.assert_called_once_with(
                self._session, self._instance, 'fake_vm_folder',
                'fake_create_spec', self._cluster.resourcePool)
            mock_get_and_set_vnc_config.assert_called_once_with(
                self._session.vim.client.factory,
                self._instance, 'fake_vm_ref')
            mock_set_machine_id.assert_called_once_with(
                self._session.vim.client.factory,
                self._instance, network_info, vm_ref='fake_vm_ref')
            mock_power_on_instance.assert_called_once_with(
                self._session, self._instance, vm_ref='fake_vm_ref')

            if (block_device_info and
                    'block_device_mapping' in block_device_info):
                bdms = block_device_info['block_device_mapping']
                for bdm in bdms:
                    mock_attach_root = (
                        self._vmops._volumeops.attach_root_volume)
                    mock_attach = self._vmops._volumeops.attach_volume
                    adapter_type = bdm.get('disk_bus') or vi.ii.adapter_type
                    if bdm.get('boot_index') == 0:
                        mock_attach_root.assert_any_call(
                            bdm['connection_info'], self._instance,
                            self._ds.ref, adapter_type)
                    else:
                        mock_attach.assert_any_call(
                            bdm['connection_info'], self._instance,
                            self._ds.ref, adapter_type)

            mock_enlist_image.assert_called_once_with(
                self._image_id, self._ds, self._dc_info.ref)

            upload_file_name = 'vmware_temp/tmp-uuid/%s/%s-flat.vmdk' % (
                self._image_id, self._image_id)
            _fetch_image.assert_called_once_with(
                self._context, self._instance, self._session._host,
                self._session._port, self._dc_info.name, self._ds.name,
                upload_file_name, cookies='Fake-CookieJar')
            self.assertGreater(len(_wait_for_task.mock_calls), 0)
            _get_inventory_path.call_count = 1
            extras = None
            if block_device_info and ('ephemerals' in block_device_info or
                                      'swap' in block_device_info):
                extras = ['CreateVirtualDisk_Task']
            self._verify_spawn_method_calls(_call_method, extras)

            dc_ref = 'fake_dc_ref'
            source_file = six.text_type('[fake_ds] vmware_base/%s/%s.vmdk' %
                                        (self._image_id, self._image_id))
            dest_file = six.text_type('[fake_ds] vmware_base/%s/%s.%d.vmdk' %
                                      (self._image_id, self._image_id,
                                       self._instance['root_gb']))
            # TODO(dims): add more tests for copy_virtual_disk after
            # the disk/image code in spawn gets refactored
            mock_copy_virtual_disk.assert_called_with(self._session,
                                                      dc_ref,
                                                      source_file,
                                                      dest_file)

            if config_drive:
                mock_configure_config_drive.assert_called_once_with(
                    self._instance, 'fake_vm_ref', self._dc_info,
                    self._ds, 'fake_files', 'password', network_info)
            mock_update_vnic_index.assert_called_once_with(
                self._context, self._instance, network_info)

    @mock.patch.object(ds_util, 'get_datastore')
    @mock.patch.object(vmops.VMwareVMOps, 'get_datacenter_ref_and_name')
    def _test_get_spawn_vm_config_info(self,
                                       mock_get_datacenter_ref_and_name,
                                       mock_get_datastore,
                                       image_size_bytes=0):
        image_info = images.VMwareImage(image_id=self._image_id,
                                        file_size=image_size_bytes,
                                        linked_clone=True)

        mock_get_datastore.return_value = self._ds
        mock_get_datacenter_ref_and_name.return_value = self._dc_info
        extra_specs = vm_util.ExtraSpecs()

        vi = self._vmops._get_vm_config_info(self._instance, image_info,
                                             extra_specs)
        self.assertEqual(image_info, vi.ii)
        self.assertEqual(self._ds, vi.datastore)
        self.assertEqual(self._instance.root_gb, vi.root_gb)
        self.assertEqual(self._instance, vi.instance)
        self.assertEqual(self._instance.uuid, vi.instance.uuid)
        self.assertEqual(extra_specs, vi._extra_specs)

        cache_image_path = '[%s] vmware_base/%s/%s.vmdk' % (
            self._ds.name, self._image_id, self._image_id)
        self.assertEqual(cache_image_path, str(vi.cache_image_path))

        cache_image_folder = '[%s] vmware_base/%s' % (
            self._ds.name, self._image_id)
        self.assertEqual(cache_image_folder, str(vi.cache_image_folder))

    def test_get_spawn_vm_config_info(self):
        image_size = (self._instance.root_gb) * units.Gi / 2
        self._test_get_spawn_vm_config_info(image_size_bytes=image_size)

    def test_get_spawn_vm_config_info_image_too_big(self):
        image_size = (self._instance.root_gb + 1) * units.Gi
        self.assertRaises(exception.InstanceUnacceptable,
                          self._test_get_spawn_vm_config_info,
                          image_size_bytes=image_size)

    def test_spawn(self):
        self._test_spawn()

    def test_spawn_config_drive_enabled(self):
        self.flags(force_config_drive=True)
        self._test_spawn(config_drive=True)

    def test_spawn_with_block_device_info(self):
        block_device_info = {
            'block_device_mapping': [{'boot_index': 0,
                                      'connection_info': 'fake',
                                      'mount_device': '/dev/vda'}]
        }
        self._test_spawn(block_device_info=block_device_info)

    def test_spawn_with_block_device_info_with_config_drive(self):
        self.flags(force_config_drive=True)
        block_device_info = {
            'block_device_mapping': [{'boot_index': 0,
                                      'connection_info': 'fake',
                                      'mount_device': '/dev/vda'}]
        }
        self._test_spawn(block_device_info=block_device_info,
                         config_drive=True)

    def _spawn_with_block_device_info_ephemerals(self, ephemerals):
        block_device_info = {'ephemerals': ephemerals}
        self._test_spawn(block_device_info=block_device_info)

    def test_spawn_with_block_device_info_ephemerals(self):
        ephemerals = [{'device_type': 'disk',
                       'disk_bus': 'virtio',
                       'device_name': '/dev/vdb',
                       'size': 1}]
        self._spawn_with_block_device_info_ephemerals(ephemerals)

    def test_spawn_with_block_device_info_ephemerals_no_disk_bus(self):
        ephemerals = [{'device_type': 'disk',
                       'disk_bus': None,
                       'device_name': '/dev/vdb',
                       'size': 1}]
        self._spawn_with_block_device_info_ephemerals(ephemerals)

    def test_spawn_with_block_device_info_swap(self):
        block_device_info = {'swap': {'disk_bus': None,
                                      'swap_size': 512,
                                      'device_name': '/dev/sdb'}}
        self._test_spawn(block_device_info=block_device_info)

    def test_spawn_cpu_limit(self):
        cpu_limits = vm_util.Limits(limit=7)
        extra_specs = vm_util.ExtraSpecs(cpu_limits=cpu_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_cpu_reservation(self):
        cpu_limits = vm_util.Limits(reservation=7)
        extra_specs = vm_util.ExtraSpecs(cpu_limits=cpu_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_cpu_allocations(self):
        cpu_limits = vm_util.Limits(limit=7,
                                    reservation=6)
        extra_specs = vm_util.ExtraSpecs(cpu_limits=cpu_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_cpu_shares_level(self):
        cpu_limits = vm_util.Limits(shares_level='high')
        extra_specs = vm_util.ExtraSpecs(cpu_limits=cpu_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_cpu_shares_custom(self):
        cpu_limits = vm_util.Limits(shares_level='custom',
                                    shares_share=1948)
        extra_specs = vm_util.ExtraSpecs(cpu_limits=cpu_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_memory_limit(self):
        memory_limits = vm_util.Limits(limit=7)
        extra_specs = vm_util.ExtraSpecs(memory_limits=memory_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_memory_reservation(self):
        memory_limits = vm_util.Limits(reservation=7)
        extra_specs = vm_util.ExtraSpecs(memory_limits=memory_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_memory_allocations(self):
        memory_limits = vm_util.Limits(limit=7,
                                       reservation=6)
        extra_specs = vm_util.ExtraSpecs(memory_limits=memory_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_memory_shares_level(self):
        memory_limits = vm_util.Limits(shares_level='high')
        extra_specs = vm_util.ExtraSpecs(memory_limits=memory_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_memory_shares_custom(self):
        memory_limits = vm_util.Limits(shares_level='custom',
                                       shares_share=1948)
        extra_specs = vm_util.ExtraSpecs(memory_limits=memory_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_vif_limit(self):
        vif_limits = vm_util.Limits(limit=7)
        extra_specs = vm_util.ExtraSpecs(vif_limits=vif_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_vif_reservation(self):
        vif_limits = vm_util.Limits(reservation=7)
        extra_specs = vm_util.ExtraSpecs(vif_limits=vif_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_vif_shares_level(self):
        vif_limits = vm_util.Limits(shares_level='high')
        extra_specs = vm_util.ExtraSpecs(vif_limits=vif_limits)
        self._test_spawn(extra_specs=extra_specs)

    def test_spawn_vif_shares_custom(self):
        vif_limits = vm_util.Limits(shares_level='custom',
                                    shares_share=1948)
        extra_specs = vm_util.ExtraSpecs(vif_limits=vif_limits)
        self._test_spawn(extra_specs=extra_specs)
