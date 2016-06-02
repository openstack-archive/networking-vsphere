# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
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

from oslo_config import cfg
from oslo_log import log
from oslo_utils import strutils

from nova.i18n import _LI
from nova.virt import configdrive
from nova.virt import driver
from nova.virt.vmwareapi import images
from nova.virt.vmwareapi import vm_util
from nova.virt.vmwareapi import vmops

CONF = cfg.CONF
LOG = log.getLogger(__name__)


class OVSvAppVMOps(vmops.VMwareVMOps):

    def __init__(self, session, virtapi, volumeops, cluster,
                 datastore_regex):
        super(OVSvAppVMOps, self).__init__(session, virtapi, volumeops,
                                           cluster, datastore_regex)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info, block_device_info=None,
              power_on=False):

        LOG.info(_LI("Inside OVSvApp VMOps spawn method."))
        client_factory = self._session.vim.client.factory
        image_info = images.VMwareImage.from_image(context,
                                                   instance.image_ref,
                                                   image_meta)
        extra_specs = self._get_extra_specs(instance.flavor, image_meta)

        vi = self._get_vm_config_info(instance, image_info,
                                      extra_specs)

        metadata = self._get_instance_metadata(context, instance)
        # Creates the virtual machine. The virtual machine reference returned
        # is unique within Virtual Center.
        vm_ref = self.build_virtual_machine(instance,
                                            image_info,
                                            vi.dc_info,
                                            vi.datastore,
                                            network_info,
                                            extra_specs,
                                            metadata)

        # Cache the vm_ref. This saves a remote call to the VC. This uses the
        # instance uuid.
        vm_util.vm_ref_cache_update(instance.uuid, vm_ref)

        # Update the Neutron VNIC index
        self._update_vnic_index(context, instance, network_info)

        # Set the machine.id parameter of the instance to inject
        # the NIC configuration inside the VM
        if CONF.flat_injected:
            self._set_machine_id(client_factory, instance, network_info,
                                 vm_ref=vm_ref)

        # Set the vnc configuration of the instance, vnc port starts from 5900
        if CONF.vnc.enabled:
            self._get_and_set_vnc_config(client_factory, instance, vm_ref)

        block_device_mapping = []
        if block_device_info is not None:
            block_device_mapping = driver.block_device_info_get_mapping(
                block_device_info)

        if instance.image_ref:
            self._imagecache.enlist_image(image_info.image_id, vi.datastore,
                                          vi.dc_info.ref)
            self._fetch_image_if_missing(context, vi)

            if image_info.is_iso:
                self._use_iso_image(vm_ref, vi)
            elif image_info.linked_clone:
                self._use_disk_image_as_linked_clone(vm_ref, vi)
            else:
                self._use_disk_image_as_full_clone(vm_ref, vi)

        if block_device_mapping:
            msg = "Block device information present: %s" % block_device_info
            # NOTE(mriedem): block_device_info can contain an auth_password
            # so we have to scrub the message before logging it.
            LOG.debug(strutils.mask_password(msg), instance=instance)

            # Before attempting to attach any volume, make sure the
            # block_device_mapping (i.e. disk_bus) is valid
            self._is_bdm_valid(block_device_mapping)

            for disk in block_device_mapping:
                connection_info = disk['connection_info']
                adapter_type = disk.get('disk_bus') or vi.ii.adapter_type

                # TODO(hartsocks): instance is unnecessary, remove it
                # we still use instance in many locations for no other purpose
                # than logging, can we simplify this?
                if disk.get('boot_index') == 0:
                    self._volumeops.attach_root_volume(connection_info,
                                                       instance,
                                                       vi.datastore.ref,
                                                       adapter_type)
                else:
                    self._volumeops.attach_volume(connection_info, instance,
                                                  adapter_type)

        # Create ephemeral disks
        self._create_ephemeral(block_device_info, instance, vm_ref,
                               vi.dc_info, vi.datastore, instance.uuid,
                               vi.ii.adapter_type)
        self._create_swap(block_device_info, instance, vm_ref, vi.dc_info,
                          vi.datastore, instance.uuid, vi.ii.adapter_type)

        if configdrive.required_by(instance):
            self._configure_config_drive(instance, vm_ref, vi.dc_info,
                                         vi.datastore, injected_files,
                                         admin_password, network_info)
        if power_on:
            vm_util.power_on_instance(self._session, instance, vm_ref=vm_ref)
