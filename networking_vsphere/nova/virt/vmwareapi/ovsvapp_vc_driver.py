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

from eventlet import greenthread
from oslo_config import cfg
from oslo_log import log
from oslo_vmware import vim_util

from nova import exception
from nova.i18n import _LI
from nova.virt.vmwareapi import driver as vmware_driver
from nova.virt.vmwareapi import images
from nova.virt.vmwareapi import ovsvapp_vmops as vmops  # noqa
from nova.virt.vmwareapi import vm_util

LOG = log.getLogger(__name__)

vmware_neutron_opts = [
    cfg.IntOpt('vmwareapi_nic_attach_retry_count',
               default=25,
               help='The number of times we retry to '
                    'attach nic on a portgroup.')]

CONF = cfg.CONF
CONF.register_opts(vmware_neutron_opts, 'vmware')


class OVSvAppVCDriver(vmware_driver.VMwareVCDriver):
    def __init__(self, virtapi):
        super(OVSvAppVCDriver, self).__init__(virtapi)
        self.client_factory = self._session.vim.client.factory
        self.old_modified_time = -1
        self.ovsvapp_vmops = vmops.OVSvAppVMOps(self._session,
                                                virtapi,
                                                self._volumeops,
                                                self._cluster_ref,
                                                self._datastore_regex)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        self.ovsvapp_vmops.spawn(context=context,
                                 instance=instance,
                                 image_meta=image_meta,
                                 injected_files=injected_files,
                                 admin_password=admin_password,
                                 network_info=None,
                                 block_device_info=block_device_info)

        vm_ref = vm_util.get_vm_ref(self._session, instance)
        if vm_ref is None:
            raise exception.InstanceNotFound(instance_id=instance['uuid'])
        image_info = images.VMwareImage.from_image(context,
                                                   instance.image_ref,
                                                   image_meta)
        self._create_virtual_nic(instance, image_info, network_info, vm_ref)
        self._power_on_vm(instance, vm_ref)

    def network_binding_host_id(self, context, instance):
        """Get host ID to associate with network ports.

        This defines the binding:host_id parameter to the port-create
        calls for Neutron.
        return None here to indicate that port should not yet be bound.
        As per implementation port-binding state will remain UNBOUND for
        OVSvAPP hosted ports and will transition to BOUND state directly
        from OVSvAPP itself

        :param context:  request context
        :param instance: nova.objects.instance.Instance that the network
                         ports will be associated with
        :returns: None
        """
        return None

    def _power_on_vm(self, instance, vm_ref):
        LOG.info(_LI("Powering on the VM: %s."), instance)
        power_on_task = self._session._call_method(self._session.vim,
                                                   "PowerOnVM_Task", vm_ref)

        self._session._wait_for_task(power_on_task)
        LOG.info(_LI("Powered on the VM: %s."), instance)

    def _get_mo_id_from_instance(self, instance):
        """Return the managed object ID from the instance.

        The instance['node'] will have the hypervisor_hostname field of the
        compute node on which the instance exists or will be provisioned.
        The name will be of the form:
            <mo id>.<vcenter uuid>
        e.g.
            domain-26.9d51f082-58a4-4449-beed-6fd205a5726b
        """
        return instance['node'].partition('.')[0]

    def _create_virtual_nic(self, instance, image_info, network_info, vm_ref):
        if network_info is None:
            return
        vif_model = image_info.vif_model
        if not vif_model:
            vif_model = "VirtualE1000"
        vif_infos = []
        for vif in network_info:
            portgroup_name = []
            mac_address = vif['address']
            network_id = vif['network']['id']
            portgroup_name.append(network_id)
            network_id_cluster_id = (network_id + "-" +
                                     self._get_mo_id_from_instance(instance))
            portgroup_name.append(network_id_cluster_id)
            # wait for port group creation (if not present) by neutron agent.
            network_ref = self._wait_and_get_portgroup_details(self._session,
                                                               vm_ref,
                                                               portgroup_name)
            if not network_ref:
                msg = ("Portgroup %(vlan)s (or) Portgroup %(vxlan)s.",
                       {'vlan': network_id, 'vxlan': network_id_cluster_id})
                raise exception.NetworkNotCreated(msg)
            vif_infos.append({
                             'network_name': network_id_cluster_id,
                             'mac_address': mac_address,
                             'network_ref': network_ref,
                             'iface_id': vif['id'],
                             'vif_model': vif_model
                             })

        config_spec = self.client_factory.create('ns0:'
                                                 'VirtualMachineConfigSpec')
        vif_spec_list = []
        for vif_info in vif_infos:
            vif_spec = vm_util._create_vif_spec(self.client_factory,
                                                vif_info)
            vif_spec_list.append(vif_spec)

        config_spec.deviceChange = vif_spec_list

        # add vm-uuid and iface-id.x values for Neutron.
        extra_config = []
        i = 0
        for vif_info in vif_infos:
            if vif_info['iface_id']:
                opt = self.client_factory.create('ns0:OptionValue')
                opt.key = "nvp.iface-id.%d" % i
                opt.value = vif_info['iface_id']
                extra_config.append(opt)
                i += 1

        config_spec.extraConfig = extra_config

        LOG.info(_LI("Reconfiguring VM instance to attach NIC."))
        reconfig_task = self._session._call_method(self._session.vim,
                                                   "ReconfigVM_Task", vm_ref,
                                                   spec=config_spec)

        self._session._wait_for_task(reconfig_task)
        LOG.info(_LI("Reconfigured VM instance to attach NIC."))

    def _wait_and_get_portgroup_details(self, session, vm_ref,
                                        port_group_name):
        """Gets reference to the portgroup for the vm."""

        max_counts = CONF.vmware.vmwareapi_nic_attach_retry_count
        count = 0
        network_obj = {}
        LOG.info(_LI("Waiting for the portgroup %s to be created."),
                 port_group_name)
        while count < max_counts:
            host = session._call_method(vim_util,
                                        "get_object_property",
                                        vm_ref, "runtime.host")
            vm_networks_ret = session._call_method(
                vim_util, "get_object_property",
                host, "network")
            if vm_networks_ret:
                vm_networks = vm_networks_ret.ManagedObjectReference
                for network in vm_networks:
                    # Get network properties.
                    if network._type == 'DistributedVirtualPortgroup':
                        props = session._call_method(
                            vim_util, "get_object_property",
                            network, "config")
                        if props.name in port_group_name:
                            LOG.info(_LI("DistributedVirtualPortgroup "
                                         "created."))
                            network_obj['type'] = 'DistributedVirtualPortgroup'
                            network_obj['dvpg'] = props.key
                            dvs_props = session._call_method(
                                vim_util,
                                "get_object_property",
                                props.distributedVirtualSwitch,
                                "uuid")
                            network_obj['dvsw'] = dvs_props
                            network_obj['dvpg-name'] = props.name
                            return network_obj
                    elif network._type == 'Network':
                        netname = session._call_method(
                            vim_util, "get_object_property",
                            network, "name")
                        if netname in port_group_name:
                            LOG.info(_LI("Standard Switch Portgroup created."))
                            network_obj['type'] = 'Network'
                            network_obj['name'] = port_group_name
                            return network_obj
                count = count + 1
                LOG.info(_LI("Port group not created. Retrying again "
                             "after 2 seconds."))
                greenthread.sleep(2)
        return None
