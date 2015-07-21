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

import eventlet

from networking_vsphere.common import error


class NetworkDriver(object):

    '''Base Class for defining interface for all L2 network drivers.'''

    def __init__(self):
        # Reference to NetworkDriverCallback implementation.
        self.callback_impl = None

    def set_callback(self, callback_impl):
        '''Sets the implementation of NetworkDriverCallback.'''
        if not isinstance(callback_impl, NetworkDriverCallback):
            raise error.OVSvAppNeutronAgentError(
                "Invalid NetworkDriverCallback")
        self.callback_impl = callback_impl

    def monitor_events(self):
        '''Common model API - monitor for events.'''
        raise NotImplementedError()

    def pause(self):
        '''Driver will stop processing and go to waiting.'''
        pass

    def stop(self):
        """To be called when the process is shutting down.

        Implements any cleanups that are required.
        """
        pass

    def is_connected(self):
        """Represents the state of the driver.

        Whether its connected to hypervisor or not.
        """
        raise NotImplementedError()

    def create_network(self, network, virtual_switch):
        """Creates l2 network on the compute node.

        :param network: Type model.Network
        :param virtual_switch: Type model.VirtualSwitch
        """
        raise NotImplementedError()

    def delete_network(self, network, virtual_switch=None):
        """Deletes l2 network on the compute node.

        :param network: Type model.Network
        :param virtual_switch: Type model.VirtualSwitch
        """
        raise NotImplementedError()

    def update_port(self, network=None, port=None, virtual_nic=None):
        """Update the Port status UP/DOWN.

        :param network: Type model.Network
        :param port: Type model.Port
        :param virtual_nic: Type model.VirtualNic
        """
        raise NotImplementedError()

    def prepare_port_group(self, network, port, virtual_nic):
        """Prepares portgroup creation on DVS with specified configuration.

        Calls create_network if network does not exist.
        :param network: Type model.Network
        :param port: Type model.Port
        :param virtual_nic: Type model.VirtualNic
        """
        raise NotImplementedError()

    def update_port_group(self, network, port, virtual_nic):
        """Updates the portgroup on DVS.

        :param network: Type model.Network
        :param port: Type model.Port
        :param virtual_nic: Type model.VirtualNic
        """
        raise NotImplementedError()

    def get_vlanid_for_port_group(self, dvs_name, pg_name):
        '''Obtain VLAN id associated with a DVS portgroup.'''
        raise NotImplementedError()

    def get_vlanid_for_portgroup_key(self, pg_id):
        '''Obtain VLAN id associated with a port group.'''
        raise NotImplementedError()

    def get_vm_ref_by_uuid(self, vm_uuid):
        '''Obtain vm reference from uuid.'''
        raise NotImplementedError()

    def wait_for_portgroup(self, vm_ref, pg_name):
        '''Wait on a portgroup on a dvswitch for a vm.'''
        raise NotImplementedError()

    def process_delete_vm(self, vm):
        '''Post process for a VM_DELETED task.'''
        raise NotImplementedError()

    def dispatch_events(self, events):
        '''Dispatch events to the callback on different green threads.'''
        for event in events:
            eventlet.spawn_n(self.callback_impl.process_event, event)


class NetworkDriverCallback(object):

    '''Base class defining callback interface.'''

    def process_event(self, event):
        """Called when an event is detected on the hypervisor.

        :param event: Type model.Event
        """
        raise NotImplementedError()
