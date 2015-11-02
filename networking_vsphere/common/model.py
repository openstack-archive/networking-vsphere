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

import uuid as uuid1


class NetworkConfig(object):

    def __init__(self, vlan):
        self.vlan = vlan


class Vlan(object):

    def __init__(self, vlan_ids=None, operation_mode=None, vlan_type="Native"):
        self.vlanIds = vlan_ids
        self.operation_mode = operation_mode
        self.vlan_type = vlan_type


class ResourceEntity(object):

    def __init__(self, key=None, uuid=None):
        super(ResourceEntity, self).__init__()
        if not uuid:
            uuid = uuid1.uuid1()
        self.uuid = str(uuid)
        self.key = key


class Host(ResourceEntity):

    def __init__(self, name=None, key=None):
        super(Host, self).__init__(key)
        self.name = name


class PhysicalNic(ResourceEntity):

    def __init__(self, name, mac_address, config, key=None):
        super(PhysicalNic, self).__init__(key)
        self.name = name
        self.mac_address = mac_address
        self.config = config


class VirtualSwitch(ResourceEntity):

    def __init__(self, name, pnics=None, networks=None, hosts=None, key=None):
        super(VirtualSwitch, self).__init__(key)
        self.name = name
        self.pnics = pnics or []
        self.networks = networks or []
        self.hosts = hosts or []


class Network(ResourceEntity):

    def __init__(self, name, network_type, config=None,
                 vswitches=None, ports=None, key=None):
        super(Network, self).__init__(key)
        self.name = name
        self.network_type = network_type
        self.config = config
        self.vswitches = vswitches or []
        self.ports = ports or []


class Port(ResourceEntity):

    def __init__(self, name=None, mac_address=None,
                 ipaddresses=None, vswitch_uuid=None,
                 vm_id=None, network_uuid=None, port_config=None,
                 port_status=None, key=None,
                 uuid=None):
        super(Port, self).__init__(key, uuid)
        self.name = name
        self.mac_address = mac_address
        self.ipaddresses = ipaddresses
        self.vswitch_uuid = vswitch_uuid
        self.vm_id = vm_id
        self.network_uuid = network_uuid
        self.port_config = port_config
        self.port_status = port_status


class VirtualNic(ResourceEntity):

    def __init__(self, mac_address, port_uuid,
                 vm_id, vm_name, nic_type, pg_id, key=None):
        super(VirtualNic, self).__init__(key)
        self.mac_address = mac_address
        self.port_uuid = port_uuid
        self.vm_id = vm_id
        self.vm_name = vm_name
        self.nic_type = nic_type
        self.pg_id = pg_id


class VirtualMachine(ResourceEntity):

    def __init__(self, name, vnics, uuid=None, key=None):
        if uuid:
            super(VirtualMachine, self).__init__(key, uuid)
        else:
            super(VirtualMachine, self).__init__(key)
        self.name = name
        self.vnics = vnics


class Event(object):

    def __init__(self, event_type, src_obj, changes, host_name,
                 cluster_name, cluster_id, host_changed):
        self.event_type = event_type
        self.src_obj = src_obj
        self.changes = changes
        self.host_name = host_name
        self.cluster_name = cluster_name
        self.cluster_id = cluster_id
        self.host_changed = host_changed
