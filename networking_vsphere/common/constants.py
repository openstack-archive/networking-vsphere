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

AGENT_TYPE_OVSVAPP = "OVSvApp L2 Agent"
OVSVAPP = 'ovsvapp'
DEVICE = 'device'

# Network type constants
NETWORK_VLAN = 'VLAN'
NETWORK_VXLAN = 'VXLAN'

# Port status constants
PORT_STATUS_UP = 'UP'
PORT_STATUS_DOWN = 'DOWN'

# VM Event type constants
VM_CREATED = 'VM_CREATED'
VM_UPDATED = 'VM_UPDATED'
VM_DELETED = 'VM_DELETED'

# Driver state constants
# Driver cannot connect or monitor hypervisor. Driver cannot process
# ResourceEntity APIs
DRIVER_IDLE = 'IDLE'
# Driver is ready for monitoring hypervisor
DRIVER_READY = 'READY'
# Driver is monitoring hypervisor
DRIVER_RUNNING = 'RUNNING'
# Driver is stopped
DRIVER_STOPPED = 'STOPPED'
