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

AGENT_TYPE_OVSVAPP = "OVSvApp Agent"
AGENT_TYPE_DVS = 'DVS agent'
OVSVAPP = 'ovsvapp'
DVS = 'dvs'
OVSVAPP_PLUGIN = 'ovsvapp_service_plugin'
DEVICE = 'device'
VMWARE_HYPERVISOR_TYPE = 'VMware vCenter Server'

# Port status constants.
PORT_STATUS_UP = 'UP'
PORT_STATUS_DOWN = 'DOWN'

# VM Event type constants.
VM_CREATED = 'VM_CREATED'
VM_UPDATED = 'VM_UPDATED'
VM_DELETED = 'VM_DELETED'

# Driver state constants.
# Driver cannot connect or monitor hypervisor. Driver cannot process
# ResourceEntity APIs.
DRIVER_IDLE = 'IDLE'
# Driver is ready for monitoring hypervisor.
DRIVER_READY = 'READY'
# Driver is monitoring hypervisor.
DRIVER_RUNNING = 'RUNNING'
# Driver is stopped.
DRIVER_STOPPED = 'STOPPED'

# VLAN ID constants.
DEAD_VLAN = 4095

# Agent State constants.
AGENT_INITIALIZING = "INITIALIZING"
AGENT_INITIALIZED = "INITIALIZED"
AGENT_RUNNING = "RUNNING"
AGENT_STOPPING = "STOPPING"
AGENT_STOPPED = "STOPPED"

SEC_TO_INT_PATCH = "patch-integration"
INT_TO_SEC_PATCH = "patch-security"

# OVS Firewall related constants.
SG_DROPALL_PRI = 0
SG_DEFAULT_PRI = 1
SG_LOW_PRI = 5
SG_RULES_PRI = 10
SG_TP_PRI = 20
SG_TCP_FLAG_PRI = 25
SG_DROP_HIGH_PRI = 50

SG_DEFAULT_TABLE_ID = 0
SG_EGRESS_TABLE_ID = 1
SG_IP_TABLE_ID = 2
SG_TCP_TABLE_ID = 2
SG_UDP_TABLE_ID = 2
SG_ICMP_TABLE_ID = 2
SG_LEARN_TABLE_ID = 5
SG_CANARY_TABLE_ID = 23

ICMP_ECHO_REQ = 8
ICMP_ECHO_REP = 0
ICMP_TIME_EXCEEDED = 11
ICMP_TS_REQ = 13
ICMP_TS_REP = 14
ICMP_INFO_REQ = 15
ICMP_INFO_REP = 16
ICMP_AM_REQ = 17
ICMP_AM_REP = 18
ICMP_DEST_UNREACH = 3

THREAD_POOL_SIZE = 5
RPC_BATCH_SIZE = 30
SG_RPC_BATCH_SIZE = 10

DIRECTION_IP_PREFIX = {'ingress': 'source_ip_prefix',
                       'egress': 'dest_ip_prefix'}

# protocol number according to RFC 1700
PROTOCOL = {'icmp': 1,
            'tcp': 6,
            'udp': 17,
            'ipv6-icmp': 58}

# VMWare DVS specific
DVS_PORTGROUP_NAME_MAXLEN = 80

LOGIN_RETRIES = 3

VM_NETWORK_DEVICE_TYPES = [
    'VirtualE1000', 'VirtualE1000e', 'VirtualPCNet32',
    'VirtualSriovEthernetCard', 'VirtualVmxnet']

CONCURRENT_MODIFICATION_TEXT = 'Cannot complete operation due to concurrent '\
                               'modification by another operation.'

LOGIN_PROBLEM_TEXT = "Cannot complete login due to an incorrect "\
                     "user name or password"

DELETED_TEXT = "The object has already been deleted or has not been "\
               "completely created"

DUPLICATE_NAME = "oslo_vmware.exceptions.DuplicateName"

RESOURCE_IN_USE = "is in use."

# EPHEMERAL ports
MIN_EPHEMERAL_PORT = 32768
MAX_EPHEMERAL_PORT = 65535
