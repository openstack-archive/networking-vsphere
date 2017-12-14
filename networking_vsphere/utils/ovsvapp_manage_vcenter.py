# (c) Copyright 2017 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#


import argparse

from networking_vsphere.utils import vim_objects


def dvs():

    parser = argparse.ArgumentParser()

    parser.add_argument("dvs_name", type=str,
                        help="Name to use for creating the DVS")

    parser.add_argument("vcenter_user", type=str,
                        help="Username to be used for connecting to vCenter")

    parser.add_argument("vcenter_password", type=str,
                        help="Password to be used for connecting to vCenter")

    parser.add_argument("vcenter_ip", type=str,
                        help="IP address to be used for connecting "
                             "to vCenter")

    parser.add_argument("datacenter_name", type=str,
                        help="Name of data center where the DVS will be "
                             "created")

    parser.add_argument("--tcp", type=int, dest='vcenter_port',
                        metavar='tcp_port',
                        help="TCP port to be used for connecting to vCenter",
                        default=443)

    parser.add_argument("--pnic_devices", nargs='+', dest='pnic_devices',
                        metavar='pnic_devices',
                        help="Space separated list of PNIC devices for DVS",
                        default=[])

    parser.add_argument("--max_mtu", type=int, dest='max_mtu',
                        metavar='max_mtu',
                        help="MTU to be used by the DVS",
                        default=1500)

    parser.add_argument("--host_names", nargs='+', dest='host_names',
                        metavar='host_names',
                        help="Space separated list of ESX hosts to add to DVS",
                        default=[])

    parser.add_argument("--description", type=str, dest='description',
                        metavar='description',
                        help="DVS description",
                        default="")

    parser.add_argument("--max_ports", type=int, dest='max_ports',
                        metavar='max_ports',
                        help="Maximum number of ports allowed on DVS",
                        default=3000)

    parser.add_argument("--cluster_name", type=str, dest='cluster_name',
                        metavar='cluster_name',
                        help="Cluster name to use for DVS",
                        default=None)

    parser.add_argument("--create", action='store_true',
                        help="Create DVS on vCenter")

    parser.add_argument("--display_spec", action='store_true',
                        help="Print create spec of DVS"
                        )

    parser.add_argument("-v", action='store_true',
                        help="Verbose output")

    args = parser.parse_args()

    _dvs = vim_objects.DistributedVirtualSwitch(
        dvs_name=args.dvs_name,
        vcenter_user=args.vcenter_user,
        vcenter_password=args.vcenter_password,
        vcenter_ip=args.vcenter_ip,
        vcenter_port=args.vcenter_port,
        datacenter_name=args.datacenter_name,
        pnic_devices=args.pnic_devices,
        max_mtu=args.max_mtu,
        host_names=args.host_names,
        description=args.description,
        max_ports=args.max_ports,
        cluster_name=args.cluster_name)

    if args.display_spec or args.create:
        _dvs.connect_to_vcenter()

    if args.display_spec:
        print(_dvs.create_spec)

    if args.create:
        print("Attempting to create switch...")
        _dvs.create_on_vcenter()
        print("Success")

    if args.v:
        print("DVS Configuration: ")
        print(_dvs)


def vlan_id_type(vid):
    _id = int(vid)
    if _id < 0 or _id > 4094:
        raise argparse.ArgumentTypeError("Vlan id must be a value between "
                                         "0 and 4094")
    return _id


def dvpg():
    parser = argparse.ArgumentParser()

    parser.add_argument("dvpg_name", type=str,
                        help="Name to use for creating the"
                             "Distributed Virtual Port Group (DVPG)")

    parser.add_argument("vcenter_user", type=str,
                        help="Username to be used for connecting to vCenter")

    parser.add_argument("vcenter_password", type=str,
                        help="Password to be used for connecting to vCenter")

    parser.add_argument("vcenter_ip", type=str,
                        help="IP address to be used for connecting to vCenter")

    parser.add_argument("--tcp", type=int, dest='vcenter_port',
                        metavar='tcp_port',
                        help="TCP port to be used for connecting to vCenter",
                        default=443)

    parser.add_argument("dvs_name", type=str,
                        help="Name of the Distributed Virtual Switch (DVS) "
                             " to create the DVPG in")

    parser.add_argument("--vlan_type", type=str, dest='vlan_type',
                        metavar='vlan_type',
                        help="Vlan type to use for the DVPG",
                        choices=['vlan', 'trunk'],
                        default='vlan')

    parser.add_argument("--vlan_id", type=vlan_id_type, dest='vlan_id',
                        metavar='vlan_id',
                        help="Vlan id to use for vlan_type='vlan'",
                        default=443)

    parser.add_argument("--vlan_range_start", type=vlan_id_type,
                        dest='vlan_range_start',
                        metavar='vlan_range_start',
                        help="Start of vlan id range for vlan_type='trunk'",
                        default=0)

    parser.add_argument("--vlan_range_stop", type=vlan_id_type,
                        dest='vlan_range_stop',
                        metavar='vlan_range_stop',
                        help="End of vlan id range for vlan_type='trunk'",
                        default=4094)

    parser.add_argument("--description", type=str, dest='description',
                        metavar='description',
                        help="DVPG description",
                        default="")

    parser.add_argument("--allow_promiscuous", action='store_true',
                        help="Sets promiscuous mode of DVPG")

    parser.add_argument("--allow_forged_transmits", action='store_true',
                        help="Sets forge transmit mode of DVPG")

    parser.add_argument("--notify_switches", action='store_true',
                        help="Set nic teaming 'notify switches' to True. ")

    parser.add_argument("--network_failover_detection", action='store_true',
                        help="Set nic teaming 'network failover detection' to "
                             "True")

    parser.add_argument("--load_balancing", type=str,
                        choices=['loadbalance_srcid',
                                 'loadbalance_ip',
                                 'loadbalance_srcmac',
                                 'loadbalance_loadbased',
                                 'failover_explicit'],
                        default='loadbalance_srcid',

                        help="Set nic teaming load balancing algorithm. "
                             "Default=loadbalance_srcid")

    parser.add_argument("--create", action='store_true',
                        help="Create DVPG on vCenter")

    parser.add_argument("--display_spec", action='store_true',
                        help="Send DVPG's create spec to OUTPUT"
                        )

    parser.add_argument("--active_nics", nargs='+',
                        help="Space separated list of active nics to use in "
                             "DVPG nic teaming"
                        )

    parser.add_argument("-v", action='store_true',
                        help="Verbose output")

    args = parser.parse_args()

    nic_teaming = {'notify_switches': args.notify_switches,
                   'network_failover_detection':
                       args.network_failover_detection,
                   'load_balancing': args.load_balancing,
                   'active_nics': args.active_nics}

    _dvpg = vim_objects.DVSPortGroup(
        args.dvpg_name,
        dvs_name=args.dvs_name,
        vcenter_user=args.vcenter_user,
        vcenter_password=args.vcenter_password,
        vcenter_ip=args.vcenter_ip,
        vcenter_port=args.vcenter_port,
        vlan_type=args.vlan_type,
        vlan_id=args.vlan_id,
        vlan_range_start=args.vlan_range_start,
        nic_teaming=nic_teaming,
        description=args.description,
        allow_promiscuous=args.allow_promiscuous,
        forged_transmits=args.allow_forged_transmits,
        auto_expand=True
    )

    if args.display_spec or args.create:
        _dvpg.connect_to_vcenter()

    if args.display_spec:
        print(_dvpg.create_spec)

    if args.create:
        print("Attempting to create switch...")
        _dvpg.create_on_vcenter()
        print("Success")

    if args.v:
        print("DVPG Configuration: ")
        print(_dvpg)
