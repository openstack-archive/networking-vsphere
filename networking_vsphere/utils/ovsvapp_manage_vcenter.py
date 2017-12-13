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
