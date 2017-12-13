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

from networking_vsphere.utils.vim_objects import DistributedVirtualSwitch


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("dvs_name", type=str,
                        help="Name to use for creating the dvs")

    parser.add_argument("vcenter_user", type=str,
                        help="username to be used for connecting to vcenter")

    parser.add_argument("vcenter_password", type=str,
                        help="username to be used for connecting to vcenter")

    parser.add_argument("vcenter_ip", type=str,
                        help="ip address to be used for connecting "
                             "to vcenter")

    parser.add_argument("datacenter_name", type=str,
                        help="name of data center where the dvs will be "
                             "created")

    parser.add_argument("--tcp", type=int, dest='vcenter_port',
                        metavar='tcp_port',
                        help="tcp port to be used for connecting to vcenter",
                        default=443)

    parser.add_argument("--pnic_devices", type=list, dest='pnic_devices',
                        metavar='pnic_devices',
                        help=" pnic devices to be used by dvs"
                             "example: vmnic0, vmnic1",
                        default=[])

    parser.add_argument("--max_mtu", type=int, dest='max_mtu',
                        metavar='max_mtu',
                        help=" mtu to be used by dvs",
                        default=1500)

    parser.add_argument("--host_names", type=list, dest='host_names',
                        metavar='host_names',
                        help=" list of host names to attach to dvs",
                        default=[])

    parser.add_argument("--description", type=str, dest='description',
                        metavar='description',
                        help=" description to add to dev",
                        default="")

    parser.add_argument("--max_ports", type=int, dest='max_ports',
                        metavar='max_ports',
                        help="maximum number of ports allowed on dvs",
                        default=3000)

    parser.add_argument("--cluster_name", type=str, dest='cluster_name',
                        metavar='cluster_name',
                        help=" name of cluster to use for dvs ",
                        default=None)

    parser.add_argument("--create", action='store_true',
                        help="Create the switch on the vcenter server. If "
                             "this flag is not present the data to create "
                             "the information to create the switch will be "
                             "requested from the vcenter server but the "
                             "switch will not be created.")

    parser.add_argument("--display_spec", action='store_true',
                        help="If the flag is set, the spec create of the "
                             "switch will be send OUTPUT"
                        )

    parser.add_argument("--no_action", action='store_true',
                        help="If the flag is set, the script simply outputs "
                             "the arguments passed in and exits. It does not "
                             "attempt to connect to vcenter")
    args = parser.parse_args()

    dvs = DistributedVirtualSwitch(dvs_name=args.dvs_name,
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

    if args.no_action:
        print(type(dvs))
        print(dvs)
        exit(0)

    dvs.connect_to_vcenter()
    if args.display_spec:
        print(dvs.create_spec)
    if args.create:
        print("Attempting to create switch...")
        dvs.create_on_vcenter()
    else:
        print("At user's request the switch was not created. If you would "
              "like to attempt to create the switch use the '--create' flag")


if __name__ == '__main__':
    main()
