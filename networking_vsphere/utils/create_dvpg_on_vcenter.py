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
import urllib3

from networking_vsphere.utils.vim_objects import DVSPortGroup


def vlan_id_type(id):
    _id = int(id)
    if _id < 0 or _id > 4094:
        raise argparse.ArgumentTypeError("Vlan id must be a value between "
                                         "0 and 4094")
    return _id


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("dvpg_name", type=str,
                        help="Name to use for creating the"
                             "Distributed Virtual Port Group")

    parser.add_argument("vcenter_user", type=str,
                        help="username to be used for connecting to vcenter")

    parser.add_argument("vcenter_password", type=str,
                        help="username to be used for connecting to vcenter")

    parser.add_argument("vcenter_ip", type=str,
                        help="ip address to be used for connecting "
                             "to vcenter")

    parser.add_argument("dvs_name", type=str,
                        help="Name of the DVS to create the port group in")

    parser.add_argument("--vlan_type", type=str, dest='vlan_type',
                        metavar='vlan_type',
                        help="Vlan type to use for the port group.",
                        choices=['vlan', 'trunk'],
                        default='vlan')

    parser.add_argument("--vlan_id", type=vlan_id_type, dest='vlan_id',
                        metavar='vlan_id',
                        help="Vlan id to use for vlan type pg",
                        default=443)

    parser.add_argument("--vlan_range_start", type=vlan_id_type,
                        dest='vlan_range_start',
                        metavar='vlan_range_start',
                        help="Start of vlan id range if vlan_type='trunk'",
                        default=0)

    parser.add_argument("--vlan_ragne_stop", type=vlan_id_type,
                        dest='vlan_range_stop',
                        metavar='vlan_range_stop',
                        help="End of vlan id range if vlan_type='trunk'",
                        default=4094)

    parser.add_argument("--description", type=str, dest='description',
                        metavar='description',
                        help="description",
                        default="")

    parser.add_argument("--allow_promiscuous", action='store_true',
                        help="Sets promiscuous mode "
                             "of port group")

    parser.add_argument("--allow_forged_transmits", action='store_true',
                        help="Sets forge transmit mode "
                             "of port group")

    parser.add_argument("--notify_switches", action='store_true',
                        help="Set nic teaming 'notify switches' to True")

    parser.add_argument("--network_fail_over_detection", action='store_true',
                        help="Set nic teaming 'network failover detection' to "
                             "True")

    parser.add_argument("--load_balancing", type=str,
                        choices=['loadbalance_srcid',
                                 'loadbalance_ip',
                                 'loadbalance_srcmac',
                                 'loadbalance_loadbased',
                                 'failover_explicit'],

                        help="Set nic teaming load balancing algorithm. "
                             "Valid choices are: 'loadbalance_srcid', "
                             "'loadbalance_ip', 'loadbalance_srcmac', "
                             "'loadbalance_loadbased', or 'failover_explicit'")

    parser.add_argument("--create", action='store_true',
                        help="Create the port group on the named dvs. "
                             "If this flag is not present the data to create "
                             "the port group will be requested from the "
                             "the vcenter server but the port group will not "
                             "be created.")

    parser.add_argument("--display_spec", action='store_true',
                        help="If the flag is set, the create spe of the "
                             "port group will be send OUTPUT"
                        )
    args = parser.parse_args()

    dvpg = DVSPortGroup(dvs_name=args.dvs_name,
                        vcenter_user=args.vcenter_user,
                        vcenter_password=args.vcenter_password,
                        vcenter_ip=args.vcenter_ip,
                        vcenter_port=args.vcenter_port,
                        vlans_type=args.vlan_type
                        )

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    dvpg.connect_to_vcenter()
    if args.display_spec:
        print(dvpg.create_spec)
    if args.create:
        print("Attempting to create switch...")
        dvpg.create_on_vcenter()
    else:
        print("At user's request the switch was not created. If you would "
              "like to attempt to create the switch use the '--create' flag")
