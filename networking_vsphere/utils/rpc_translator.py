# Copyright 2016 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

import copy
import netaddr


def update_rules(devices_rules_info):
    sg_members = devices_rules_info['sg_member_ips']
    devices = devices_rules_info['devices']
    result = copy.copy(devices)
    for device, device_info in devices.items():
        device_ips = device_info['fixed_ips']
        for sg in device_info['security_groups']:
            for sg_rule in devices_rules_info['security_groups'][sg]:
                if 'remote_group_id' in sg_rule:
                    result[device]['security_group_rules'].extend(
                        build_rules_from_sg(sg_rule, sg_members, device_ips))
                else:
                    result[device]['security_group_rules'].append(sg_rule)
    return result


def build_rules_from_sg(rule, sg_members, device_ips):
    rules = []
    for ip in sg_members[rule['remote_group_id']][rule['ethertype']]:
        if ip not in device_ips:
            r_builder = copy.copy(rule)
            direction_ip_prefix = 'source_ip_prefix' \
                if rule['direction'] == 'ingress' else 'dest_ip_prefix'
            r_builder[direction_ip_prefix] = str(netaddr.IPNetwork(ip).cidr)
            rules.append(r_builder)
    return rules
