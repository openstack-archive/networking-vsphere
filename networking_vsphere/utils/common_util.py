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


def convert_propset_to_dict(propset_list):
    propset_dict = {}
    for prop in propset_list:
        propset_dict[prop.name] = prop.val
    return propset_dict


def convert_objectupdate_to_dict(objectUpdate):
    changes = {}
    if (hasattr(objectUpdate, "changeSet")
            and objectUpdate.changeSet):
        for prop in objectUpdate.changeSet:
            if hasattr(prop, "name"):
                changes[prop.name] = None
                if hasattr(prop, "val"):
                    changes[prop.name] = prop.val
    return changes
