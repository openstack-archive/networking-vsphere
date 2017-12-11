# (c) Copyright 2017 SUSE LLC
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
#


from networking_vsphere.common import constants as const
from oslo_vmware import api
from oslo_vmware import vim_util


class VcenterProxy(object):
    def __init__(self, name, vcenter_ip=None, vcenter_port=443,
                 vcenter_user=None, vcenter_password=None):
        self.name = name
        self.vcenter_ip = vcenter_ip
        self.vcenter_port = vcenter_port
        self.vcenter_user = vcenter_user
        self.vcenter_password = vcenter_password
        self.cf = None
        self.session = None
        self._connected = False

    def connect_to_vcenter(self, **kwargs):
        try:
            self.session = api.VMwareAPISession(self.vcenter_ip,
                                                self.vcenter_user,
                                                self.vcenter_password,
                                                const.VIM_API_RETRY_COUNT,
                                                const.VIM_TASK_POLL_INTERVAL,
                                                port=self.vcenter_port,
                                                create_session=True,
                                                **kwargs
                                                )
            self.cf = self.session.vim.client.factory
        except Exception as e:
            self._connected = False
            return e

        self._connected = True

    def get_type(self, type_name):
        type_ns = "ns0:" + str(type_name)
        return self.cf.create(type_ns)

    def get_all_objects_of_type(self, vim_type, **kwargs):
        return self.session.invoke_api(vim_util,
                                       'get_objects',
                                       self.session.vim,
                                       vim_type,
                                       const.VIM_MAX_OBJETS,
                                       **kwargs)

    def get_mob_by_name(self, vim_type, obj_name, **kwargs):
        results = self.get_all_objects_of_type(vim_type, **kwargs)
        while results:
            for _mob in results.objects:
                for prop in _mob.propSet:
                    if prop.name == 'name' and obj_name == prop.val:
                        vim_util.cancel_retrieval(self.session.vim, results)
                        return _mob
            results = vim_util.continue_retrieval(self.session.vim, results)

    def get_mob_by_mobid(self, vim_type, mob_id, **kwargs):
        results = self.get_all_objects_of_type(vim_type, **kwargs)
        while results:
            for _mob in results.objects:
                if _mob.obj.value == mob_id:
                    vim_util.cancel_retrieval(self.session.vim, results)
                    return _mob
            results = vim_util.continue_retrieval(self.session.vim, results)

    def get_hosts(self, **kwargs):
        return self.get_all_objects_of_type("HostSystem", **kwargs)

    def get_all_properties(self, mob, **kwargs):
        return self.session.invoke_api(vim_util,
                                       'get_object_properties',
                                       self.session.vim,
                                       mob.obj,
                                       [],
                                       **kwargs)

    def get_property(self, moref, property_name, **kwargs):
        return self.session.invoke_api(vim_util, 'get_object_property',
                                       self.session.vim,
                                       moref,
                                       property_name,
                                       **kwargs)

    @staticmethod
    def make_moref(value, type_):
        return vim_util.get_moref(value, type_)
