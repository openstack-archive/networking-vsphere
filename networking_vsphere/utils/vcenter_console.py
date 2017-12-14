# (c) Copyright 2018 SUSE LLC
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

from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from networking_vsphere.utils.vim_objects import VcenterProxy


class VcenterConsole(VcenterProxy):
    """Class provides an object which can be loaded

    from with in a python repl. The object can the be used to interact
    with a vcenter service.

    Example: (from within ipython)

    In[142]: import networking_vsphere.utils.vcenter_console as vo
    Out[142]: <module 'networking_vsphere.utils.vim_objects'
                       from 'networking_vsphere/utils/vim_objects.py'>

    In[143]: vc = vo.VcenterConsole('some_name',
                        vcenter_ip='192.168.0.1',
                        vcenter_user='VcenterUserNmae',
                        vcenter_password='VcenterPassword')


    In [144]: vc.connect
    Out[144]: 'SUCCESS'

    In [94]: vc.get_used_pnics_in_host('192.168.200.80')
    Out[94]: [key-vim.host.PhysicalNic-vmnic0,
              key-vim.host.PhysicalNic-vmnic1]
    """

    def __init__(self, *args, **kwargs):
        super(VcenterConsole, self).__init__(*args, **kwargs)
        disable_warnings(InsecureRequestWarning)
        self._connected = False

    @property
    def user_name(self):
        return self.vcenter_user

    @user_name.setter
    def user_name(self, name):
        self.vcenter_user = name

    @property
    def password(self):
        return "*******"

    @password.setter
    def password(self, pswd):
        self.vcenter_password = pswd

    @property
    def connection_ip(self):
        return self.vcenter_ip

    @connection_ip.setter
    def connection_ip(self, ip):
        self.vcenter_ip = ip

    @property
    def connection_port(self):
        return self.vcenter_port

    @connection_port.setter
    def connection_port(self, port):
        self.vcenter_port = port

    @property
    def credentials(self):
        return {
            'user_name': self.user_name,
            'password': self.password,
            'ip address': self.vcenter_ip,
            'tcp port': self.vcenter_port,

        }

    @property
    def connected(self):
        return self._connected

    @property
    def connect(self):
        self.connect_to_vcenter()
        self._connected = True
        return "SUCCESS"

    @property
    def get_all_dvs(self):
        return self.get_all_objects_of_type("DistributedVirtualSwitch")

    @property
    def get_all_dvpg(self):
        return self.get_all_objects_of_type("DistributedVirtualPortgroup")

    @property
    def get_all_vim_methods_and_types(self):
        return str(self.session.vim.client)

    @property
    def get_all_hosts(self):
        return self.get_hosts().objects

    @property
    def get_all_clusters(self):
        return self.get_all_objects_of_type('ClusterComputeResource').objects
