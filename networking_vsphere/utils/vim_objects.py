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

    def connect_to_vcenter(self):
        self.session = api.VMwareAPISession(self.vcenter_ip,
                                            self.vcenter_user,
                                            self.vcenter_password,
                                            const.VIM_API_RETRY_COUNT,
                                            const.VIM_TASK_POLL_INTERVAL,
                                            port=self.vcenter_port,
                                            create_session=True
                                            )
        self.cf = self.session.vim.client.factory

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

    def get_mob_by_name(self, vim_type, obj_name):
        results = self.get_all_objects_of_type(vim_type)
        while results:
            for _mob in results.objects:
                for prop in _mob.propSet:
                    if prop.name == 'name' and obj_name == prop.val:
                        vim_util.cancel_retrieval(self.session.vim, results)
                        return _mob
            results = vim_util.continue_retrieval(self.session.vim, results)

    def get_mob_by_mobid(self, vim_type, mob_id):
        results = self.get_all_objects_of_type(vim_type)
        while results:
            for _mob in results.objects:
                if _mob.obj.value == mob_id:
                    vim_util.cancel_retrieval(self.session.vim, results)
                    return _mob
            results = vim_util.continue_retrieval(self.session.vim, results)

    def get_hosts(self):
        return self.get_all_objects_of_type("HostSystem")

    def get_all_properties(self, mob):
        return self.session.invoke_api(vim_util,
                                       'get_object_properties',
                                       self.session.vim,
                                       mob.obj,
                                       [])

    def get_property(self, moref, property_name):
        return self.session.invoke_api(vim_util, 'get_object_property',
                                       self.session.vim,
                                       moref,
                                       property_name
                                       )

    @staticmethod
    def make_moref(value, type_):
        return vim_util.get_moref(value, type_)

    def get_vswitches_from_host(self, host):
        """Returns vswitches from host

        :param host: mob
        :return:  list
        """
        return self.get_property(host.obj,
                                 "config.network.vswitch")

    def get_proxyswitches_from_host(self, host):
        """Returns proxy switches in host

        :param host:
        :return:  list
        """
        return self.get_property(host.obj,
                                 "config.network.proxySwitch")

    def get_host_pnics(self, host):
        """Returns list of pnics in host

        :param host: host
        :return: returns a list of pnic mobs
        """
        return self.get_property(host.obj, "config.network.pnic")[0]

    def get_used_pnics_keys_in_host(self, host):
        """Returns keys pointing to used pnics in host

        :param host: mob
        :return: a set of keys pointing to pnics not used in the host
        """
        used_pnics = []
        for vswitch in self.get_vswitches_from_host(host):
            if hasattr(vswitch, "pnic"):
                used_pnics += vswitch.pnic
        for pswitch in self.get_proxyswitches_from_host(host):
            if hasattr(pswitch, "pnic"):
                used_pnics += pswitch.pnic
        return set(used_pnics)

    def get_all_pnic_keys_in_host(self, host):
        """Returns keys pointing to pnics in host

        :param host:
        :return: a set of keys pointing to all pnics on host
        """
        return {pnic.key for pnic in self.get_host_pnics(host) if host}

    def get_free_pnics_keys_in_host(self, host):
        """Returns keys pointing to free pnics in host

        :param host: mob
        :return: a set of free (not in use) pnic keys for host
        """
        _used = self.get_used_pnics_keys_in_host(host)
        _all = self.get_all_pnic_keys_in_host(host)
        return _all.difference(_used)


class DistributedVirtualSwitch(VcenterProxy):

    def __str__(self):

        return '\n'.join(["{} = '{}'".format(key, self.__dict__[key])
                          for key in self.__dict__])

    __repr__ = __str__

    def __init__(self, dvs_name, pnic_devices=None, max_mtu=1500,
                 host_names=None,
                 description=None, max_ports=3000, datacenter_name=None,
                 cluster_name=None,
                 **kwargs):
        super(DistributedVirtualSwitch, self).__init__(dvs_name, **kwargs)
        self.type = 'dvSwitch'
        if pnic_devices is None:
            pnic_devices = []
        self.pnic_keys = {"key-vim.host.PhysicalNic-" + device
                          for device in pnic_devices}
        self.max_mtu = max_mtu
        self.host_names = host_names
        self.description = description
        self.max_ports = max_ports
        self.datacenter_name = datacenter_name
        self.cluster_name = cluster_name
        self.hosts = None

    def collect_data_from_vcenter(self):

        # Lets get hosts ready
        if self.session is None or len(self.host_names) == 0:
            self.hosts = []
        else:
            self.hosts = [self.get_mob_by_name("HostSystem", host_name)
                          for host_name in self.host_names]

    @property
    def create_spec(self):
        spec = self.get_type('DVSCreateSpec')
        spec.productInfo = self.get_type('DistributedVirtualSwitchProductSpec')
        spec.productInfo.version = ''.join([const.MIN_SUPPORTED_VERSION, '.0'])
        spec.configSpec = self.config_spec
        return spec

    @property
    def config_spec(self):
        if self.session is None:
            return None
        self.collect_data_from_vcenter()
        spec = self.get_type('VMwareDVSConfigSpec')
        spec.name = self.name
        spec.description = self.description
        spec.maxPorts = self.max_ports
        spec.maxMtu = self.max_mtu
        spec.uplinkPortPolicy = self.uplink_port_policy
        spec.host = self.list_of_host_member_config_specs
        return spec

    @property
    def list_of_host_member_config_specs(self):
        if self.hosts is None:
            return []
        return [self.host_member_config_spec_for(host) for host in self.hosts
                if host]

    def host_member_config_spec_for(self, host):
        spec = self.get_type("DistributedVirtualSwitchHostMemberConfigSpec")
        spec.operation = self.get_type("ConfigSpecOperation").add
        spec.host = host.obj
        spec.backing = self.get_host_member_backing(host)
        return spec

    def get_host_member_backing(self, host):
        available_devices = self.get_available_pnic_devices(host)
        if available_devices:
            return self.host_member_pnic_backing(available_devices)

    def get_available_pnic_devices(self, host):
        _free = self.get_free_pnics_keys_in_host(host)

        _available_keys = _free.intersection(self.pnic_keys)
        return [_key.replace("key-vim.host.PhysicalNic-", "")
                for _key in _available_keys]

    def host_member_pnic_backing(self, p_devices):
        pnic_backing = self.get_type(
            'DistributedVirtualSwitchHostMemberPnicBacking')
        pnic_backing.pnicSpec = [self.host_member_pnic_spec(device)
                                 for device in p_devices]
        return pnic_backing

    def host_member_pnic_spec(self, device):
        spec = self.get_type('DistributedVirtualSwitchHostMemberPnicSpec')
        spec.pnicDevice = device
        return spec

    @property
    def uplink_port_policy(self):
        policy = self.get_type('DVSNameArrayUplinkPortPolicy')
        policy.uplinkPortName = self.uplink_port_names
        return policy

    @property
    def uplink_port_names(self):
        if self.pnic_keys:
            return [''.join(['dvUplink', str(c)]) for c, nic in
                    enumerate(self.pnic_keys)]
        return ['dvUplink']

    @property
    def datacenter(self):
        return self.get_mob_by_name('Datacenter', self.datacenter_name)

    @property
    def networkfolder(self):
        _dc_network = self.get_property(self.datacenter.obj, "networkFolder")
        return self.get_mob_by_mobid('Folder', _dc_network.value)

    @property
    def networkfolder_moref(self):
        return self.networkfolder.obj

    def create_on_vcenter(self):
        """Creates DVS on vCenter server

        :raises VimException, VimFaultException, VimAttributeException,
                 VimSessionOverLoadException, VimConnectionException

        """
        task = self.session.invoke_api(self.session.vim,
                                       'CreateDVS_Task',
                                       self.networkfolder_moref,
                                       spec=self.create_spec)

        self.session.wait_for_task(task)


class DVSPortGroup(VcenterProxy):

    def __init__(self, name,
                 vlan_type=None,
                 vlan_id=None,
                 vlan_range_start=0,
                 vlan_range_end=4094,
                 dvs_name=None,
                 nic_teaming=None,
                 description=None,
                 allow_promiscuous=False,
                 forged_transmits=False,
                 auto_expand=True,
                 **kwargs):
        super(DVSPortGroup, self).__init__(name, **kwargs)
        self.vlan_type = vlan_type
        self.vlan_id = vlan_id
        self.vlan_range_start = vlan_range_start
        self.vlan_range_end = vlan_range_end
        self.dvs_name = dvs_name
        self.nic_teaming = nic_teaming
        self.description = description
        self.allow_promiscuous = allow_promiscuous
        self.forged_transmits = forged_transmits
        self.auto_expand = auto_expand
        if self.nic_teaming is None:
            self.nic_teaming = {'notify_switches': True,
                                'network_failover_detection': True,
                                'load_balancing': 'loadbalance_srcid',
                                'active_nics': []}

    def __str__(self):

        return '\n'.join(["{} = '{}'".format(key, self.__dict__[key])
                          for key in self.__dict__])

    @property
    def config_spec(self):
        spec = self.get_type('DVPortgroupConfigSpec')
        spec.name = self.name
        spec.description = self.description
        spec.autoExpand = True
        spec.type = self.get_type(
            'DistributedVirtualPortgroupPortgroupType').earlyBinding
        spec.defaultPortConfig = self.dvs_port_settings
        return spec

    @property
    def dvs_port_settings(self):
        port_settings = self.get_type('VMwareDVSPortSetting')
        port_settings.vlan = self.vlan_spec
        port_settings.vlan.vlanId = self.vlan_spec_id
        port_settings.vlan.inherited = False
        port_settings.securityPolicy = self.security_policy
        port_settings.uplinkTeamingPolicy = self.uplink_teaming_policy
        return port_settings

    @property
    def vlan_spec(self):
        if self.vlan_type == const.VLAN_TYPE_TRUNK:
            return self.get_type('VmwareDistributedVirtualSwitchTrunkVlanSpec')
        return self.get_type('VmwareDistributedVirtualSwitchVlanIdSpec')

    @property
    def vlan_spec_id(self):
        if str(self.vlan_type).lower() == str(const.VLAN_TYPE_TRUNK).lower():
            vlan_range = self.get_type('NumericRange')
            vlan_range.start = self.vlan_range_start
            vlan_range.end = self.vlan_range_end
            return vlan_range

        if self.vlan_id is None:
            return 0
        return self.vlan_id

    @property
    def security_policy(self):
        policy = self.get_type('DVSSecurityPolicy')
        policy.inherited = False
        policy.allowPromiscuous = self.get_type('BoolPolicy')
        policy.allowPromiscuous.inherited = False
        policy.allowPromiscuous.value = self.allow_promiscuous
        policy.forgedTransmits = self.get_type('BoolPolicy')
        policy.forgedTransmits.inherited = False
        policy.forgedTransmits.value = self.forged_transmits
        return policy

    @property
    def uplink_teaming_policy(self):
        policy = self.get_type('VmwareUplinkPortTeamingPolicy')
        policy.inherited = False

        policy.notifySwitches = self.get_type('BoolPolicy')
        policy.notifySwitches.inherited = False
        policy.notifySwitches.value = self.nic_teaming['notify_switches']

        policy.failureCriteria = self.get_type('DVSFailureCriteria')
        policy.failureCriteria.inherited = False
        policy.failureCriteria.checkBeacon = self.get_type('BoolPolicy')
        policy.failureCriteria.checkBeacon.inherited = False
        policy.failureCriteria.checkBeacon.value = self.nic_teaming[
            'network_failover_detection']

        policy.policy.inherited = False
        policy.policy.value = self.nic_teaming['load_balancing']

        policy.uplinkPortOrder = self.get_type('VMwareUplinkPortOrderPolicy')
        policy.uplinkPortOrder.activeUplinkPort = self.nic_teaming[
            'active_nics']

        return policy

    def create_on_vcenter(self):
        dvs = self.get_mob_by_name('DistributedVirtualSwitch',
                                   self.dvs_name)
        task = self.session.invoke_api(self.session.vim,
                                       'AddDVPortgroup_Task',
                                       dvs.obj,
                                       spec=self.config_spec)

        self.session.wait_for_task(task)
