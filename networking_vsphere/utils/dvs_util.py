# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import six
from time import sleep
import uuid

from oslo_log import log
from oslo_vmware import api
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware import vim_util
from requests.exceptions import ConnectionError

from networking_vsphere._i18n import _LI, _LW, _LE
from networking_vsphere.common import constants as dvs_const
from networking_vsphere.common import exceptions
from networking_vsphere.common import vmware_conf as config
from networking_vsphere.utils import spec_builder


CONF = config.CONF
LOG = log.getLogger(__name__)

CREATING_PG_STATUS = 'creating'
READY_PG_STATUS = 'ready'
UPDATING_PG_STATUS = 'updating'
REMOVING_PG_STATUS = 'removing'

MAX_OBJECTS_COUNT_TO_RETURN = 100


class DVSController(object):
    """Controls one DVS."""

    def __init__(self, dvs_name, cluster_name, connection):
        self.connection = connection
        self.dvs_name = dvs_name
        self._blocked_ports = set()
        self.builder = spec_builder.SpecBuilder(
            self.connection.vim.client.factory)
        self.uplink_map = {}
        try:
            self._dvs, self._dvs_uuid, self._inventory = \
                self._get_dvs(dvs_name, cluster_name, connection)
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def load_uplinks(self, phys, uplinks):
        self.uplink_map[phys] = uplinks

    def check_free(self, key):
        criteria = self.builder.port_criteria(port_key=key)
        criteria.connected = True
        connected_port_keys = set(
            self.connection.invoke_api(self.connection.vim,
                                       'FetchDVPortKeys',
                                       self._dvs, criteria=criteria))
        return key not in connected_port_keys

    def create_network(self, network, segment):
        name = self._get_net_name(network)
        blocked = not network['admin_state_up']
        uplinks = self.uplink_map.get(network['provider:physical_network'])
        try:
            pg_spec = self._build_pg_create_spec(
                name, segment['segmentation_id'], blocked, uplinks)
            pg_create_task = self.connection.invoke_api(
                self.connection.vim,
                'CreateDVPortgroup_Task',
                self._dvs, spec=pg_spec)

            result = self.connection.wait_for_task(pg_create_task)
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)
        else:
            pg = result.result
            LOG.info(_LI('Network %(name)s created \n%(pg_ref)s'),
                     {'name': name, 'pg_ref': pg})
            return pg

    def update_network(self, network, original=None):
        original_name = self._get_net_name(original) if original else None
        current_name = self._get_net_name(network)
        blocked = not network['admin_state_up']
        try:
            pg_ref = self._get_pg_by_name(original_name or current_name)
            pg_config_info = self._get_config_by_ref(pg_ref)
            if (pg_config_info.defaultPortConfig.blocked.value != blocked or
                    (original_name and original_name != current_name)):
                # we upgrade only defaultPortConfig, because it is inherited
                # by all ports in PortGroup, unless they are explicit
                # overwritten on specific port.
                pg_spec = self._build_pg_update_spec(
                    pg_config_info.configVersion,
                    blocked=blocked)
                pg_spec.name = current_name
                pg_update_task = self.connection.invoke_api(
                    self.connection.vim,
                    'ReconfigureDVPortgroup_Task',
                    pg_ref, spec=pg_spec)

                self.connection.wait_for_task(pg_update_task)
                LOG.info(_LI('Network %(name)s updated'),
                         {'name': current_name})
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def delete_network(self, network):
        name = self._get_net_name(network)
        try:
            pg_ref = self._get_pg_by_name(name)
        except exceptions.PortGroupNotFound:
            LOG.debug('Network %s is not present in vcenter. '
                      'Nothing to delete.', name)
            return
        self._delete_port_group(pg_ref, name)

    def delete_networks_without_active_ports(self, pg_keys_with_active_ports):
        for pg_ref in self._get_all_port_groups():
            if pg_ref.value not in pg_keys_with_active_ports:
                # check name
                try:
                    name = self.connection.invoke_api(
                        vim_util, 'get_object_property',
                        self.connection.vim, pg_ref, 'name')
                    name_tokens = name.split(self.dvs_name)
                    if (len(name_tokens) == 2 and not name_tokens[0] and
                            self._valid_uuid(name_tokens[1])):
                        self._delete_port_group(pg_ref, name)
                except vmware_exceptions.VMwareDriverException as e:
                    if dvs_const.DELETED_TEXT in e.message:
                        pass

    def _delete_port_group(self, pg_ref, name):
        remove_used_pg_try = 0
        while True:
            try:
                pg_delete_task = self.connection.invoke_api(
                    self.connection.vim,
                    'Destroy_Task',
                    pg_ref)
                self.connection.wait_for_task(pg_delete_task)
                LOG.info(_LI('Network %(name)s deleted.'), {'name': name})
                break
            except vmware_exceptions.VimException as e:
                if dvs_const.RESOURCE_IN_USE in e.message:
                    remove_used_pg_try += 1
                    if remove_used_pg_try > 3:
                        LOG.info(_LI('Network %(name)s was not deleted. Active'
                                     ' ports were found'), {'name': name})
                        break
                    else:
                        sleep(0.2)
                else:
                    raise exceptions.wrap_wmvare_vim_exception(e)
            except vmware_exceptions.VMwareDriverException as e:
                if dvs_const.DELETED_TEXT in e.message:
                    sleep(0.1)
                else:
                    raise

    def switch_port_blocked_state(self, port):
        try:
            port_info = self.get_port_info(port)
            port_settings = self.builder.port_setting()
            state = not port['admin_state_up']
            port_settings.blocked = self.builder.blocked(state)

            update_spec = self.builder.port_config_spec(
                port_info.config.configVersion, port_settings)
            update_spec.key = port_info.key
            update_task = self.connection.invoke_api(
                self.connection.vim, 'ReconfigureDVPort_Task',
                self._dvs, port=[update_spec])
            self.connection.wait_for_task(update_task)
        except exceptions.PortNotFound:
            LOG.debug("Port %s was not found. Nothing to block.", port['id'])
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def _lookup_unbound_port_or_increase_pg(self, pg):
        while True:
            try:
                port_info = self._lookup_unbound_port(pg)
                break
            except exceptions.UnboundPortNotFound:
                try:
                    self._increase_ports_on_portgroup(pg)
                except (vmware_exceptions.VMwareDriverException,
                        exceptions.VMWareDVSException) as e:
                    if dvs_const.CONCURRENT_MODIFICATION_TEXT in e.message:
                        LOG.info(_LI('Concurrent modification on '
                                     'increase port group.'))
                        continue
                    raise e
        return port_info

    def book_port(self, network, port_name, segment, net_name=None):
        try:
            if not net_name:
                net_name = self._get_net_name(network)
            pg = self._get_or_create_pg(net_name, network, segment)
            for iter in range(0, 4):
                try:
                    port_info = self._lookup_unbound_port_or_increase_pg(pg)

                    port_settings = self.builder.port_setting()
                    port_settings.blocked = self.builder.blocked(False)
                    update_spec = self.builder.port_config_spec(
                        port_info.config.configVersion, port_settings,
                        name=port_name)
                    update_spec.key = port_info.key
                    update_task = self.connection.invoke_api(
                        self.connection.vim, 'ReconfigureDVPort_Task',
                        self._dvs, port=[update_spec])
                    self.connection.wait_for_task(update_task)
                    return {'key': port_info.key,
                            'dvs_uuid': self._dvs_uuid,
                            'pg_key': pg.value}
                except vmware_exceptions.VimException as e:
                    sleep(0.1)
            raise exceptions.wrap_wmvare_vim_exception(e)
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def release_port(self, port):
        try:
            port_info = self.get_port_info(port)
            update_spec = self.builder.port_config_spec(
                port_info.config.configVersion, name='')
            update_spec.key = port_info.key
            update_spec.operation = 'remove'
            self.connection.invoke_api(
                self.connection.vim, 'ReconfigureDVPort_Task',
                self._dvs, port=[update_spec])
            self.remove_block(port_info.key)
        except exceptions.PortNotFound:
            LOG.debug("Port %s was not found. Nothing to delete.", port['id'])
        except vmware_exceptions.VimException as e:
            if dvs_const.RESOURCE_IN_USE in e.message:
                LOG.debug("Port %s in use, couldn't be deleted.", port['id'])
            else:
                raise exceptions.wrap_wmvare_vim_exception(e)

    def remove_block(self, port_key):
        self._blocked_ports.discard(port_key)

    def _build_pg_create_spec(self, name, vlan_tag, blocked, uplinks):
        port_setting = self.builder.port_setting()

        port_setting.vlan = self.builder.vlan(vlan_tag)
        port_setting.blocked = self.builder.blocked(blocked)

        port_setting.filterPolicy = self.builder.filter_policy([])
        if uplinks:
            port_setting.uplinkTeamingPolicy.inherited = False
            port_setting.uplinkTeamingPolicy.uplinkPortOrder.inherited = False
            port_setting.uplinkTeamingPolicy.uplinkPortOrder. \
                activeUplinkPort = uplinks['active']
            port_setting.uplinkTeamingPolicy.uplinkPortOrder. \
                standbyUplinkPort = uplinks['passive']
            for key in uplinks:
                if key.startswith('uplink_'):
                    ul_object = getattr(port_setting.uplinkTeamingPolicy,
                                        key.replace('uplink_', '', 1))
                    ul_object.value = uplinks[key]
                    ul_object.inherited = False

        pg = self.builder.pg_config(port_setting)
        pg.name = name
        pg.numPorts = CONF.DVS.init_pg_ports_count

        # Equivalent of vCenter static binding type.
        pg.type = 'earlyBinding'
        pg.description = 'Managed By Neutron'
        return pg

    def _build_pg_update_spec(self, config_version,
                              blocked=None,
                              ports_number=None):
        port = self.builder.port_setting()
        if blocked is not None:
            port.blocked = self.builder.blocked(blocked)
        pg = self.builder.pg_config(port)
        if ports_number:
            pg.numPorts = ports_number
        pg.configVersion = config_version
        return pg

    def _get_dvs(self, dvs_name, cluster_name, connection):
        """Get the dvs by name"""
        cluster = None
        if cluster_name:
            clusters = self.connection.invoke_api(
                vim_util, 'get_objects', self.connection.vim,
                'ClusterComputeResource', MAX_OBJECTS_COUNT_TO_RETURN,
                ['name']).objects
            for cluster_item in clusters:
                cluster_item = cluster_item.obj
                name = connection.invoke_api(
                    vim_util, 'get_object_property',
                    connection.vim, cluster_item, 'name')
                if name == cluster_name:
                    cluster = cluster_item
                    break
            else:
                raise exceptions.ClusterNotFound(cluster_name=cluster_name)

        dcs = connection.invoke_api(
            vim_util, 'get_objects', connection.vim,
            'Datacenter', MAX_OBJECTS_COUNT_TO_RETURN, ['name']).objects
        for dc in dcs:
            datacenter = dc.obj
            network_folder = connection.invoke_api(
                vim_util, 'get_object_property', connection.vim,
                datacenter, 'networkFolder')
            results = connection.invoke_api(
                vim_util, 'get_object_property', connection.vim,
                network_folder, 'childEntity')
            if results:
                networks = results.ManagedObjectReference
                # Search between top-level dvswitches, if any
                dvswitches = self._get_object_by_type(
                    networks, 'VmwareDistributedVirtualSwitch')
                for dvs in dvswitches:
                    dvs_properties = connection.invoke_api(
                        vim_util, 'get_object_properties_dict',
                        connection.vim, dvs, ['name', 'uuid'])
                    if dvs_properties['name'] == dvs_name:
                        return (dvs, dvs_properties['uuid'],
                                cluster or datacenter)
                # if we still haven't found it, search sub-folders
                dvswitches = self._search_inside_folders(networks,
                                                         connection)
                for dvs in dvswitches:
                    dvs_properties = connection.invoke_api(
                        vim_util, 'get_object_properties_dict',
                        connection.vim, dvs, ['name', 'uuid'])
                    if dvs_properties['name'] == dvs_name:
                        return (dvs, dvs_properties['uuid'],
                                cluster or datacenter)
        raise exceptions.DVSNotFound(dvs_name=dvs_name)

    def _search_inside_folders(self, net_folders, connection):
        dvs_list = []
        folders = self._get_object_by_type(net_folders, 'Folder')
        for folder in folders:
            results = connection.invoke_api(
                vim_util, 'get_object_property', connection.vim,
                folder, 'childEntity').ManagedObjectReference
            dvs = self._get_object_by_type(results,
                                           'VmwareDistributedVirtualSwitch')
            if dvs:
                dvs_list += dvs
        return dvs_list

    def _get_pg_by_name(self, pg_name):
        """Get the dpg ref by name"""
        for pg in self._get_all_port_groups():
            try:
                name = self.connection.invoke_api(
                    vim_util, 'get_object_property',
                    self.connection.vim, pg, 'name')
                if pg_name == name:
                    return pg
            except vmware_exceptions.VimException:
                pass
        raise exceptions.PortGroupNotFound(pg_name=pg_name)

    def _get_all_port_groups(self):
        net_list = self.connection.invoke_api(
            vim_util, 'get_object_property', self.connection.vim,
            self._inventory, 'network').ManagedObjectReference
        type_value = 'DistributedVirtualPortgroup'
        return self._get_object_by_type(net_list, type_value)

    def _get_or_create_pg(self, pg_name, network, segment):
        try:
            return self._get_pg_by_name(pg_name)
        except exceptions.PortGroupNotFound:
            LOG.debug('Network %s is not present in vcenter. Perform network '
                      'creation', pg_name)
            return self.create_network(network, segment)

    def _get_config_by_ref(self, ref):
        """pg - ManagedObjectReference of Port Group"""
        return self.connection.invoke_api(
            vim_util, 'get_object_property',
            self.connection.vim, ref, 'config')

    def _get_net_name(self, network):
        # TODO(dbogun): check network['bridge'] generation algorithm our
        # must match it

        return self.dvs_name + network['id']

    @staticmethod
    def _get_object_by_type(results, type_value):
        """Get object by type.

        Get the desired object from the given objects result by the given type.
        """
        return [obj for obj in results if obj._type == type_value]

    def _get_ports_for_pg(self, pg_name):
        pg = self._get_pg_by_name(pg_name)
        return self.connection.invoke_api(
            vim_util, 'get_object_property',
            self.connection.vim, pg, 'portKeys')[0]

    def _get_free_pg_keys(self, port_group):
        criteria = self.builder.port_criteria(
            port_group_key=port_group.value)
        all_port_keys = set(
            self.connection.invoke_api(self.connection.vim,
                                       'FetchDVPortKeys',
                                       self._dvs, criteria=criteria))
        criteria.connected = True
        connected_port_keys = set(
            self.connection.invoke_api(self.connection.vim,
                                       'FetchDVPortKeys',
                                       self._dvs, criteria=criteria))
        return list(all_port_keys - connected_port_keys - self._blocked_ports)

    def _lookup_unbound_port(self, port_group):
        for port_key in self._get_free_pg_keys(port_group):
            self._blocked_ports.add(port_key)
            p_info = self._get_port_info_by_portkey(port_key)
            if not getattr(p_info.config, 'name', None):
                return p_info
        raise exceptions.UnboundPortNotFound()

    def _increase_ports_on_portgroup(self, port_group):
        pg_info = self._get_config_by_ref(port_group)
        # TODO(ekosareva): need to have max size of ports number
        ports_number = max(CONF.DVS.init_pg_ports_count, pg_info.numPorts * 2)
        pg_spec = self._build_pg_update_spec(
            pg_info.configVersion, ports_number=ports_number)
        pg_update_task = self.connection.invoke_api(
            self.connection.vim,
            'ReconfigureDVPortgroup_Task',
            port_group, spec=pg_spec)
        self.connection.wait_for_task(pg_update_task)

    def get_port_info(self, port):
        key = port.get('binding:vif_details', {}).get('dvs_port_key')
        if key is not None:
            port_info = self._get_port_info_by_portkey(key)
        else:
            port_info = self._get_port_info_by_name(port['id'])
        return port_info

    def _get_port_info_by_portkey(self, port_key):
        """pg - ManagedObjectReference of Port Group"""
        criteria = self.builder.port_criteria(port_key=port_key)
        port_info = self.connection.invoke_api(
            self.connection.vim,
            'FetchDVPorts',
            self._dvs, criteria=criteria)
        if not port_info:
            raise exceptions.PortNotFound(id=port_key)
        return port_info[0]

    def _get_port_info_by_name(self, name, port_list=None):
        if port_list is None:
            port_list = self.get_ports(None)
        ports = [port for port in port_list if port.config.name == name]
        if not ports:
            raise exceptions.PortNotFound(id=name)
        if len(ports) > 1:
            LOG.warning(_LW("Multiple ports found for name %s."), name)
        return ports[0]

    def get_ports(self, connect_flag=True):
        criteria = self.builder.port_criteria(connected=connect_flag)
        ports = self.connection.invoke_api(
            self.connection.vim,
            'FetchDVPorts',
            self._dvs, criteria=criteria)
        p_ret = []
        for port in ports:
            if (getattr(port.config, 'name', None) is not None and
                    self._valid_uuid(port.config.name)):
                p_ret.append(port)
        return p_ret

    def _get_ports_ids(self):
        return [port.config.name for port in self.get_ports()]

    def _valid_uuid(self, name):
        try:
            uuid.UUID(name, version=4)
        except ValueError:
            return False
        return True


class DVSControllerWithCache(DVSController):
    def __init__(self, dvs_name, cluster_name, connection):
        super(DVSControllerWithCache, self).__init__(
            dvs_name, cluster_name, connection)
        self._init_pg_cache()

    def _init_pg_cache(self):
        self._pg_cache = {}
        for pg in self._get_all_port_groups():
            name = self.connection.invoke_api(
                vim_util, 'get_object_property',
                self.connection.vim, pg, 'name')
            self._pg_cache[name] = {
                'item': pg,
                'status': READY_PG_STATUS,
                'pg_key': pg.value
            }

    def _wait_port_group_stable_status(self, pg_name,
                                       waiting_status_list=(READY_PG_STATUS,)):
        while (pg_name in self._pg_cache and
               self._pg_cache[pg_name]['status'] not in waiting_status_list):
            sleep(CONF.DVS.cache_pool_interval)

    def _create_missed_pg_by_ref(self, pg_ref):
        pg_info = self._get_config_by_ref(pg_ref)
        self._get_or_create_pg(
            pg_ref.config.name,
            {'id': pg_info.name.replace(self.dvs_name, '', 1),
             'admin_state_up': pg_info.defaultPortConfig.blocked.value},
            {'segmentation_id': pg_info.defaultPortConfig.vlan.vlanId}
        )

    def create_network(self, network, segment):
        name = self._get_net_name(network)
        self._wait_port_group_stable_status(
            name, (READY_PG_STATUS, UPDATING_PG_STATUS))
        if name in self._pg_cache and self._pg_cache[name]['item']:
            return self._pg_cache[name]['item']

        self._pg_cache.setdefault(name, {}).update({
            'item': None,
            'status': CREATING_PG_STATUS,
            'pg_key': None
        })
        try:
            pg = super(DVSControllerWithCache, self).create_network(
                network, segment)
        except exceptions.VMWareDVSException as e:
            if dvs_const.DUPLICATE_NAME in str(e):
                pg = super(DVSControllerWithCache, self)._get_pg_by_name(name)
            else:
                self._pg_cache.pop(name)
                raise e
        self._pg_cache[name].update({
            'item': pg,
            'status': READY_PG_STATUS,
            'pg_key': pg.value
        })
        return pg

    def _delete_port_group(self, pg_ref, name):
        self._wait_port_group_stable_status(name)
        if name not in self._pg_cache:
            LOG.info(_LI('Network %(name)s has been already deleted. '
                         'Nothing to do.'), {'name': name})
            return

        self._pg_cache[name].update({'status': REMOVING_PG_STATUS})
        try:
            super(DVSControllerWithCache, self).\
                _delete_port_group(pg_ref, name)
        except Exception as e:
            if dvs_const.DELETED_TEXT not in str(e):
                self._pg_cache[name].update({'status': READY_PG_STATUS})
                raise e
        self._pg_cache.pop(name, None)

    def _get_pg_by_name(self, pg_name):
        if pg_name not in self._pg_cache:
            # if pg not in cache, try to find port group on vsphere
            pg = super(DVSControllerWithCache, self)._get_pg_by_name(pg_name)
            self._pg_cache.setdefault(pg_name, {}).update({
                'item': pg,
                'status': READY_PG_STATUS,
                'pg_key': pg.value
            })
            return pg
        if self._pg_cache.get(pg_name, {}).get('status') in (
                READY_PG_STATUS, UPDATING_PG_STATUS, REMOVING_PG_STATUS):
            return self._pg_cache[pg_name]['item']
        raise exceptions.PortGroupNotFound(pg_name=pg_name)

    def _increase_ports_on_portgroup(self, port_group):
        pg_name = next((name for name, pg in six.iteritems(self._pg_cache)
                        if pg.get('pg_key') == port_group.value), None)
        prev_status = self._pg_cache.get(pg_name, {}).get('status')
        self._wait_port_group_stable_status(pg_name)
        if prev_status == UPDATING_PG_STATUS:
            return

        if pg_name not in self._pg_cache:
            self._create_missed_pg_by_ref(port_group)

        self._pg_cache[pg_name].update({'status': UPDATING_PG_STATUS})
        try:
            super(DVSControllerWithCache, self).\
                _increase_ports_on_portgroup(port_group)
        finally:
            self._pg_cache[pg_name].update({'status': READY_PG_STATUS})

    def _refill_free_cached_ports(self, pg_name, port_group):
        free_port_keys = self._get_free_pg_keys(port_group)
        self._pg_cache[pg_name].update({
            'free_ports_count': len(free_port_keys),
            'free_cached_ports':
                free_port_keys[:CONF.DVS.cache_free_ports_size]
        })

    def _lookup_unbound_port(self, port_group):
        pg_name = next((name for name, pg in six.iteritems(self._pg_cache)
                        if pg.get('pg_key') == port_group.value), None)
        self._wait_port_group_stable_status(pg_name)

        if pg_name not in self._pg_cache:
            self._create_missed_pg_by_ref(port_group)

        if not self._pg_cache[pg_name].get('free_cached_ports'):
            self._refill_free_cached_ports(pg_name, port_group)

        while self._pg_cache[pg_name]['free_ports_count'] > 0:
            pg_cache_item = self._pg_cache[pg_name].get('free_cached_ports')
            while pg_cache_item:
                port_key = pg_cache_item.pop()
                self._pg_cache[pg_name]['free_ports_count'] -= 1
                if port_key not in self._blocked_ports:
                    self._blocked_ports.add(port_key)
                    p_info = self._get_port_info_by_portkey(port_key)
                    if not getattr(p_info.config, 'name', None):
                        return p_info
            # free cached ports is ended, but free pg keys exist on vSphere,
            # refill free_cached_ports in pg_cache
            if self._pg_cache[pg_name]['free_ports_count'] > 0:
                self._refill_free_cached_ports(pg_name, port_group)
        raise exceptions.UnboundPortNotFound()


def create_network_map_from_config(config, pg_cache=False):
    """Creates physical network to dvs map from config"""
    connection = None
    while not connection:
        try:
            connection = api.VMwareAPISession(
                host=config.vsphere_hostname,
                port=config.host_port,
                server_username=config.vsphere_login,
                server_password=config.vsphere_password,
                api_retry_count=config.api_retry_count,
                task_poll_interval=config.task_poll_interval,
                scheme='https',
                create_session=True,
                cacert=config.ca_file,
                insecure=config.insecure,
                pool_size=config.connections_pool_size)
        except ConnectionError:
            LOG.error(_LE("No connection to vSphere. Retry in 10 sec..."))
            sleep(10)
    network_map = {}
    controller_class = DVSControllerWithCache if pg_cache else DVSController
    for pair in config.network_maps:
        network, dvs = pair.split(':')
        network_map[network] = controller_class(dvs, config.cluster_name,
                                                connection)
    return network_map


def create_uplink_map_from_config(config, network_map):
    uplink_policies = ['loadbalance_srcid', 'loadbalance_srcmac',
                       'loadbalance_loadbased', 'loadbalance_ip',
                       'failover_explicit']
    failover_keys = ['uplink_notifySwitches', 'uplink_rollingOrder',
                     'uplink_reversePolicy']
    uplink_map = {}
    for mapping in config.uplink_maps:
        net_conf = mapping.split(':')
        if len(net_conf) not in (2, 3):
            raise ValueError("Invalid uplink mapping: '%s'" % mapping)
        phys_net = net_conf[0]
        active = net_conf[1].split(';')
        passive = net_conf[2].split(';') if len(net_conf) == 3 else []
        if phys_net in network_map:
            dvs = network_map[phys_net]
            conf = dvs._get_config_by_ref(dvs._dvs)
            uplinks = conf.uplinkPortPolicy.uplinkPortName
            for uplink in set(active + passive):
                if uplink not in uplinks:
                    raise ValueError("Invalid uplink mapping: '%s'" % mapping)
            uplink_map[phys_net] = {'active': active,
                                    'passive': passive}
            for key in failover_keys:
                if getattr(config, key) is not None:
                    uplink_map[phys_net][key] = getattr(config, key)
            if config.uplink_policy in uplink_policies:
                uplink_map[phys_net]['uplink_policy'] = config.uplink_policy
    return uplink_map


def create_port_map(dvs_list):
    port_map = {}
    for dvs in dvs_list:
        port_map[dvs] = dvs._get_ports_ids()

    return port_map


def get_dvs_by_uuid(dvs_list, uuid):
    for dvs in dvs_list:
        if dvs._dvs_uuid == uuid:
            return dvs
    return None


def wrap_retry(func):
    """Retry operation on dvs when concurrent modification was discovered."""
    @six.wraps(func)
    def wrapper(*args, **kwargs):
        login_failures = 0
        while True:
            try:
                return func(*args, **kwargs)
            except (vmware_exceptions.VMwareDriverException,
                    exceptions.VMWareDVSException) as e:
                if dvs_const.CONCURRENT_MODIFICATION_TEXT in str(e):
                    continue
                elif (dvs_const.LOGIN_PROBLEM_TEXT in str(e) and
                        login_failures < dvs_const.LOGIN_RETRIES - 1):
                    login_failures += 1
                    continue
                else:
                    raise
    return wrapper
