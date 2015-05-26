# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
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
import atexit
from neutron.common import exceptions
from neutron.i18n import _LI
from neutron.tests.api import base
from neutron.tests.api import base_security_groups
from neutron.tests.api import clients
from neutron.tests.tempest import manager
from neutron.tests.tempest import test
import time

from networking_vsphere.tests.tempest import config

from oslo_log import log
from oslo_serialization import jsonutils
from pyVim import connect
from pyVim.connect import Disconnect
from pyVmomi import vim
import six
from tempest_lib.common import rest_client
from tempest_lib.common.utils import data_utils
from tempest_lib.common.utils import misc as misc_utils
from tempest_lib import exceptions as lib_exc

CONF = config.CONF

LOG = log.getLogger(__name__)


class NetworksTestjsonutils(base.BaseAdminNetworkTest,
                            base_security_groups.BaseSecGroupTest):

    @classmethod
    def resource_setup(cls):
        super(NetworksTestjsonutils, cls).resource_setup()
        admin_manager = clients.AdminManager()
        cls.identity_admin_client = admin_manager.identity_client
        cls.auth_provider = manager.get_auth_provider(
            cls.isolated_creds.get_primary_creds())
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)
        cls.ext_net_id = CONF.network.public_network_id

        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.tenant_cidr = (CONF.network.tenant_network_cidr
                           if cls._ip_version == 4 else
                           CONF.network.tenant_network_v6_cidr)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id,
                                       admin_state_up="true")
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = list()
        cls.floating_ip = cls.create_floatingip(cls.ext_net_id)

    def setUp(self):
        super(NetworksTestjsonutils, self).setUp()
        self.portgroup_list = []
        self.segmentid_list = []
        self.portgroup_deleted_list = []
        self.segmentid_deleted_list = []

    def get_obj(self, content, vimtype, name):
        """Get the vsphere object associated with a given text name."""
        obj = None
        container = content.viewManager.CreateContainerView(content.rootFolder,
                                                            vimtype, True)
        for c in container.view:
                if c.name == name:
                    obj = c
                    break
        return obj

    def vsphere(self, vcenter_ip, vcenter_username, vcenter_password):
        si = None
        try:
                msg = 'Trying to connect .....'
                LOG.info(msg)
                si = connect.Connect(vcenter_ip, 443, vcenter_username,
                                     vcenter_password, service="hostd")
        except Exception:
            msg = ('Could not connect to the specified host')
            raise exceptions.TimeoutException(msg)
        atexit.register(Disconnect, si)
        content = si.RetrieveContent()
        return content

    def _portgroup_verify(self, portgroup, segmentid):
        vcenter_ip = CONF.network.vcenter_ip
        trunk_dvswitch_name = CONF.network.trunk_dvswitch_name
        vcenter_username = CONF.network.vcenter_username
        vcenter_password = CONF.network.vcenter_password
        content = self.vsphere(vcenter_ip, vcenter_username, vcenter_password)
        dvswitch_obj = self.get_obj(content,
                                    [vim.DistributedVirtualSwitch],
                                    trunk_dvswitch_name)
        port_groups = dvswitch_obj.portgroup
        for port_group in port_groups:
                portgroupname = port_group.name
                self.portgroup_list.append(portgroupname)
                segment_id = port_group.config.defaultPortConfig.vlan.vlanId
                self.segmentid_list.append(segment_id)
        self.assertIn(portgroup, self.portgroup_list)
        self.assertIn(segmentid, self.segmentid_list)

    def _portgroup_verify_after_server_delete(self, portgroup, segmentid):
        vcenter_ip = CONF.network.vcenter_ip
        trunk_dvswitch_name = CONF.network.trunk_dvswitch_name
        vcenter_username = CONF.network.vcenter_username
        vcenter_password = CONF.network.vcenter_password
        content = self.vsphere(vcenter_ip, vcenter_username, vcenter_password)
        dvswitch_obj = self.get_obj(content,
                                    [vim.DistributedVirtualSwitch],
                                    trunk_dvswitch_name)
        port_groups = dvswitch_obj.portgroup
        for port_group in port_groups:
                portgroupname = port_group.name
                segment_id = port_group.config.defaultPortConfig.vlan.vlanId
                self.portgroup_deleted_list.append(portgroupname)
                self.segmentid_deleted_list.append(segment_id)
        self.assertNotIn(portgroup, self.portgroup_deleted_list)
        self.assertNotIn(segmentid, self.segmentid_deleted_list)

    def _fetch_network_segmentid_and_verify_portgroup(self, network=None):
        net = self.admin_client.show_network(network)
        net_segmentid = net['network']['provider:segmentation_id']
        self._portgroup_verify(portgroup=network,
                               segmentid=net_segmentid)

    def _verify_portgroup_after_vm_delete(self, network=None):
        net = self.admin_client.show_network(network)
        net_segmentid = net['network']['provider:segmentation_id']
        self._portgroup_verify_after_server_delete(portgroup=network,
                                                   segmentid=net_segmentid)

    def _create_server_with_sec_group(self, name=None, network=None,
                                      securitygroup=None, wait_on_boot=True,
                                      wait_on_delete=True):
        region = CONF.compute.region
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           region)
        data = {"server": {"name": name, "imageRef": image,
                "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"uuid": network}],
                           "security_groups": [{"name": securitygroup}]}}

        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _create_server(self, name=None, network=None,
                       wait_on_boot=True, wait_on_delete=True):
        region = CONF.compute.region
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           region)
        data = {"server": {"name": name, "imageRef": image,
                "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"uuid": network}]}}

        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _delete_server(self, server=None):
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           "RegionOne")
        resp, body = rs_client.delete("servers/%s" % str(server))
        self.wait_for_server_termination(server)
        rest_client.ResponseBody(resp, body)

    def _associate_floating_ips(self, port_id=None):
        floating_ip_body = self.client.update_floatingip(
            self.floating_ip['id'], port_id=port_id)
        return floating_ip_body

    def wait_for_server_termination(self, server_id, ignore_error=False):
        """Waits for server to reach termination."""
        build_interval = CONF.boto.build_interval
        while True:
            try:
                region = CONF.compute.region
                rs_client = rest_client.RestClient(self.auth_provider,
                                                   "compute", region)
                resp, body = rs_client.get("servers/%s" % str(server_id))
                body = jsonutils.loads(body)
            except lib_exc.NotFound:
                return

            server_status = body['server']['status']
            if server_status == 'ERROR' and not ignore_error:
                raise exceptions.BuildErrorException(server_id=server_id)

            time.sleep(build_interval)

    def wait_for_server_status(self, server_id, status, ready_wait=True,
                               extra_timeout=0, raise_on_error=True):
        """Waits for a server to reach a given status."""
        build_timeout = CONF.compute.build_timeout
        build_interval = CONF.boto.build_interval

        def _get_task_state(body):
            return body.get('OS-EXT-STS:task_state', None)
        region = CONF.compute.region
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           region)
        resp, body = rs_client.get("servers/%s" % str(server_id))
        body = jsonutils.loads(body)
        old_status = server_status = body['server']['status']
        old_task_state = task_state = _get_task_state(body)
        start_time = int(time.time())
        timeout = build_timeout + extra_timeout
        while True:
            if status == 'BUILD' and server_status != 'UNKNOWN':
                return
            if server_status == status:
                if ready_wait:
                    if status == 'BUILD':
                        return
                    if str(task_state) == "None":
                        time.sleep(CONF.compute.ready_wait)
                        return
                else:
                    return

            time.sleep(build_interval)
            resp, body = rs_client.get("servers/%s" % str(server_id))
            body = jsonutils.loads(body)
            server_status = body['server']['status']
            task_state = _get_task_state(body)
            if (server_status != old_status) or (task_state != old_task_state):
                oldstatus = '/'.join((old_status, str(old_task_state)))
                serverstatus = '/'.join((server_status, str(task_state)))
                waitsec = (time.time() - start_time)
                LOG.info(
                    _LI('State transition %(oldstatus)s => %(serverstatus)s '
                        'after %(waitsec)d second wait') %
                    {'oldstatus': oldstatus, 'serverstatus': serverstatus,
                     'waitsec': waitsec}
                )
            if (server_status == 'ERROR') and raise_on_error:
                if 'fault' in body:
                    raise exceptions.BuildErrorException(body['fault'],
                                                         server_id=server_id)
                else:
                    raise exceptions.BuildErrorException(server_id=server_id)

            timed_out = int(time.time()) - start_time >= timeout

            if timed_out:
                expected_task_state = 'None' if ready_wait else 'n/a'
                message = ('Server %(server_id)s failed to reach %(status)s '
                           'status and task state "%(expected_task_state)s" '
                           'within the required time (%(timeout)s s).' %
                           {'server_id': server_id,
                            'status': status,
                            'expected_task_state': expected_task_state,
                            'timeout': timeout})
                message += ' Current status: %s.' % server_status
                message += ' Current task state: %s.' % task_state
                caller = misc_utils.find_test_caller()
                if caller:
                    message = '(%s) %s' % (caller, message)
                raise exceptions.TimeoutException(message)
            old_status = server_status
            old_task_state = task_state

    def _create_verify_security_group_rule(self, sg_id, direction,
                                           ethertype, protocol,
                                           port_range_min,
                                           port_range_max,
                                           remote_group_id=None,
                                           remote_ip_prefix=None):
        rule_create_body = self.client.create_security_group_rule(
            security_group_id=sg_id,
            direction=direction,
            ethertype=ethertype,
            protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_group_id=remote_group_id,
            remote_ip_prefix=remote_ip_prefix
        )

        sec_group_rule = rule_create_body['security_group_rule']
        self.addCleanup(self._delete_security_group_rule,
                        sec_group_rule['id'])

        expected = {'direction': direction, 'protocol': protocol,
                    'ethertype': ethertype, 'port_range_min': port_range_min,
                    'port_range_max': port_range_max,
                    'remote_group_id': remote_group_id,
                    'remote_ip_prefix': remote_ip_prefix}
        for key, value in six.iteritems(expected):
            self.assertEqual(value, sec_group_rule[key],
                             "Field %s of the created security group "
                             "rule does not match with %s." %
                             (key, value))
