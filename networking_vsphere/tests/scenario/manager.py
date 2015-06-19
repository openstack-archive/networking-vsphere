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
"""
The test requires pyvmomi as a requirement to validate
port group in vCenter

You will need to install the python pyvmomi package
sudo pip install pyvmomi

"""
import atexit

import netaddr
import six

import subprocess
import time

from networking_vsphere.tests.tempest import config as tempest_config

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import importutils

from neutron.common import exceptions
from neutron.i18n import _LI, _LW
from neutron.tests.api import base
from neutron.tests.api import base_security_groups
from neutron.tests.api import clients
from neutron.tests.tempest import manager
from neutron.tests.tempest import test

from tempest_lib.common import rest_client
from tempest_lib.common import ssh
from tempest_lib.common.utils import data_utils
from tempest_lib.common.utils import misc as misc_utils
from tempest_lib import exceptions as lib_exc

pyVmomi = importutils.try_import("pyVmomi")
if pyVmomi:
    from pyVim import connect
    from pyVim.connect import Disconnect
    from pyVmomi import vim

CONF = cfg.CONF

LOG = log.getLogger(__name__)


class ESXNetworksTestJSON(base.BaseAdminNetworkTest,
                          base_security_groups.BaseSecGroupTest):

    @classmethod
    def resource_setup(cls):
        super(ESXNetworksTestJSON, cls).resource_setup()
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
        tempest_config.register_options()

    def setUp(self):
        super(ESXNetworksTestJSON, self).setUp()
        self.portgroup_list = []
        self.segmentid_list = []
        self.portgroup_deleted_list = []
        self.segmentid_deleted_list = []

    def get_obj(self, content, vimtype, name):
        """Get the vsphere object associated with a given text name."""
        obj = None
        container = content.viewManager.CreateContainerView(content.rootFolder,
                                                            vimtype, True)
        for containername in container.view:
                if containername.name == name:
                    obj = containername
                    break
        return obj

    def _create_connection(self, vcenter_ip, vcenter_username,
                           vcenter_password):
        connection = None
        try:
                msg = "Trying to connect %s vCenter" % vcenter_ip
                LOG.info(msg)
                connection = connect.Connect(vcenter_ip, 443,
                                             vcenter_username,
                                             vcenter_password,
                                             service="hostd")
        except Exception:
            msg = ('Could not connect to the specified vCenter')
            raise lib_exc.TimeoutException(msg)
        atexit.register(Disconnect, connection)
        content = connection.RetrieveContent()
        return content

    def _get_portgroups(self):
        vcenter_ip = cfg.CONF.VCENTER.vcenter_ip
        trunk_dvswitch_name = cfg.CONF.VCENTER.trunk_dvswitch_name
        vcenter_username = cfg.CONF.VCENTER.vcenter_username
        vcenter_password = cfg.CONF.VCENTER.vcenter_password
        content = self._create_connection(vcenter_ip, vcenter_username,
                                          vcenter_password)
        dvswitch_obj = self.get_obj(content,
                                    [vim.DistributedVirtualSwitch],
                                    trunk_dvswitch_name)
        port_groups = dvswitch_obj.portgroup
        return port_groups

    def _portgroup_verify(self, portgroup, segmentid):
        port_groups = self._get_portgroups()
        for port_group in port_groups:
                portgroupname = port_group.name
                self.portgroup_list.append(portgroupname)
                segment_id = port_group.config.defaultPortConfig.vlan.vlanId
                self.segmentid_list.append(segment_id)
        self.assertIn(portgroup, self.portgroup_list)
        self.assertIn(segmentid, self.segmentid_list)

    def _portgroup_verify_after_server_delete(self, portgroup, segmentid):
        port_groups = self._get_portgroups()
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
                                      securitygroup=None, wait_on_boot=True):
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
        if wait_on_boot:
                self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _create_server(self, name=None, network=None,
                       wait_on_boot=True):
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
        if wait_on_boot:
                self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _delete_server(self, server=None):
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           "RegionOne")
        resp, body = rs_client.delete("servers/%s" % str(server))
        self.wait_for_server_termination(server)
        rest_client.ResponseBody(resp, body)

    def _associate_floating_ips(self, port_id=None):
        floating_ip = self.client.update_floatingip(
            self.floating_ip['id'], port_id=port_id)
        updated_floating_ip = floating_ip['floatingip']
        self.assertEqual(updated_floating_ip['port_id'], port_id)
        self.wait_for_floating_ip_status(self.floating_ip['id'], "ACTIVE")
        return floating_ip

    def wait_for_floating_ip_status(self, floating_ip_id, status):
        """Waits for a floating_ip to reach a given status."""
        build_timeout = CONF.compute.build_timeout
        build_interval = CONF.boto.build_interval
        floating_ip = self.client.show_floatingip(floating_ip_id)
        shown_floating_ip = floating_ip['floatingip']
        floating_ip_status = shown_floating_ip['status']
        start = int(time.time())

        while floating_ip_status != status:
            time.sleep(build_interval)
            floating_ip = self.client.show_floatingip(floating_ip_id)
            shown_floating_ip = floating_ip['floatingip']
            floating_ip_status = shown_floating_ip['status']
            if int(time.time()) - start >= build_timeout:
                message = ('floating_ip %s failed to reach'
                           ' %s status (current %s) '
                           'within the required time (%s s).' %
                           (floating_ip, status, floating_ip_status,
                            build_timeout))
                raise exceptions.TimeoutException(message)

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

    def ping_ip_address(self, ip_address, should_succeed=True,
                        ping_timeout=None):
        timeout = ping_timeout or CONF.compute.ping_timeout
        cmd = ['ping', '-c1', '-w1', ip_address]

        def ping():
            proc = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            proc.communicate()
            return (proc.returncode == 0) == should_succeed

        return self._call_until_true(ping, timeout, 1)

    def check_vm_connectivity(self, ip_address,
                              username=None,
                              should_connect=True):
        """:param ip_address: server to test against

        :param username: server's ssh username
        :param should_connect: True/False indicates positive/negative test
            positive - attempt ping and ssh
            negative - attempt ping and fail if succeed
        :raises: AssertError if the result of the connectivity check does
            not match the value of the should_connect param
        """
        if should_connect:
            msg = "Timed out waiting for %s to become reachable" % ip_address
        else:
            msg = "ip address %s is reachable" % ip_address
        self.assertTrue(self.ping_ip_address(ip_address,
                                             should_succeed=should_connect),
                        msg=msg)
        if should_connect:
            # no need to check ssh for negative connectivity
            self.get_remote_client(ip_address, username)

    def check_public_network_connectivity(self, ip_address, username,
                                          should_connect=True,
                                          msg=None):
        LOG.debug('checking network connections to IP %s with user: %s' %
                  (ip_address, username))
        try:
            self.check_vm_connectivity(ip_address,
                                       username,
                                       should_connect=should_connect)
        except Exception:
            ex_msg = 'Public network connectivity check failed'
            if msg:
                ex_msg += ": " + msg
            LOG.exception(ex_msg)
            raise

    def get_remote_client(self, server_or_ip, username=None):
        """Get a SSH client to a remote server

        :param server_or_ip: a server object as returned by Tempest compute
            client or an IP address to connect to
        :param username: name of the Linux account on the remote server
        :return: a RemoteClient object
        """
        if isinstance(server_or_ip, six.string_types):
            ip = server_or_ip
        else:
            addrs = server_or_ip['addresses'][CONF.compute.network_for_ssh]
            try:
                ip = (addr['addr'] for addr in addrs if
                      netaddr.valid_ipv4(addr['addr'])).next()
            except StopIteration:
                raise lib_exc.NotFound("No IPv4 addresses to use for SSH to "
                                       "remote server.")

        if username is None:
            username = CONF.scenario.ssh_user
            password = CONF.compute.image_ssh_password
        linux_client = ssh.Client(ip, username, password)

        try:
            linux_client.test_connection_auth()
        except Exception as e:
            message = ('Initializing SSH connection to %(ip)s failed. '
                       'Error: %(error)s' % {'ip': ip, 'error': e})
            caller = misc_utils.find_test_caller()
            if caller:
                message = '(%s) %s' % (caller, message)
            LOG.exception(message)
            raise
        return linux_client

    def _ssh_to_server(self, server, private_key):
        ssh_login = CONF.compute.image_ssh_user
        return self.get_remote_client(server,
                                      username=ssh_login)

    def _call_until_true(self, func, duration, sleep_for):
        """Call the given function until it returns True (and return True)

        or until the specified duration (in seconds) elapses (and return
        False).
        :param func: A zero argument callable that returns True on success.
        :param duration: The number of seconds for which to attempt a
            successful call of the function.
        :param sleep_for: The number of seconds to sleep after an unsuccessful
                          invocation of the function.
        """
        now = time.time()
        timeout = now + duration
        while now < timeout:
            if func():
                return True
            time.sleep(sleep_for)
            now = time.time()
        return False

    def _check_public_network_connectivity(
            self, floating_ip, should_connect=True, msg=None,
            should_check_floating_ip_status=True):
        """Verifies connectivty to a VM via public network and floating IP,

        and verifies floating IP has resource status is correct.
        :param should_connect: bool. determines if connectivity check is
        negative or positive.
        :param msg: Failure message to add to Error message. Should describe
        the place in the test scenario where the method was called,
        to indicate the context of the failure
        :param should_check_floating_ip_status: bool. should status of
        floating_ip be checked or not
        """
        ssh_login = CONF.compute.image_ssh_user
        ip_address = floating_ip
        floatingip_status = 'DOWN'
        if should_connect:
            floatingip_status = 'ACTIVE'
        # Check FloatingIP Status before initiating a connection
        if should_check_floating_ip_status:
            floating_ip = self.client.show_floatingip(self.floating_ip['id'])
            shown_floating_ip = floating_ip['floatingip']
            self.assertEqual(floatingip_status, shown_floating_ip['status'])
        self.check_public_network_connectivity(ip_address, ssh_login,
                                               should_connect, msg)

    def _disassociate_floating_ips(self, port_id=None):
        disassociate_floating_ip_body = self.client.update_floatingip(
            self.floating_ip['id'],
            port_id=None)
        self.wait_for_floating_ip_status(self.floating_ip['id'], "DOWN")
        return disassociate_floating_ip_body

    def _create_server_multiple_nic(self, name=None, network1=None,
                                    network2=None, securitygroup=None,
                                    wait_on_boot=True):
        region = CONF.compute.region
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           region)
        data = {"server": {"name": name, "imageRef": image,
                "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"uuid": network1},
                                        {"uuid": network2}],
                           "security_groups": [{"name": securitygroup}]}}
        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        if wait_on_boot:
                self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _create_server_multiple_nic_user_created_port(self, name=None,
                                                      port1=None, port2=None,
                                                      securitygroup=None,
                                                      wait_on_boot=True):
        region = CONF.compute.region
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           region)
        data = {"server": {"name": name, "imageRef": image,
                "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"port": port1},
                                        {"port": port2}],
                           "security_groups": [{"name": securitygroup}]}}
        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        if wait_on_boot:
                self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def ping_host(self, source, host):
        client = self.get_remote_client(source)
        addr = netaddr.IPAddress(host)
        cmd = 'ping6' if addr.version == 6 else 'ping'
        cmd += ' -c{0} -w{0} -s{1} {2}'.format(1, 56, host)
        cmd = "set -eu -o pipefail; PATH=$PATH:/sbin; " + cmd
        return client.exec_command(cmd)

    def _check_remote_connectivity(self, source, dest, should_succeed=True):
        """check ping server via source ssh connection

        :param source: RemoteClient: an ssh connection from which to ping
        :param dest: and IP to ping against
        :param should_succeed: boolean should ping succeed or not
        :returns: boolean -- should_succeed == ping
        :returns: ping is false if ping failed
        """
        def ping_remote():
            try:
                self.ping_host(source, dest)
            except lib_exc.SSHExecCommandFailed:
                LOG.warn(_LW('Failed to ping IP: %(dest)s '
                             'via a ssh connection from: %(source)s.') %
                         {'dest': dest, 'source': source})
                return not should_succeed
            return should_succeed

        return test.call_until_true(ping_remote,
                                    CONF.compute.ping_timeout, 1)
