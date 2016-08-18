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

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import importutils
from tempest.common import waiters
from tempest.lib.common import rest_client
from tempest.lib.common import ssh
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import misc as misc_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest import manager
from tempest import test

from networking_vsphere.tests.tempest import config as tempest_config
from networking_vsphere._i18n import _LI, _LW

from tempest.api.network import base
from tempest.api.network import base_security_groups


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
        cls.servers_client = cls.manager.servers_client
        cls.networks_client = cls.manager.networks_client
        cls.ports_client = cls.manager.ports_client
        cls.routers_client = cls.manager.routers_client
        cls.subnets_client = cls.manager.subnets_client
        cls.floating_ips_client = cls.manager.floating_ips_client
        cls.security_groups_client = cls.manager.security_groups_client
        cls.security_group_rules_client = (
            cls.manager.security_group_rules_client)

        cls.creds = cls.os.credentials
        cls.user_id = cls.creds.user_id
        cls.username = cls.creds.username
        cls.password = cls.creds.password
        cls.auth_provider = manager.get_auth_provider(cls.creds)
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)
        cls.ext_net_id = CONF.network.public_network_id

        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.tenant_cidr = (CONF.network.project_network_cidr
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
        self.vapp_username = CONF.VCENTER.vapp_username
        self.build_interval = CONF.compute.build_interval
        self.tenant_network_type = CONF.VCENTER.tenant_network_type
        self.br_inf = CONF.VCENTER.bridge_interface_trunk
        self.cleanup_waits = []
        self.addCleanup(self._wait_for_cleanups)

    def _wait_for_cleanups(self):
        # To handle async delete actions, a list of waits is added
        # which will be iterated over as the last step of clearing the
        # cleanup queue. That way all the delete calls are made up front
        # and the tests won't succeed unless the deletes are eventually
        # successful. This is the same basic approach used in the api tests to
        # limit cleanup execution time except here it is multi-resource,
        # because of the nature of the scenario tests.
        for wait in self.cleanup_waits:
            waiter_callable = wait.pop('waiter_callable')
            waiter_callable(**wait)

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

    def _connect_server(self):
        region = CONF.compute.region
        endpoint_type = CONF.compute.endpoint_type
        build_interval = CONF.compute.build_interval
        build_timeout = CONF.compute.build_timeout
        disable_ssl_cert = CONF.identity.disable_ssl_certificate_validation
        ca_certs = CONF.identity.ca_certificates_file
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           region, endpoint_type,
                                           build_interval, build_timeout,
                                           disable_ssl_cert,
                                           ca_certs)
        return rs_client

    def _create_connection(self):
        connection = None
        vcenter_ip = CONF.VCENTER.vcenter_ip
        vcenter_username = CONF.VCENTER.vcenter_username
        vcenter_password = CONF.VCENTER.vcenter_password
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
        trunk_dvswitch_name = CONF.VCENTER.trunk_dvswitch_name
        content = self._create_connection()
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

    def addCleanup_with_wait(self, waiter_callable, thing_id, thing_id_param,
                             cleanup_callable, cleanup_args=None,
                             cleanup_kwargs=None, waiter_client=None):
        """Adds wait for async resource deletion at the end of cleanups

        @param waiter_callable: callable to wait for the resource to delete
            with the following waiter_client if specified.
        @param thing_id: the id of the resource to be cleaned-up
        @param thing_id_param: the name of the id param in the waiter
        @param cleanup_callable: method to load pass to self.addCleanup with
            the following *cleanup_args, **cleanup_kwargs.
            usually a delete method.
        """
        if cleanup_args is None:
            cleanup_args = []
        if cleanup_kwargs is None:
            cleanup_kwargs = {}
        self.addCleanup(cleanup_callable, *cleanup_args, **cleanup_kwargs)
        wait_dict = {
            'waiter_callable': waiter_callable,
            thing_id_param: thing_id
        }
        if waiter_client:
            wait_dict['client'] = waiter_client
        self.cleanup_waits.append(wait_dict)

    def _create_server_with_sec_group(self, name=None, network=None,
                                      securitygroup=None, wait_on_boot=True):
        rs_client = self._connect_server()
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        data = {"server": {"name": name, "imageRef": image,
                           "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"uuid": network}],
                           "security_groups": [{"name": securitygroup}]}}

        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        clients = self.manager
        self.addCleanup(waiters.wait_for_server_termination,
                        clients.servers_client,
                        server_id)
        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=server_id, thing_id_param='server_id',
            cleanup_callable=test_utils.call_and_ignore_notfound_exc,
            cleanup_args=[clients.servers_client.delete_server, server_id],
            waiter_client=clients.servers_client)
        if wait_on_boot:
            self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _create_server(self, name=None, network=None,
                       wait_on_boot=True):
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        rs_client = self._connect_server()
        data = {"server": {"name": name, "imageRef": image,
                           "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"uuid": network}]}}

        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        clients = self.manager
        self.addCleanup(waiters.wait_for_server_termination,
                        clients.servers_client,
                        server_id)
        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=server_id, thing_id_param='server_id',
            cleanup_callable=test_utils.call_and_ignore_notfound_exc,
            cleanup_args=[clients.servers_client.delete_server, server_id],
            waiter_client=clients.servers_client)
        if wait_on_boot:
            self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _delete_server(self, server=None):
        rs_client = self._connect_server()
        resp, body = rs_client.delete("servers/%s" % str(server))
        clients = self.manager
        self.addCleanup(waiters.wait_for_server_termination,
                        clients.servers_client,
                        server)
        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=server, thing_id_param='server_id',
            cleanup_callable=test_utils.call_and_ignore_notfound_exc,
            cleanup_args=[clients.servers_client.delete_server, server],
            waiter_client=clients.servers_client)

        rest_client.ResponseBody(resp, body)

    def _associate_floating_ips(self, port_id=None):
        floating_ip = self.floating_ips_client.update_floatingip(
            self.floating_ip['id'], port_id=port_id)
        updated_floating_ip = floating_ip['floatingip']
        self.assertEqual(updated_floating_ip['port_id'], port_id)
        self.wait_for_floating_ip_status(self.floating_ip['id'], "ACTIVE")
        return floating_ip

    def wait_for_floating_ip_status(self, floating_ip_id, status):
        """Waits for a floating_ip to reach a given status."""
        build_timeout = CONF.compute.build_timeout
        build_interval = CONF.compute.build_interval
        floating_ip = self.floating_ips_client.show_floatingip(floating_ip_id)
        shown_floating_ip = floating_ip['floatingip']
        floating_ip_status = shown_floating_ip['status']
        start = int(time.time())

        while floating_ip_status != status:
            time.sleep(build_interval)
            floating_ip = self.floating_ips_client.show_floatingip(
                floating_ip_id)
            shown_floating_ip = floating_ip['floatingip']
            floating_ip_status = shown_floating_ip['status']
            if int(time.time()) - start >= build_timeout:
                message = ('floating_ip %s failed to reach'
                           ' %s status (current %s) '
                           'within the required time (%s s).' %
                           (floating_ip, status, floating_ip_status,
                            build_timeout))
                raise lib_exc.TimeoutException(message)

    def wait_for_server_termination(self, server_id, ignore_error=False):
        """Waits for server to reach termination."""
        build_interval = CONF.compute.build_interval
        while True:
            try:
                rs_client = self._connect_server()
                resp, body = rs_client.get("servers/%s" % str(server_id))
                body = jsonutils.loads(body)
            except lib_exc.NotFound:
                return

            server_status = body['server']['status']
            if server_status == 'ERROR' and not ignore_error:
                raise lib_exc.BuildErrorException(server_id=server_id)

            time.sleep(build_interval)

    def wait_for_server_status(self, server_id, status, ready_wait=True,
                               extra_timeout=0, raise_on_error=True):
        """Waits for a server to reach a given status."""
        build_interval = CONF.compute.build_interval
        build_timeout = CONF.compute.build_timeout

        def _get_task_state(body):
            return body.get('OS-EXT-STS:task_state', None)
        rs_client = self._connect_server()
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
                        'after %(waitsec)d second wait'),
                    {'oldstatus': oldstatus, 'serverstatus': serverstatus,
                     'waitsec': waitsec}
                )
            if (server_status == 'ERROR') and raise_on_error:
                if 'fault' in body:
                    raise lib_exc.BuildErrorException(body['fault'],
                                                      server_id=server_id)
                else:
                    raise lib_exc.BuildErrorException(server_id=server_id)

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
                raise lib_exc.TimeoutException(message)
            old_status = server_status
            old_task_state = task_state

    def _create_verify_security_group_rule(self, sg_id, direction,
                                           ethertype, protocol,
                                           port_range_min,
                                           port_range_max,
                                           remote_group_id=None,
                                           remote_ip_prefix=None):
        rule_create_body = \
            self.security_group_rules_client.create_security_group_rule(
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
        timeout = ping_timeout or CONF.validation.ping_timeout
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
        LOG.debug('checking network connection')
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

    def get_remote_client(self, ip, username=None):
        """Get a SSH client to a remote server

        :param server_or_ip: a server object as returned by Tempest compute
            client or an IP address to connect to
        :param username: name of the Linux account on the remote server
        :return: a RemoteClient object
        """
        if username is None:
            username = CONF.validation.image_ssh_user
        password = CONF.validation.image_ssh_password
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
        ssh_login = CONF.validation.image_ssh_user
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
        ssh_login = CONF.validation.image_ssh_user
        ip_address = floating_ip
        floatingip_status = 'DOWN'
        if should_connect:
            floatingip_status = 'ACTIVE'
        # Check FloatingIP Status before initiating a connection
        if should_check_floating_ip_status:
            floating_ip = self.floating_ips_client.show_floatingip(
                self.floating_ip['id'])
            shown_floating_ip = floating_ip['floatingip']
            self.assertEqual(floatingip_status, shown_floating_ip['status'])
        self.check_public_network_connectivity(ip_address, ssh_login,
                                               should_connect, msg)

    def _disassociate_floating_ips(self, port_id=None):
        disassociate_floating_ip_body =\
            self.floating_ips_client.update_floatingip(
                self.floating_ip['id'],
                port_id=None)
        self.wait_for_floating_ip_status(self.floating_ip['id'], "DOWN")
        return disassociate_floating_ip_body

    def _create_server_multiple_nic(self, name=None, network1=None,
                                    network2=None, securitygroup=None,
                                    wait_on_boot=True):
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        rs_client = self._connect_server()
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
        clients = self.manager
        self.addCleanup(waiters.wait_for_server_termination,
                        clients.servers_client,
                        server_id)
        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=server_id, thing_id_param='server_id',
            cleanup_callable=test_utils.call_and_ignore_notfound_exc,
            cleanup_args=[clients.servers_client.delete_server, server_id],
            waiter_client=clients.servers_client)

        if wait_on_boot:
            self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _create_server_multiple_nic_user_created_port(self, name=None,
                                                      port1=None, port2=None,
                                                      wait_on_boot=True):
        rs_client = self._connect_server()
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        data = {"server": {"name": name, "imageRef": image,
                           "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"port": port1},
                                        {"port": port2}]}}
        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        clients = self.manager
        self.addCleanup(waiters.wait_for_server_termination,
                        clients.servers_client,
                        server_id)
        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=server_id, thing_id_param='server_id',
            cleanup_callable=test_utils.call_and_ignore_notfound_exc,
            cleanup_args=[clients.servers_client.delete_server, server_id],
            waiter_client=clients.servers_client)

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
                LOG.warning(_LW('Failed to ping IP: %(dest)s '
                                'via a ssh connection from: %(source)s.'),
                            {'dest': dest, 'source': source})
                return not should_succeed
            return should_succeed

        return test.call_until_true(ping_remote,
                                    CONF.validation.ping_timeout, 1)

    def _fetch_segment_id_from_db(self, segmentid):
        cont_ip = CONF.VCENTER.controller_ip
        neutron_db_name = CONF.VCENTER.neutron_database_name
        neutron_db = "select lvid from ovsvapp_cluster_vni_allocations " \
                     "where network_id=\"" + segmentid + "\";"
        cmd = ['mysql', '-sN', '-h', cont_ip, neutron_db_name,
               '-e', neutron_db]
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE)
        segment_id = proc.communicate()[0]
        return int(segment_id.strip('\r\n'))

    def _get_vm_name(self, server_id):
        content = self._create_connection()
        vm_name = self.get_obj(content, [vim.VirtualMachine],
                               server_id)
        return vm_name

    def _fetch_cluster_in_use_from_server(self, server_id):
        region = CONF.compute.region
        auth_provider = manager.get_auth_provider(self.creds.credentials)
        endpoint_type = CONF.compute.endpoint_type
        build_interval = CONF.compute.build_interval
        build_timeout = CONF.compute.build_timeout
        disable_ssl_cert = CONF.identity.disable_ssl_certificate_validation
        ca_certs = CONF.identity.ca_certificates_file
        rs_client = rest_client.RestClient(auth_provider, "compute",
                                           region, endpoint_type,
                                           build_interval, build_timeout,
                                           disable_ssl_cert,
                                           ca_certs)
        resp, body = rs_client.get("servers/%s" % str(server_id))
        body = jsonutils.loads(body)
        cst_name = body['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']
        return cst_name[cst_name.index("(") + 1:cst_name.rindex(")")]

    def _verify_portgroup_vlan_vxlan(self, trunk_dvswitch, vm_name, net_id,
                                     segment_id):
        content = self._create_connection()

        dvswitch_obj = self.get_obj(content, [vim.DistributedVirtualSwitch],
                                    trunk_dvswitch)
        port_groups = dvswitch_obj.portgroup
        for port_group in port_groups:
            if vm_name in port_group.vm:
                if net_id in port_group.summary.name:
                    seg_id = port_group.config.defaultPortConfig
                    self.assertEqual(seg_id.vlan.vlanId,
                                     segment_id)
                    return True
        return False

    def verify_portgroup(self, net_id, server_id):
        segment_id = self._fetch_segment_id_from_db(net_id)
        vm_name = self._get_vm_name(server_id)
        trunk_dvswitch_name = CONF.VCENTER.trunk_dvswitch_name
        return (self._verify_portgroup_vlan_vxlan(trunk_dvswitch_name,
                                                  vm_name,
                                                  net_id,
                                                  segment_id))
        return False

    def verify_portgroup_after_vm_delete(self, net_id):
        content = self._create_connection()
        trunk_dvswitch_name = CONF.VCENTER.trunk_dvswitch_name
        trunk_dvswitch_name = trunk_dvswitch_name.split(',')
        time.sleep(10)
        for trunk_dvswitch in trunk_dvswitch_name:
            dvswitch_obj = self.get_obj(content,
                                        [vim.DistributedVirtualSwitch],
                                        trunk_dvswitch)
            port_groups = dvswitch_obj.portgroup
            for port_group in port_groups:
                if net_id in port_group.summary.name:
                    return True
        return False

    def _create_server_user_created_port(self, name=None,
                                         port1=None,
                                         wait_on_boot=True):
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        rs_client = self._connect_server()
        data = {"server": {"name": name, "imageRef": image,
                           "flavorRef": flavor, "max_count": 1, "min_count": 1,
                           "networks": [{"port": port1}]}}
        data = jsonutils.dumps(data)
        resp, body = rs_client.post("/servers", data)
        rs_client.expected_success(202, resp.status)
        body = jsonutils.loads(body)
        server_id = body['server']['id']
        clients = self.manager
        self.addCleanup(waiters.wait_for_server_termination,
                        clients.servers_client,
                        server_id)
        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=server_id, thing_id_param='server_id',
            cleanup_callable=test_utils.call_and_ignore_notfound_exc,
            cleanup_args=[clients.servers_client.delete_server, server_id],
            waiter_client=clients.servers_client)

        if wait_on_boot:
            self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _get_vm_info(self, dic, vm, depth=1):
        maxdepth = 10
        if hasattr(vm, 'childEntity'):
            if depth > maxdepth:
                return
            vmList = vm.childEntity
            for c in vmList:
                self._get_vm_info(dic, c, depth + 1)
            return

        summary = vm.summary
        vm_name = summary.config.name
        host_name = summary.runtime.host
        name = summary.guest.hostName
        ip_address = summary.guest.ipAddress
        dic1 = {'vm_name': vm_name, 'host_name': host_name,
                'name': name, 'ip_address': ip_address}
        if vm_name is not None:
            dic[str(vm_name)] = dic1
            return dic

    def _get_host_name(self, server_id):
        content = self._create_connection()
        for child in content.rootFolder.childEntity:
            if hasattr(child, 'vmFolder'):
                datacenter = child
                vmFolder = datacenter.vmFolder
                vmList = vmFolder.childEntity
                dic = {}
                for vm in vmList:
                    host_name = self._get_vm_info(dic, vm)
                    if host_name is not None:
                        for key in host_name:
                            if server_id == str(host_name[key]['vm_name']):
                                return host_name[key]

    def _get_vapp_ip(self, host_n, vapp_name):
        content = self._create_connection()
        for child in content.rootFolder.childEntity:
            if hasattr(child, 'vmFolder'):
                datacenter = child
                vmFolder = datacenter.vmFolder
                vmList = vmFolder.childEntity
                dic = {}
                for vm in vmList:
                    host_name = self._get_vm_info(dic, vm)
                    if host_name is not None:
                        for key in host_name:
                            if host_n == str(host_name[key]['host_name']):
                                if vapp_name == str(host_name[key]['name']):
                                    return host_name[key]['ip_address']

    def _create_multiple_server_on_different_host(self):
        group_create_body_update, _ = self._create_security_group()
        server = {}
        count = 0
        while count < 3:
            name = data_utils.rand_name('server-with-security-group')
            server_id = self._create_server_with_sec_group(
                name, self.network['id'],
                group_create_body_update['security_group']['id'])
            clients = self.manager
            self.addCleanup(waiters.wait_for_server_termination,
                            clients.servers_client,
                            server_id)
            self.addCleanup_with_wait(
                waiter_callable=waiters.wait_for_server_termination,
                thing_id=server_id, thing_id_param='server_id',
                cleanup_callable=test_utils.call_and_ignore_notfound_exc,
                cleanup_args=[clients.servers_client.delete_server, server_id],
                waiter_client=clients.servers_client)
            serv = self._get_host_name(server_id)

            if count is not 0:
                if str(serv['host_name']) == str(server['host_name']):
                    if count == 2:
                        raise Exception('VM hosted on same host.')
                else:
                    return str(serv['vm_name']), str(server['vm_name'])
            server = serv
            count += 1

    def get_server_ip(self, server_id, net_name):
        region = CONF.compute.region
        auth_provider = manager.get_auth_provider(self.creds)
        endpoint_type = CONF.compute.endpoint_type
        build_interval = CONF.compute.build_interval
        build_timeout = CONF.compute.build_timeout
        disable_ssl_cert = CONF.identity.disable_ssl_certificate_validation
        ca_certs = CONF.identity.ca_certificates_file
        rs_client = rest_client.RestClient(auth_provider, "compute",
                                           region, endpoint_type,
                                           build_interval, build_timeout,
                                           disable_ssl_cert,
                                           ca_certs)
        resp, body = rs_client.get("servers/%s" % str(server_id))
        body = jsonutils.loads(body)
        ipaddress = body['server']['addresses'][net_name][0]['addr']
        return ipaddress

    def _migrate_vm(self, content, vm, dest_host):
        """Migrate vm from one host to the destination host."""

        vm_obj = self.get_obj(content, [vim.VirtualMachine], vm)
        resource_pool = vm_obj.resourcePool
        if vm_obj.runtime.powerState != 'poweredOn':
            raise Exception('Migration is only for Powered On VMs')
        migrate_priority = vim.VirtualMachine.MovePriority.defaultPriority
        task = vm_obj.Migrate(pool=resource_pool, host=dest_host,
                              priority=migrate_priority)
        return task

    def _get_hosts_for_cluster(self, content, cluster):
        """Get all the hosts within a cluster."""

        cluster_hosts = self.get_obj(content, [vim.ClusterComputeResource],
                                     cluster)
        return cluster_hosts

    def _wait_for_task(self, task, actionName='job', hideResult=False):
        """Waits and provides updates on a vSphere task."""

        while task.info.state == vim.TaskInfo.State.running:
            time.sleep(2)

        if task.info.state != vim.TaskInfo.State.success:
            raise Exception('%s did not complete successfully: %s' % (
                            actionName, task.info.error))

    def _dump_flows_on_br_sec(self, vapp_ipadd, protocol, vlan, mac,
                              port, net_id):
        HOST = self.vapp_username + "@" + vapp_ipadd
        time.sleep(self.build_interval)
        segment_id = self._fetch_segment_id_from_db(str(net_id))
        cmd = ('sudo ovs-ofctl dump-flows ' +
               self.br_inf + ' table=0' + ',' +
               str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
               str(segment_id) + ',tp_dst=' + str(port))
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        if output[1:] == []:
            error = ssh.stderr.readlines()
            raise lib_exc.TimeoutException(error)
        else:
            for output_list in output[1:]:
                self.assertIn('tp_dst=' + str(port), output_list)

    def _dump_flows_on_br_sec_for_icmp_rule(self, vapp_ipadd, protocol, vlan,
                                            mac, icmp_type, icmp_code, net_id):
        HOST = self.vapp_username + "@" + vapp_ipadd
        time.sleep(self.build_interval)
        segment_id = self._fetch_segment_id_from_db(str(net_id))
        cmd = ('sudo ovs-ofctl dump-flows ' +
               self.br_inf + ' table=0' + ',' +
               str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
               str(segment_id) + ',icmp_type=' + str(icmp_type) +
               ',icmp_code=' + str(icmp_code))
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        if output[1:] == []:
            error = ssh.stderr.readlines()
            raise lib_exc.TimeoutException(error)
        else:
            for output_list in output[1:]:
                self.assertIn('icmp_type=' + str(icmp_type),
                              output_list)
                self.assertIn('icmp_code=' + str(icmp_code),
                              output_list)

    def _get_vapp_ip_from_agent_list(self, host_n):
        content = self._create_connection()
        for child in content.rootFolder.childEntity:
            if hasattr(child, 'vmFolder'):
                datacenter = child
                vmFolder = datacenter.vmFolder
                vmList = vmFolder.childEntity
                dic = {}
                for vm in vmList:
                    host_name = self._get_vm_info(dic, vm)
                    if host_name is not None:
                        for key in host_name:
                            if key == host_n:
                                return host_name[key]['ip_address']

    def _dump_flows_on_br_sec_for_icmp_type(self, vapp_ipadd, protocol, vlan,
                                            mac, icmp_type, net_id):
        HOST = self.vapp_username + "@" + vapp_ipadd
        time.sleep(self.build_interval)
        segment_id = self._fetch_segment_id_from_db(str(net_id))
        cmd = ('sudo ovs-ofctl dump-flows ' +
               self.br_inf + ' table=0' + ',' +
               str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
               str(segment_id) + ',icmp_type=' + str(icmp_type))
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        if output[1:] == []:
            error = ssh.stderr.readlines()
            raise lib_exc.TimeoutException(error)
        else:
            for output_list in output[1:]:
                self.assertIn('icmp_type=' + str(icmp_type),
                              output_list)
