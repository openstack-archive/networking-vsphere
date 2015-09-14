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

from neutron.i18n import _LI
from neutron.i18n import _LW
from neutron.tests.api import base
from neutron.tests.api import base_security_groups
from neutron.tests.api import clients
from neutron.tests.tempest import exceptions
from neutron.tests.tempest import manager
from neutron.tests.tempest import test
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import importutils
from pexpect import pxssh
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
        vcenter_ip = cfg.CONF.VCENTER.vcenter_ip
        vcenter_username = cfg.CONF.VCENTER.vcenter_username
        vcenter_password = cfg.CONF.VCENTER.vcenter_password
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
        trunk_dvswitch_name = cfg.CONF.VCENTER.trunk_dvswitch_name
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
        self.addCleanup(self._try_delete_resource, self._delete_server,
                        server_id)
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
        self.addCleanup(self._try_delete_resource, self._delete_server,
                        server_id)
        if wait_on_boot:
                self.wait_for_server_status(server_id, 'ACTIVE')
        return server_id

    def _delete_server(self, server=None):
        rs_client = self._connect_server()
        resp, body = rs_client.delete("servers/%s" % str(server))
        self.addCleanup(self._try_delete_resource, self._delete_server,
                        server)
        self.wait_for_server_termination(server)
        rest_client.ResponseBody(resp, body)

    def _associate_floating_ips(self, port_id=None):
        floating_ip = self.client.update_floatingip(
            self.floating_ip['id'], port_id=port_id)
        updated_floating_ip = floating_ip['floatingip']
        self.assertEqual(updated_floating_ip['port_id'], port_id)
        self._wait_for_floating_ip_status(self.floating_ip['id'], "ACTIVE")
        return floating_ip

    def _wait_for_floating_ip_status(self, floating_ip_id, status):
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
                rs_client = self._connect_server()
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
        build_interval = CONF.boto.build_interval
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

    def get_remote_client(self, ip, username=None):
        """Get a SSH client to a remote server

        :param server_or_ip: a server object as returned by Tempest compute
            client or an IP address to connect to
        :param username: name of the Linux account on the remote server
        :return: a RemoteClient object
        """
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
        self._wait_for_floating_ip_status(self.floating_ip['id'], "DOWN")
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
        self.addCleanup(self._try_delete_resource, self._delete_server,
                        server_id)
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
        self.addCleanup(self._try_delete_resource, self._delete_server,
                        server_id)
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

    def _fetch_segment_id_from_db(self, segmentid):
        cont_ip = cfg.CONF.VCENTER.controller_ip
        neutron_db = "select lvid from ovsvapp_cluster_vni_allocations " \
                     "where network_id=\"" + segmentid + "\";"
        cmd = ['mysql', '-sN', '-h', cont_ip, 'neutron',
               '-e', neutron_db]
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE)
        segment_id = proc.communicate()[0]
        return segment_id.strip('\r\n')

    def _get_vm_name(self, server_id):
        content = self._create_connection()
        vm_name = self.get_obj(content, [vim.VirtualMachine],
                               server_id)
        return vm_name

    def _fetch_cluster_in_use_from_server(self, server_id):
        region = CONF.compute.region
        auth_provider = manager.get_auth_provider(
            self.isolated_creds.get_admin_creds())
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

    def _verify_portgroup_vxlan(self, trunk_dvswitch, vm_name, net_id,
                                segment_id):
        content = self._create_connection()

        dvswitch_obj = self.get_obj(content, [vim.DistributedVirtualSwitch],
                                    trunk_dvswitch)
        port_groups = dvswitch_obj.portgroup
        for port_group in port_groups:
                if vm_name in port_group.vm:
                        if net_id in port_group.summary.name[0:36]:
                                seg_id = port_group.config.defaultPortConfig
                                self.assertEqual(seg_id.vlan.vlanId,
                                                 int(segment_id))
                                return True
        return False

    def _verify_portgroup_vlan(self, trunk_dvswitch, vm_name, net_id,
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
        tenant_network_type = cfg.CONF.VCENTER.tenant_network_type
        if "vlan" == tenant_network_type:
                net = self.admin_client.show_network(net_id)
                segment_id = net['network']['provider:segmentation_id']
        else:
                segment_id = self._fetch_segment_id_from_db(net_id)
        cluster_name = self._fetch_cluster_in_use_from_server(server_id)
#       Made changes for openstack liberty release
#       cluster_name = cfg.CONF.VCENTER.cluster_in_use
        vm_name = self._get_vm_name(server_id)
        trunk_dvswitch_name = cfg.CONF.VCENTER.trunk_dvswitch_name
        trunk_dvswitch_name = trunk_dvswitch_name.split(',')
        for trunk_dvswitch in trunk_dvswitch_name:
            if "vxlan" == tenant_network_type:
                if str(cluster_name) in trunk_dvswitch:
                    return (self._verify_portgroup_vxlan(trunk_dvswitch,
                                                         vm_name,
                                                         net_id,
                                                         segment_id))
            else:
                return (self._verify_portgroup_vlan(trunk_dvswitch,
                                                    vm_name,
                                                    net_id,
                                                    segment_id))
        return False

    def verify_portgroup_after_vm_delete(self, net_id):
        content = self._create_connection()
        trunk_dvswitch_name = cfg.CONF.VCENTER.trunk_dvswitch_name
        trunk_dvswitch_name = trunk_dvswitch_name.split(',')
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
        self.addCleanup(self._try_delete_resource, self._delete_server,
                        server_id)
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
            self.addCleanup(self._try_delete_resource, self._delete_server,
                            server_id)
            serv = self._get_host_name(server_id)

            if count is not 0:
                if str(serv['host_name']) == str(server['host_name']):
                    if count == 2:
                        raise Exception('VM hosted on same host.')
                else:
                    return str(serv['vm_name']), str(server['vm_name'])
            server = serv
            count += 1

    def _create_remote_session(self, ip_addr, u_name, psswd):
        session = pxssh.pxssh()
        try:
            session.login(ip_addr, u_name, password=psswd, login_timeout=80)
            return session

        except Exception:
            LOG.warn(_LW('Failed to connect to IP: %(dest)s '
                         'via a ssh connection.') %
                     {'dest': ip_addr})
            raise

    def _dump_flows_on_br_sec_old(self, vapp_ipadd, protocol, vlan, mac,
                                  port, net_id):
        vapp_username = cfg.CONF.VCENTER.vapp_username
        vapp_password = cfg.CONF.VCENTER.vapp_password
        session = self._create_remote_session(vapp_ipadd, vapp_username,
                                              vapp_password)
        tenant_network_type = cfg.CONF.VCENTER.tenant_network_type
        if "vlan" == tenant_network_type:
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(vlan) + ',tp_dst=' + str(port))
        else:
                segment_id = self._fetch_segment_id_from_db(str(net_id))
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(segment_id) + ',tp_dst=' + str(port))
        session.sendline(cmd)
        session.prompt()
        output = session.before
        session.logout()
        check = 'tp_dst=' + str(port)
        self.assertIn(check, output)

    def _dump_flows_on_br_sec_for_icmp_rule_old(self, vapp_ipadd, protocol,
                                                vlan, mac, icmp_type,
                                                icmp_code, net_id):
        vapp_username = cfg.CONF.VCENTER.vapp_username
        vapp_password = cfg.CONF.VCENTER.vapp_password
        session = self._create_remote_session(vapp_ipadd, vapp_username,
                                              vapp_password)
        tenant_network_type = cfg.CONF.VCENTER.tenant_network_type
        if "vlan" == tenant_network_type:
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(vlan) + ',icmp_type=' + str(icmp_type) +
                       ',icmp_code=' + str(icmp_code))
        else:
                segment_id = self._fetch_segment_id_from_db(str(net_id))
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(segment_id) + ',icmp_type=' + str(icmp_type) +
                       ',icmp_code=' + str(icmp_code))
        session.sendline(cmd)
        session.prompt()
        output = session.before
        session.logout()
        check_list = ['icmp_type=' + str(icmp_type),
                      'icmp_code=' + str(icmp_code)]
        for checks in check_list:
                self.assertIn(checks, output)

    def get_server_ip(self, server_id, net_name):
        region = CONF.compute.region
        auth_provider = manager.get_auth_provider(
            self.isolated_creds.get_admin_creds())
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
        vapp_username = cfg.CONF.VCENTER.vapp_username
        HOST = vapp_username + "@" + vapp_ipadd
        build_interval = CONF.boto.build_interval
        time.sleep(build_interval)
        tenant_network_type = cfg.CONF.VCENTER.tenant_network_type
        if "vlan" == tenant_network_type:
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(vlan) + ',tp_dst=' + str(port))
        else:
                segment_id = self._fetch_segment_id_from_db(str(net_id))
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(segment_id) + ',tp_dst=' + str(port))
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        if output[1:] == []:
                error = ssh.stderr.readlines()
                raise exceptions.TimeoutException(error)
        else:
                for output_list in output[1:]:
                        self.assertIn('tp_dst=' + str(port), output_list)

    def _dump_flows_on_br_sec_for_icmp_rule(self, vapp_ipadd, protocol, vlan,
                                            mac, icmp_type, icmp_code, net_id):
        vapp_username = cfg.CONF.VCENTER.vapp_username
        HOST = vapp_username + "@" + vapp_ipadd
        build_interval = CONF.boto.build_interval
        time.sleep(build_interval)
        tenant_network_type = cfg.CONF.VCENTER.tenant_network_type
        if "vlan" == tenant_network_type:
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(vlan) + ',icmp_type=' + str(icmp_type) +
                       ',icmp_code=' + str(icmp_code))
        else:
                segment_id = self._fetch_segment_id_from_db(str(net_id))
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
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
                raise exceptions.TimeoutException(error)
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
        vapp_username = cfg.CONF.VCENTER.vapp_username
        HOST = vapp_username + "@" + vapp_ipadd
        build_interval = CONF.boto.build_interval
        time.sleep(build_interval)
        tenant_network_type = cfg.CONF.VCENTER.tenant_network_type
        if "vlan" == tenant_network_type:
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(vlan) + ',icmp_type=' + str(icmp_type))
        else:
                segment_id = self._fetch_segment_id_from_db(str(net_id))
                cmd = ('sudo ovs-ofctl dump-flows br-sec table=0' + ',' +
                       str(protocol) + ',dl_dst=' + str(mac) + ',dl_vlan=' +
                       str(segment_id) + ',icmp_type=' + str(icmp_type))
        ssh = subprocess.Popen(["ssh", "%s" % HOST, cmd],
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()
        if output[1:] == []:
                error = ssh.stderr.readlines()
                raise exceptions.TimeoutException(error)
        else:
                for output_list in output[1:]:
                        self.assertIn('icmp_type=' + str(icmp_type),
                                      output_list)
