# Copyright 2012 OpenStack Foundation
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
import json
import time

from neutron.common import exceptions
from neutron.tests.api import base
from neutron.tests.tempest import manager
from neutron.tests.tempest import test

from networking_vsphere.tests.tempest import config

from oslo_log import log
from pyVim import connect
from pyVim.connect import Disconnect
from pyVmomi import vim
from tempest_lib.common import rest_client
from tempest_lib.common.utils import data_utils

CONF = config.CONF

LOG = log.getLogger(__name__)


class NetworksTestJSON(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(NetworksTestJSON, cls).resource_setup()
        nova_creds = cls.isolated_creds.get_admin_creds()
        cls.auth_provider = manager.get_auth_provider(nova_creds)
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)
        cls.ext_net_id = CONF.network.public_network_id

        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = list()

    def setUp(self):
        super(NetworksTestJSON, self).setUp()
        self.portgroup_list = []
        self.segmentid_list = []

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

    def _create_server(self, network=None):
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           "RegionOne")
        image = CONF.compute.image_ref
        flavor = CONF.compute.flavor_ref
        data = {"server": {"name": "vm", "imageRef": image,
                "flavorRef": flavor, "max_count": 1, "min_count": 1,
                                   "networks": [{"uuid": network}]}}
        data = json.dumps(data)
        resp, body = rs_client.post("/servers", data)
        time.sleep(50)
        rs_client.expected_success(202, resp.status)
        body = json.loads(body)
        server_id = body['server']['id']
        return server_id

    def _delete_server(self, server=None):
        rs_client = rest_client.RestClient(self.auth_provider, "compute",
                                           "RegionOne")
        resp, body = rs_client.delete("servers/%s" % str(server))
        rest_client.ResponseBody(resp, body)

    def test_sample_create_server(self):
        net_id = self.network['id']
        serverid = self._create_server(net_id)
        self._delete_server(serverid)
