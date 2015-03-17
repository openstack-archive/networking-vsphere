# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
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

from oslo_log import log

from neutron.common import rpc as n_rpc
from neutron.common import topics

from networking_vsphere.common import constants
from networking_vsphere.plugins.ml2.drivers.ovsvapp import ovsvapp_rpc

LOG = log.getLogger(__name__)


class OVSvAppAgentDriver(object):
    """OVSvApp Python Driver for Neutron.

    This code is the backend implementation for the OVSvApp ML2
    MechanismDriver for OpenStack Neutron.
    """

    def initialize(self):
        self._start_rpc_listeners()

    def _start_rpc_listeners(self):
        self.notifier = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self.endpoints = [ovsvapp_rpc.OVSvAppServerRpcCallback(self.notifier)]
        self.topic = constants.OVSVAPP
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()
