# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from neutron.common import rpc as n_rpc
from neutron.common import topics
import oslo_messaging

from networking_vsphere.common import constants as dvs_const


class ExtendAPI(object):

    def create_network(self, context, current, segment):
        self.create_network_precommit(current, segment)

    def delete_network(self, context, current, segment):
        self.delete_network_postcommit(current, segment)

    def network_delete(self, context, network_id):
        pass

    def update_network(self, context, current, segment, original):
        self.update_network_precommit(current, segment, original)

    def bind_port(self, context, current, network_segments, network_current):
        return self.book_port(current, network_segments, network_current)

    def post_update_port(self, context, current, original, segment):
        self.update_port_postcommit(current, original, segment)

    def delete_port(self, context, current, original, segment):
        self.delete_port_postcommit(current, original, segment)


class DVSClientAPI(object):
    """Client side RPC interface definition."""
    ver = '1.1'

    def __init__(self, context):
        target = oslo_messaging.Target(topic=dvs_const.DVS, version='1.0')
        self.client = n_rpc.get_client(target)
        self.context = context

    def _get_security_group_topic(self, host=None):
        return topics.get_topic_name(topics.AGENT,
                                     dvs_const.DVS,
                                     topics.UPDATE, host)

    def _get_cctxt(self):
        return self.client.prepare(version=self.ver,
                                   topic=self._get_security_group_topic(),
                                   fanout=True)

    def _get_cctxt_direct(self, host):
        return self.client.prepare(version=self.ver,
                    topic=self._get_security_group_topic(host=host))

    def create_network_cast(self, current, segment):
        return self._get_cctxt().cast(self.context, 'create_network',
                                      current=current, segment=segment)

    def delete_network_cast(self, current, segment):
        return self._get_cctxt().cast(self.context, 'delete_network',
                                      current=current, segment=segment)

    def update_network_cast(self, current, segment, original):
        return self._get_cctxt().cast(self.context, 'update_network',
                                      current=current, segment=segment,
                                      original=original)

    def bind_port_call(self, current, network_segments, network_current, host):
        return self._get_cctxt_direct(host).call(
            self.context, 'bind_port', current=current,
            network_segments=network_segments, network_current=network_current)

    def update_postcommit_port_call(self, current, original, segment, host):
        return self._get_cctxt_direct(host).call(
            self.context, 'post_update_port', current=current,
            original=original, segment=segment)

    def delete_port_call(self, current, original, segment, host):
        return self._get_cctxt_direct(host).call(
            self.context, 'delete_port', current=current, original=original,
            segment=segment)
