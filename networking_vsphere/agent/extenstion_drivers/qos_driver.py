# Copyright 2018 CtYun, Inc.
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

from neutron.agent.l2.extensions import qos


class QosDvsAgentDriver(qos.QosAgentDriver):

    def __init__(self):
        super(QosDvsAgentDriver, self).__init__()

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def initialize(self):
        pass

    def create_bandwidth_limit(self, port, rule):
        pass

    def update_bandwidth_limit(self, port, rule):
        pass

    def delete_bandwidth_limit(self, port):
        pass

    def delete_bandwidth_limit_ingress(self, port):
        pass

    def create_dscp_marking(self, port, rule):
        pass

    def update_dscp_marking(self, port, rule):
        pass

    def delete_dscp_marking(self, port):
        pass

    def _update_egress_bandwidth_limit(self, vif_port, rule):
        pass

    def _update_ingress_bandwidth_limit(self, vif_port, rule):
        pass

    def _get_egress_burst_value(self, rule):
        pass
