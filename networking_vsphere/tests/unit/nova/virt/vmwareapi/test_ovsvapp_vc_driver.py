# Copyright (c) 2016 Hewlett-Packard Development Company, L.P.
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

from networking_vsphere.nova.virt.vmwareapi import ovsvapp_vc_driver
from nova import context
from nova import test
from nova.tests.unit import fake_instance


class OVSvAppVCDriverTestCase(test.TestCase):
    """Test Cases for ovsvapp_vc_driver.OVSvAppVCDriver."""

    def setUp(self):
        super(OVSvAppVCDriverTestCase, self).setUp()
        self.user_id = 'test_user_id'
        self.project_id = 'test_project_id'
        self.context = context.RequestContext(self.user_id, self.project_id,
                                              is_admin=False)
        self.conn = ovsvapp_vc_driver.OVSvAppVCDriver(None)

    def test_network_binding_host_id(self):
        expected = None
        host_id = self.conn.network_binding_host_id(self.context,
                                                    fake_instance)
        self.assertEqual(expected, host_id)
