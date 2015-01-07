# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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

import os
import tempfile

from oslo.config import cfg

from networking_vsphere.common import config
from networking_vsphere.tests import base

CONF = cfg.CONF


class TestConfig(base.TestCase):

    def setUp(self):
        super(TestConfig, self).setUp()
        self.temp_dir = tempfile.mkdtemp()

    def test_parse(self):
        config_file = os.path.join(self.temp_dir, "ovsvapp.ini")
        with open(config_file, 'w') as fd:
            fd.write("[DEFAULT]\ntest_arg=test_val")
        argv = ['test_config', '--config-file=%s' % config_file]
        config.parse(argv[1:])
        test_opts = [cfg.
                     StrOpt('test_arg',
                            help=_("Test CONF item"),
                            default=_("test_val_def"))]
        CONF.register_opts(test_opts)
        self.assertEqual(CONF.test_arg, "test_val")
        self.addCleanup(config.remove_config_file, self.temp_dir)
