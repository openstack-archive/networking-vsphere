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

import logging

import eventlet
import fixtures
import mock
from oslo_config import cfg
from oslo_messaging import conffixture as messaging_conffixture
from oslotest import base
import six

from networking_vsphere.common import config as ovsvapp_config

from neutron.common import rpc as n_rpc
from neutron.tests import fake_notifier

CONF = cfg.CONF
eventlet.monkey_patch()


class TestCase(base.BaseTestCase):

    """Test case base class for all unit tests."""

    def setUp(self):
        """Run before each test method to initialize test environment."""
        super(base.BaseTestCase, self).setUp()
        ovsvapp_config.register_options()
        self.setup_rpc_mocks()
        self.mock = mock.Mock()
        self.logger = self.useFixture(fixtures.FakeLogger(name="neutron",
                                                          level=logging.INFO
                                                          ))
        self._overridden_opts = []
        self.addCleanup(self.del_attributes)
        self.addCleanup(self.reset_flags)

    def setup_rpc_mocks(self):
        # don't actually start RPC listeners when testing
        mock.patch('neutron.common.rpc.Connection.consume_in_threads',
                   return_value=[]).start()

        self.useFixture(fixtures.MonkeyPatch(
            'oslo_messaging.Notifier', fake_notifier.FakeNotifier))

        self.messaging_conf = messaging_conffixture.ConfFixture(CONF)
        self.messaging_conf.transport_driver = 'fake'
        # NOTE(russellb) We want all calls to return immediately.
        self.messaging_conf.response_timeout = 0
        self.useFixture(self.messaging_conf)

        self.addCleanup(n_rpc.clear_extra_exmods)
        n_rpc.add_extra_exmods('neutron.test')

        self.addCleanup(n_rpc.cleanup)
        n_rpc.init(CONF)

    def flags(self, **kw):
        """Override flag variables for a test."""
        group = kw.pop('group', None)
        module = kw.pop('module', None)
        for k, v in six.iteritems(kw):
            if module:
                CONF.import_opt(k, module, group)
            CONF.set_override(k, v, group)
            self._overridden_opts.append((k, group))

    def reset_flags(self):
        """Resets all flag variables for the test.

        Runs after each test.

        """
        for (k, group) in self._overridden_opts:
            CONF.clear_override(k, group)
        self._overridden_opts = []

    def del_attributes(self):
        """Deletes attributes for the test.

        Runs after each test.

        """
        # Delete attributes that don't start with _ so they don't pin
        # memory around unnecessarily for the duration of the test
        # suite
        for key in [k for k in self.__dict__.keys() if k[0] != '_']:
            del self.__dict__[key]
