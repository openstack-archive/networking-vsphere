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

from oslo_config import cfg
from oslo_log import log

from networking_vsphere._i18n import _LI
from networking_vsphere.common import constants
from networking_vsphere.common import utils
from networking_vsphere.drivers import base_manager as manager
from networking_vsphere.drivers import driver

LOG = log.getLogger(__name__)


class Agent(driver.NetworkDriverCallback):

    """Agent class.

    Base class for agents - initializing, starting and
    stopping driver manager.
    """

    def __init__(self):
        self.net_mgr = None
        self.state = constants.AGENT_INITIALIZING
        self.node_up = False

    def _stop_managers(self):
        LOG.debug("Stopping managers.")
        self.state = constants.AGENT_STOPPING
        if self.net_mgr:
            self.net_mgr.stop()
        self.state = constants.AGENT_STOPPED

    def _initialize_managers(self):
        self.state = constants.AGENT_INITIALIZING
        LOG.info(_LI("Loading network driver manager: %s."),
                 cfg.CONF.OVSVAPP.network_manager)
        self.net_mgr = utils.load_object(cfg.CONF.OVSVAPP.network_manager,
                                         manager.DriverManager,
                                         self)
        self.net_mgr.initialize_driver()
        self.state = constants.AGENT_INITIALIZED

    def _start_managers(self):
        if self.state == constants.AGENT_INITIALIZED and self.node_up:
            LOG.debug("Starting managers.")
            if self.net_mgr:
                self.net_mgr.start()
            self.state = constants.AGENT_RUNNING

    def set_node_state(self, is_up):
        if is_up != self.node_up:
            self.node_up = is_up
            if is_up:
                LOG.info(_LI("Making node up."))
                self._initialize_managers()
                self._start_managers()
            else:
                self.state = constants.AGENT_INITIALIZING
                self._stop_managers()
        else:
            LOG.info(_LI("Ignoring node update as agent "
                         "is already %s."),
                     "ACTIVE" if self.node_up else "DOWN")
