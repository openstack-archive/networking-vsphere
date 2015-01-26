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

import os
import time

import eventlet
from oslo.config import cfg

from neutron.openstack.common import log as logging

from networking_vsphere.common import config
from networking_vsphere.common import constants
from networking_vsphere.common import utils
from networking_vsphere.drivers import base_manager as manager
from networking_vsphere.drivers import driver

cfg.CONF.import_group('OVSVAPPAGENT', 'networking_vsphere.common.config')

LOG = logging.getLogger(__name__)


class Agent(driver.NetworkDriverCallback):

    """Agent class.

    Base class for agents which takes care of common functionalities
    like - initializing driver managers and monitoring for conf updates.
    """

    def __init__(self):
        self.net_mgr = None
        self.state = constants.AGENT_INITIALIZING
        self.node_up = False

    def start(self):
        LOG.debug("Starting L2 agent")
        LOG.info(_("Starting configuration updates monitor"))
        t = eventlet.spawn(self._monitor_conf_updates)
        LOG.info(_("Waiting for node to be ACTIVE"))
        t.wait()

    def stop(self):
        LOG.debug("Stopping L2 agent")
        self.state = constants.AGENT_STOPPING
        self._stop_managers()
        self.state = constants.AGENT_STOPPED

    def _stop_managers(self):
        LOG.debug("Stopping managers")
        if self.net_mgr:
            self.net_mgr.stop()

    def _monitor_conf_updates(self):
        """Monitor all config files for any change."""
        LOG.info(_("Started configuration updates monitor"))
        old_timestamp = {}
        config_files = cfg.CONF.config_file
        try:
            for config_file in config_files:
                old_timestamp[config_file] = self._get_last_modified_time(
                    config_file)
            while self.state not in (constants.AGENT_STOPPED,
                                     constants.AGENT_STOPPING):
                try:
                    for config_file in config_files:
                        current_timestamp = self._get_last_modified_time(
                            config_file)
                        if current_timestamp != old_timestamp[config_file]:
                            LOG.info(_("%s updated.") % config_file)
                            LOG.debug("Reloading oslo-config opts.")
                            config.parse(["--config-file=%s" %
                                          f for f in config_files])
                            old_timestamp[config_file] = current_timestamp
                            eventlet.spawn_n(self._handle_conf_updates)
                except OSError as e:
                    LOG.error(_("Failed to monitor file %(config_file)s."
                              "Cause %(error)s "), {'config_file': config_file,
                              'error': e})
                time.sleep(cfg.CONF.OVSVAPPAGENT.conf_file_poll_interval)
        except OSError as e:
            LOG.error(_("Failed to monitor file %(config_file)s."
                      "Cause %(error)s "), {'config_file': config_file,
                      'error': e})

    def _get_last_modified_time(self, config_file):
        return os.stat(config_file).st_mtime

    def _handle_conf_updates(self):
        try:
            if not self.node_up:
                # handle conf updates only when node is up
                return
            self.state = constants.AGENT_INITIALIZING
            if self.net_mgr:
                self.net_mgr.handle_conf_update()
            self.state = constants.AGENT_INITIALIZED
            self._start_managers()
        except Exception as e:
            LOG.exception(_("Error while handling conf update: %s"), e)

    def _initialize_managers(self):
        self.state = constants.AGENT_INITIALIZING
        LOG.info(_("Loading network driver manager %s"),
                 cfg.CONF.OVSVAPPAGENT.network_manager)
        self.net_mgr = utils.load_object(cfg.CONF.OVSVAPPAGENT.network_manager,
                                         manager.DriverManager,
                                         self)
        self.net_mgr.initialize_driver()
        self.state = constants.AGENT_INITIALIZED

    def _start_managers(self):
        if self.state == constants.AGENT_INITIALIZED and self.node_up:
            LOG.info(_("Starting managers"))
            if self.net_mgr:
                self.net_mgr.start()
            self.state = constants.AGENT_RUNNING

    def set_node_state(self, is_up):
        if is_up != self.node_up:
            self.node_up = is_up
            if is_up:
                LOG.info(_("Making node up"))
                self._initialize_managers()
                self._start_managers()
            else:
                self.state = constants.AGENT_INITIALIZING
                self._stop_managers()
        else:
            LOG.info(_("Ignoring node update as agent"
                     " is already %s"),
                     "ACTIVE" if self.node_up else "DOWN")
