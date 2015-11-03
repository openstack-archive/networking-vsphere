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
#
from oslo_config import cfg

import logging
import os
import signal
import subprocess
import sys
import time

from networking_vsphere.common import config as ovsvapp_config
from neutron.common import config as common_config


LOG = logging.getLogger(__name__)


def initiate_monitor_log():
    ovsvapp_config.register_monitoring_opts()
    try:
        logger = logging.getLogger('monitor')
        logger.addHandler(logging.FileHandler
                          (cfg.CONF.OVSVAPP_MONITORING.monitor_log_path))
        return logger
    except Exception:
        LOG.error(_("Could not get handle for %s."),
                  cfg.CONF.OVSVAPP_MONITORING.monitor_log_path)


def start_monitor():
    '''Method to start monitoring the required processes.'''
    try:
        current_dir = os.path.dirname(os.path.realpath(__file__))
        ovs_monitor_path = str(current_dir) + '/ovsvapp-agent-monitor.sh'
        os.chmod(ovs_monitor_path, 0o755)
        LOG.info(_("Loading OVS_MONITOR: %s"), ovs_monitor_path)
        while True:
            subprocess.call(ovs_monitor_path)
            f = open(cfg.CONF.OVSVAPP_MONITORING.monitor_log_path)
            for line in f:
                pass
            status = line
            sf = open(cfg.CONF.OVSVAPP_MONITORING.status_json_path, 'w')
            if 'broken' in status or 'pending' in status:
                sf.write('{"ovs": "BAD"}')
            else:
                sf.write('{"ovs": "OK"}')
            sf.close()
            f.close()
            time.sleep(2)
    except Exception as e:
        LOG.exception(_("Error in start_monitor method %(err)s."),
                      {'err': e})


def main():

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    ovsvapp_config.register_monitoring_opts()
    FORMAT = '%(asctime)-15s %(message)s'
    logging.basicConfig(format=FORMAT,
                        filename=cfg.CONF.OVSVAPP_MONITORING.monitor_log_path,
                        level=logging.DEBUG)
    try:
        LOG.info(_("Starting ovsvapp-agent-monitor."))
        start_monitor()
    except Exception as e:
        LOG.exception(_("Failed to start ovsvapp-agent-monitor "
                        "%(err)s."), {'err': e})


def stop(signum, frame):
    '''Signal handler to stop the OVSvApp agent Monitoring.'''
    LOG.info(_("Stopping ovsvapp-agent-monitor."))
    sys.exit(0)
