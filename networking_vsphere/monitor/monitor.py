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

import logging
import os
import signal
import subprocess
import sys
import time

from networking_vsphere._i18n import _LE, _LI
from neutron.common import config as common_config

LOG = logging.getLogger(__name__)
LOG_FILE_PATH = '/var/log/neutron/ovsvapp-agent/monitor.log'
JSON_FILE_PATH = '/var/log/neutron/ovsvapp-agent/status.json'


def start_monitor():
    '''Method to start monitoring the required processes.'''
    try:
        current_dir = os.path.dirname(os.path.realpath(__file__))
        ovs_monitor_path = str(current_dir) + '/ovsvapp-agent-monitor.sh'
        os.chmod(ovs_monitor_path, 0o755)
        LOG.info(_LI("Loading OVS_MONITOR: %s"), ovs_monitor_path)
        while True:
            subprocess.call(ovs_monitor_path)
            f = open(LOG_FILE_PATH)
            for line in f:
                pass
            status = line
            sf = open(JSON_FILE_PATH, 'w')
            if 'broken' in status or 'pending' in status:
                sf.write('{"ovs": "BAD"}')
            else:
                sf.write('{"ovs": "OK"}')
            sf.close()
            f.close()
            time.sleep(2)
    except Exception as e:
        LOG.exception(_LE("Error in start_monitor method %(err)s."),
                      {'err': e})


def main():

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    common_config.setup_logging()
    FORMAT = '%(asctime)-15s %(message)s'
    logging.basicConfig(format=FORMAT,
                        filename=LOG_FILE_PATH,
                        level=logging.DEBUG)
    try:
        LOG.info(_LI("Starting ovsvapp-agent-monitor."))
        start_monitor()
    except Exception as e:
        LOG.exception(_LE("Failed to start ovsvapp-agent-monitor "
                          "%(err)s."), {'err': e})


def stop(signum, frame):
    '''Signal handler to stop the OVSvApp agent Monitoring.'''
    LOG.info(_LI("Stopping ovsvapp-agent-monitor."))
    sys.exit(0)
