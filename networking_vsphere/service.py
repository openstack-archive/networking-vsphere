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

import signal
import sys

import eventlet
eventlet.monkey_patch()
from oslo_config import cfg
from oslo_log import log

from neutron.common import config as neutron_config

from networking_vsphere.agent import agent
from networking_vsphere.common import config as ovsvapp_config
from networking_vsphere.common import utils

LOG = log.getLogger(__name__)

agent_obj = None


def main():
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    try:
        global agent_obj
        neutron_config.init(sys.argv[1:])
        neutron_config.setup_logging()
        LOG.debug("Logging setup complete")
        ovsvapp_config.register_options()
        LOG.info(_("Loading agent %s"), cfg.CONF.OVSVAPP.agent_driver)
        agent_obj = utils.load_object(cfg.CONF.OVSVAPP.agent_driver,
                                      agent.Agent)
        agent_obj.start()
    except Exception as e:
        LOG.exception(_("Error in L2 agent service"))
        if agent_obj:
            agent_obj.stop()
        sys.exit(_("ERROR: %s") % e)


def signal_handler(signum, frame):
    signals_to_names = {}
    for n in dir(signal):
        if n.startswith('SIG') and not n.startswith('SIG_'):
            signals_to_names[getattr(signal, n)] = n
    LOG.info(_("Caught %s, exiting"), signals_to_names[signum])
    if agent_obj:
        try:
            agent_obj.stop()
        except Exception:
            # Ignore any exceptions while exiting
            pass
    signal.signal(signum, signal.SIG_DFL)
    sys.exit(0)


if __name__ == '__main__':
    main()
