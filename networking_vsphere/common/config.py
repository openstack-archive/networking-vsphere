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

import shutil

from oslo.config import cfg

from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def parse(args):
    cfg.CONF(args=args, project='neutron',
             default_config_files=["/etc/neutron/plugins/ovsvapp/"
                                   "ovsvapp.ini"])


def remove_config_file(temp_dir):
    shutil.rmtree(temp_dir)


def setup_logging():
    logging.setup("neutron")
    LOG.debug("Logging setup complete")
