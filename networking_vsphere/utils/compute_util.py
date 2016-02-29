# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from novaclient import client
from oslo_config.cfg import NoSuchOptError

from networking_vsphere.common import exceptions


NOVA_API_VERSION = '2'


def get_hypervisors_by_host(cfg, host):
    client = _make_nova_client(cfg)

    for hypervisor in client.hypervisors.list():
        if hypervisor.service['host'] == host:
            return hypervisor
    raise exceptions.HypervisorNotFound


def _make_nova_client(cfg):

    params = dict(
        username=cfg.nova.username,
        api_key=cfg.nova.password,
        project_id=cfg.nova.tenant_name,
        auth_url=cfg.nova.auth_url + "v2.0/"
    )

    try:
        params['cacert'] = cfg.nova_ca_certificates_file
    except NoSuchOptError:
        pass

    try:
        params['insecure'] = cfg.nova_api_insecure
    except NoSuchOptError:
        pass

    try:
        params['region_name'] = cfg.nova_region_name
    except NoSuchOptError:
        pass

    return client.Client(NOVA_API_VERSION, **params)
