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

import copy
from oslo_log import log as logging

from tempest_lib import exceptions as lib_exc

from networking_vsphere.tests.tempest.common import isolated_creds
from networking_vsphere.tests.tempest import config
from networking_vsphere.tests.tempest import exceptions

CONF = config.CONF

LOG = logging.getLogger(__name__)


def get_tenant_network(creds_provider, compute_networks_client):
    """Get a network usable by the primary tenant

    :param creds_provider: instance of credential provider
    :param compute_networks_client: compute network client. We want to have the
           compute network client so we can have use a common approach for both
           neutron and nova-network cases. If this is not an admin network
           client, set_network_kwargs might fail in case fixed_network_name
           is the network to be used, and it's not visible to the tenant
    :return a dict with 'id' and 'name' of the network
    """
    fixed_network_name = CONF.compute.fixed_network_name
    network = None
    # NOTE(andreaf) get_primary_network will always be available once
    # bp test-accounts-continued is implemented
    if (isinstance(creds_provider, isolated_creds.IsolatedCreds) and
        (CONF.service_available.neutron and
         not CONF.service_available.ironic)):
        # tenant_allow_isolation == True, so network is defined
        network = creds_provider.get_primary_creds().network
    else:
        if fixed_network_name:
            try:
                resp = compute_networks_client.list_networks(
                    name=fixed_network_name)
                if isinstance(resp, list):
                    networks = resp
                elif isinstance(resp, dict):
                    networks = resp['networks']
                else:
                    raise lib_exc.NotFound()
                if len(networks) > 0:
                    network = networks[0]
                else:
                    msg = "Configured fixed_network_name not found"
                    raise exceptions.InvalidConfiguration(msg)
                # To be consistent with network isolation, add name is only
                # label is available
                network['name'] = network.get('name', network.get('label'))
            except lib_exc.NotFound:
                # In case of nova network, if the fixed_network_name is not
                # owned by the tenant, and the network client is not an admin
                # one, list_networks will not find it
                LOG.info('Unable to find network %s. '
                         'Starting instance without specifying a network.' %
                         fixed_network_name)
                network = {'name': fixed_network_name}
    LOG.info('Found network %s available for tenant' % network)
    return network


def set_networks_kwarg(network, kwargs=None):
    """Set 'networks' kwargs for a server create if missing

    :param network: dict of network to be used with 'id' and 'name'
    :param kwargs: server create kwargs to be enhanced
    :return: new dict of kwargs updated to include networks
    """
    params = copy.copy(kwargs) or {}
    if kwargs and 'networks' in kwargs:
        return params

    if network:
        params.update({"networks": [{'uuid': network['id']}]})
    return params
