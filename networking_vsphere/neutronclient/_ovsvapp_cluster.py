# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
#
# All Rights Reserved
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
import six

from networking_vsphere._i18n import _

from neutronclient.common import exceptions
from neutronclient.common import extension
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronV20

from oslo_serialization import jsonutils


class OVSvAppCluster(extension.NeutronClientExtension):
    resource = 'ovsvapp_cluster'
    resource_plural = 'ovsvapp_clusters'
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']


def _format_devices(ovsvapp_cluster):
    try:
        return '\n'.join([(jsonutils.dumps(cluster)).replace(
                          '"', '') for cluster in
                          ovsvapp_cluster['clusters']])
    except (TypeError, KeyError):
        return ''


def comman_args2body(parsed_args):
    body = {'ovsvapp_cluster': {
            'vcenter_id': parsed_args.vcenter_id,
            'clusters': parsed_args.clusters}, }
    neutronV20.update_dict(parsed_args, body['ovsvapp_cluster'],
                           ['vcenter_id', 'clusters'])
    return body


def comman_add_args(parser):
    parser.add_argument(
        '--vcenter_id', metavar='VCENTER_ID',
        required=True,
        help=_('Id of the new vCenter Cluster.'))
    parser.add_argument(
        '--clusters', metavar='[CLUSTERS]',
        required=True, type=lambda x: x.split(),
        help=_('List of Clusters for the given vCenter.'))
    return parser


class OVSvAppClusterCreate(extension.ClientExtensionCreate, OVSvAppCluster):
    """Creates a given new vcenter cluster."""
    shell_command = 'ovsvapp-cluster-create'
    list_columns = ['vcenter_id', 'clusters']

    def add_known_arguments(self, parser):
        comman_add_args(parser)

    def args2body(self, parsed_args):
        body = comman_args2body(parsed_args)
        return body


class OVSvAppClusterUpdate(extension.ClientExtensionUpdate, OVSvAppCluster):
    """Delete a given vcenter cluster with given details."""
    shell_command = 'ovsvapp-cluster-update'
    allow_names = True

    def get_parser(self, prog_name):
        parser = super(neutronV20.UpdateCommand, self).get_parser(prog_name)
        comman_add_args(parser)
        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)', parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        parsed_args.id = parsed_args.vcenter_id
        body = self.args2body(parsed_args)
        if not body[self.resource]:
            raise exceptions.CommandError(
                _("Must specify existing values to delete %s "
                  "info") % self.resource)
        obj_updator = getattr(neutron_client,
                              "update_%s" % self.resource)
        obj_updator(parsed_args.id, body)
        return

    def args2body(self, parsed_args):
        return comman_args2body(parsed_args)


class OVSvAppClusterList(extension.ClientExtensionList, OVSvAppCluster):
    """List vCenter Clusters under Admin Context."""

    shell_command = 'ovsvapp-cluster-list'

    _formatters = {'clusters': _format_devices, }
    list_columns = ['vcenter_id', 'clusters']
    pagination_support = True
    sorting_support = True


class OVSvAppClusterShow(extension.ClientExtensionShow, OVSvAppCluster):
    """Show information of a given vCenter Name."""

    shell_command = 'ovsvapp-cluster-show'
    allow_names = True

    def execute(self, parsed_args):
        self.log.debug('execute(%s)', parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        vcenter_id = parsed_args.id
        params = {}
        obj_shower = getattr(neutron_client,
                             "show_%s" % self.resource)
        data = obj_shower(vcenter_id, **params)
        try:
            if data[self.resource] == {}:
                raise Exception()
            if self.resource in data:
                for k, v in six.iteritems(data[self.resource]):
                    if isinstance(v, list):
                        value = ""
                        for _item in v:
                            if value:
                                value += "\n"
                            if isinstance(_item, dict):
                                value += utils.dumps(_item)
                            else:
                                value += str(_item)
                        data[self.resource][k] = value
                    elif v is None:
                        data[self.resource][k] = ''
        except Exception:
            not_found_message = (_("Unable to find %(resource)s with vCenter "
                                   "name '%(vcenter_id)s'.") %
                                 {'resource': self.resource,
                                  'vcenter_id': vcenter_id})
            raise exceptions.NeutronClientException(
                message=not_found_message, status_code=404)
        return zip(*sorted(six.iteritems(data[self.resource])))
