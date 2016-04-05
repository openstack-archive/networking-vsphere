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

import argparse
import six

from networking_vsphere._i18n import _
from neutronclient.common import exceptions
from neutronclient.common import extension
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronV20


class OVSvAppMitigatedCluster(extension.NeutronClientExtension):
    resource = 'ovsvapp_mitigated_cluster'
    resource_plural = 'ovsvapp_mitigated_clusters'
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']


class OVSvAppMitigatedClusterList(extension.ClientExtensionList,
                                  OVSvAppMitigatedCluster):
    """List all Mitigated clusters under Admin Context."""

    shell_command = 'ovsvapp-mitigated-cluster-list'

    list_columns = ['vcenter_id', 'cluster_id', 'being_mitigated',
                    'threshold_reached']
    pagination_support = True
    sorting_support = True


class OVSvAppMitigatedClusterShow(extension.ClientExtensionShow,
                                  OVSvAppMitigatedCluster):
    """Show mitigated info of a given cluster."""

    shell_command = 'ovsvapp-mitigated-cluster-show'
    allow_names = True

    def args2body(self, parsed_args):
        body = {'ovsvapp_mitigated_cluster': {
                'vcenter_id': parsed_args.vcenter_id,
                'cluster_id': parsed_args.cluster_id}}
        return body

    def get_parser(self, prog_name):
        parser = super(neutronV20.ShowCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--vcenter-id', metavar='VCENTER_ID',
            required=True,
            dest='vcenter_id',
            help=_('Specify the vcenter_id.'))
        parser.add_argument(
            '--cluster-id', metavar='CLUSTER_ID',
            dest='cluster_id',
            required=True,
            help=_('Specify the cluster_id.'))

        return parser

    def execute(self, parsed_args):
        self.log.debug('execute(%s)', parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        parsed_args.id = (parsed_args.vcenter_id + ':'
                          + parsed_args.cluster_id.replace('/', '|'))
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


def comman_args2body(parsed_args):
    if not parsed_args.being_mitigated:
        if not parsed_args.threshold_reached:
            err_msg = 'Have to specify atleast one parameter to update.'
            raise exceptions.NeutronClientException(
                message=err_msg, status_code=400)
    body = {'ovsvapp_mitigated_cluster': {
        'vcenter_id': parsed_args.vcenter_id,
        'cluster_id': parsed_args.cluster_id}}
    neutronV20.update_dict(parsed_args, body['ovsvapp_mitigated_cluster'],
                           ['vcenter_id', 'cluster_id'])
    res_dict = body['ovsvapp_mitigated_cluster']
    if parsed_args.being_mitigated:
        res_dict['being_mitigated'] = parsed_args.being_mitigated
        neutronV20.update_dict(parsed_args, body['ovsvapp_mitigated_cluster'],
                               ['being_mitigated'])
    if parsed_args.threshold_reached:
        res_dict['threshold_reached'] = parsed_args.threshold_reached
        neutronV20.update_dict(parsed_args, body['ovsvapp_mitigated_cluster'],
                               ['threshold_reached'])
    return body


def comman_add_args(parser):
    parser.add_argument(
        '--vcenter-id', metavar='VCENTER_ID',
        required=True,
        dest='vcenter_id',
        help=_('Specify the vcenter_id.'))
    parser.add_argument(
        '--cluster-id', metavar='CLUSTER_ID',
        dest='cluster_id',
        required=True,
        help=_('Specify the cluster_id.'))
    parser.add_argument(
        '--being-mitigated', metavar='BEING_MITIGATED',
        dest='being_mitigated',
        help=_('Specify the being mitigated flag (True/False).'))
    parser.add_argument(
        '--threshold-reached', metavar='THRESHOLD_REACHED',
        dest='threshold_reached',
        help=_('Specify the threshold reached flag (True/False).'))


class OVSvAppMitigatedClusterUpdate(extension.ClientExtensionUpdate,
                                    OVSvAppMitigatedCluster):
    """Update a given mitigated cluster with given details."""

    shell_command = 'ovsvapp-mitigated-cluster-update'
    allow_names = True

    def get_parser(self, prog_name):
        parser = super(neutronV20.NeutronCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--request-format',
            help=_('The XML or JSON request format.'),
            default='json',
            choices=['json', 'xml', ], )
        parser.add_argument(
            '--request_format',
            choices=['json', 'xml', ],
            help=argparse.SUPPRESS)
        comman_add_args(parser)
        return parser

    def args2body(self, parsed_args):
        return comman_args2body(parsed_args)

    def run(self, parsed_args):
        self.log.debug('run(%s)', parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        parsed_args.id = (parsed_args.vcenter_id + ':'
                          + parsed_args.cluster_id.replace('/', '|'))
        body = self.args2body(parsed_args)
        if not body[self.resource]:
            raise exceptions.CommandError(
                _("Must specify new values to update %s.") % self.resource)
        obj_updator = getattr(neutron_client,
                              "update_%s" % self.resource)
        obj_updator(parsed_args.id, body)
        print(_('Updated the given vcenter:cluster %(vcenter_id)s:'
              '%(cluster_id)s.') % {'vcenter_id': parsed_args.vcenter_id,
              'cluster_id': parsed_args.cluster_id})
        return


class OVSvAppMitigatedClusterDelete(extension.ClientExtensionDelete,
                                    OVSvAppMitigatedCluster):
    """Delete mitigation information of a specific cluster given."""

    shell_command = 'ovsvapp-mitigated-cluster-delete'

    allow_names = True

    def args2body(self, parsed_args):
        return comman_args2body(parsed_args)

    def get_parser(self, prog_name):
        parser = super(neutronV20.NeutronCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--request-format',
            help=_('The XML or JSON request format.'),
            default='json',
            choices=['json', 'xml', ], )
        parser.add_argument(
            '--request_format',
            choices=['json', 'xml', ],
            help=argparse.SUPPRESS)
        parser.add_argument(
            '--vcenter-id', metavar='VCENTER_ID',
            required=True,
            dest='vcenter_id',
            help=_('Specify the vcenter_id.'))
        parser.add_argument(
            '--cluster-id', metavar='CLUSTER_ID',
            dest='cluster_id',
            required=True,
            help=_('Specify the cluster_id.'))

        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)', parsed_args)
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        parsed_args.id = (parsed_args.vcenter_id + ':'
                          + parsed_args.cluster_id.replace('/', '|'))
        obj_deletor = getattr(neutron_client,
                              "delete_%s" % self.resource)
        obj_deletor(parsed_args.id)
        print(_('Deleted the given vcenter:cluster %(vcenter_id)s:'
              '%(cluster_id)s.') % {'vcenter_id': parsed_args.vcenter_id,
              'cluster_id': parsed_args.cluster_id})
