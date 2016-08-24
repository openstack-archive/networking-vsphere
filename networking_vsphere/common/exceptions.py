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

from networking_vsphere._i18n import _
from neutron.common import exceptions


class VMWareDVSException(exceptions.NeutronException):
    """Base of all exceptions throwed by vmware_dvs driver"""
    message = _('VMWare DVS exception occurred. Original Exception: '
                '"%(type)s: %(message)s". Cause: "%(cause)s."')


class InvalidSystemState(VMWareDVSException):
    message = _('OpenStack environment or one of it component is in invalid '
                'state: %(details)s')


class InvalidNetwork(VMWareDVSException):
    message = _('Not supported or incorrectly configured network %(name)s')


class NotSupportedNetworkType(InvalidNetwork):
    message = _("VMWare DVS driver don't support %(network_type)s network")


class InvalidNetworkName(InvalidNetwork):
    message = _('Illegal network name %(name)s: %(reason)s')


class ResourceNotFound(VMWareDVSException):
    message = _('Resource not found')


class ClusterNotFound(ResourceNotFound):
    message = _('Cluster Compute Resource %(cluster_name)s not found')


class DVSNotFound(ResourceNotFound):
    message = _('Distributed Virtual Switch %(dvs_name)s not found')


class PortGroupNotFound(ResourceNotFound):
    message = _('Port Group %(pg_name)s not found')


class PortNotFound(ResourceNotFound):
    message = _('Port %(id)s not found')


class UnboundPortNotFound(ResourceNotFound):
    message = _('Unbound port not found')


class HypervisorNotFound(ResourceNotFound):
    message = _('Hypervisor not found')


class VMNotFound(ResourceNotFound):
    message = _('Virtual machine not found')


class NoDVSForPhysicalNetwork(VMWareDVSException):
    message = _('No dvs mapped for physical network: %(physical_network)s')


def wrap_wmvare_vim_exception(original_exception):
    return VMWareDVSException(type=type(original_exception),
                              message=original_exception.msg,
                              cause=original_exception.cause)
