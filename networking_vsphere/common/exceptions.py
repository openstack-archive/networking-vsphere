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

from neutron.common import exceptions
from neutron.i18n import _


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


class ResourceNotFond(VMWareDVSException):
    message = _('Resource not found')


class DVSNotFound(ResourceNotFond):
    message = _('Distributed Virtual Switch %(dvs_name)s not found')


class PortGroupNotFound(ResourceNotFond):
    message = _('Port Group %(pg_name)s not found')


class PortNotFound(ResourceNotFond):
    message = _('Port %(id)s not found')


class UnboundPortNotFound(ResourceNotFond):
    message = _('Unbound port not found')


class HypervisorNotFound(ResourceNotFond):
    message = _('Hypervisor not found')


class VMNotFound(ResourceNotFond):
    message = _('Virtual machine not found')


class NoDVSForPhysicalNetwork(VMWareDVSException):
    message = _('No dvs mapped for physical network: %(physical_network)s')


def wrap_wmvare_vim_exception(original_exception):
    return VMWareDVSException(type=type(original_exception),
                              message=original_exception.msg,
                              cause=original_exception.cause)
