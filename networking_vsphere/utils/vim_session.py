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

import time

from networking_vsphere._i18n import _LE

from oslo_log import log
from oslo_vmware import api
from oslo_vmware import vim

LOG = log.getLogger(__name__)


class ConnectionHandler(object):
    session = None
    host_ip = None
    host_username = None
    host_password = None
    api_retry_count = 0
    wsdl_url = None
    ca_cert = None
    scheme = None
    stopped = False
    create_session = True
    https_port = 443

    @classmethod
    def set_vc_details(cls, host_ip, host_username, host_password,
                       api_retry_count, wsdl_url, ca_cert,
                       https_port=443, scheme="https"):
        cls.session = None
        cls.host_ip = host_ip
        cls.host_username = host_username
        cls.host_password = host_password
        cls.api_retry_count = api_retry_count
        cls.wsdl_url = wsdl_url
        cls.scheme = scheme
        cls.https_port = https_port
        cls.stopped = False
        cls.create_session = True
        cls.ca_cert = ca_cert

    @classmethod
    def stop(cls):
        cls.stopped = True
        if cls.session:
            cls.session.logout()
        cls.session = None

    @classmethod
    def start(cls):
        cls.stopped = False

    @classmethod
    def create_connection(cls):
        cls.session = VMWareAPISession(cls.host_ip,
                                       cls.host_username,
                                       cls.host_password,
                                       cls.api_retry_count,
                                       cls.wsdl_url,
                                       scheme=cls.scheme,
                                       https_port=cls.https_port,
                                       create_session=cls.create_session,
                                       ca_cert=cls.ca_cert)
        return cls.session

    @classmethod
    def get_connection(cls, create=False):
        if not cls.session and create:
            return cls.create_connection()
        else:
            return cls.session

    @classmethod
    def try_connection(cls):
        while not cls.stopped:
            try:
                return cls.get_connection(create=True)
            except Exception as e:
                LOG.error(_LE("Connection to vCenter %(host_ip)s failed -"
                              "%(exception)s"), {"host_ip": cls.host_ip,
                                                 "exception": e})
                LOG.error(_LE("Will retry after 60 secs"))
                time.sleep(60)
                LOG.error(_LE("Retrying VMWare Connection after 60 secs"))
                continue


class VMWareAPISession(api.VMwareAPISession):

    """Sets up a session with the ESX host and handles all the calls."""

    def __init__(self, host_ip, host_username, host_password,
                 api_retry_count, wsdl_url, scheme="https", https_port=443,
                 create_session=True, ca_cert=None):
        super(VMWareAPISession, self).__init__(
            host=host_ip,
            port=https_port,
            server_username=host_username,
            server_password=host_password,
            api_retry_count=api_retry_count,
            scheme=scheme,
            task_poll_interval=1,
            wsdl_loc=wsdl_url,
            create_session=create_session,
            cacert=ca_cert)

    def __del__(self):
        """Logs-out the session."""
        # Logout to avoid un-necessary increase in session count at the
        # ESX host
        try:
            self.logout()
        except Exception:
            # It is just cautionary on our part to do a logout in del just
            # to ensure that the session is not left active.
            pass

    def _is_vim_object(self, module):
        """Check if the module is a VIM Object instance."""
        return isinstance(module, vim.Vim)

    def _call_method(self, module, method, *args, **kwargs):
        """Calls a method within the module specified with args provided."""
        if not self._is_vim_object(module):
            return self.invoke_api(module, method, self.vim, *args, **kwargs)
        else:
            return self.invoke_api(module, method, *args, **kwargs)

    def _get_vim(self):
        """Gets the VIM object reference."""
        return self.vim
