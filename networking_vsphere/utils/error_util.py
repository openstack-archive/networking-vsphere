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

"""
Exception classes
"""


class VimException(Exception):

    """The VIM Exception class."""

    def __init__(self, exception_summary, excep):
        Exception.__init__(self)
        self.exception_summary = exception_summary
        self.exception_obj = excep

    def __str__(self):
        return self.exception_summary + str(self.exception_obj)


class SocketTimeoutException(VimException):

    """Socket Timeout Exception."""
    pass


class VimFaultException(Exception):

    """The VIM Fault exception class."""

    def __init__(self, fault_list, excep):
        Exception.__init__(self)
        self.fault_list = fault_list
        self.exception_obj = excep

    def __str__(self):
        return str(self.exception_obj)


class RunTimeError(Exception):

    """vCenter Run time error."""
    pass
