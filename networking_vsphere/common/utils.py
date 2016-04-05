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

import functools
import sys
import traceback

from oslo_log import log

from networking_vsphere._i18n import _LI
from networking_vsphere.common import error

LOG = log.getLogger(__name__)


def import_class(import_str):
    """Returns a class from a string including module and class."""
    mod_str, _sep, class_str = import_str.rpartition('.')
    try:
        __import__(mod_str)
        return getattr(sys.modules[mod_str], class_str)
    except (ValueError, AttributeError):
        raise ImportError('Class %s cannot be found (%s).' %
                          (class_str,
                           traceback.format_exception(*sys.exc_info())))


def load_object(driver, base_class, *args, **kwargs):
    """Load a class, instantiate, check if its of base_class type."""
    driver_obj = import_class(driver)(*args, **kwargs)
    if not isinstance(driver_obj, base_class):
        raise TypeError("Invalid type - %s does not extend %s." %
                        (fullname(driver_obj), base_class))
    return driver_obj


def fullname(cls):
    """Get full name of a class."""
    module = cls.__module__
    if module is None or module == str.__class__.__module__:
        return cls.__class__.__name__
    return module + '.' + cls.__class__.__name__


def require_state(state=None, excp=True):
    """Decorator to check state of an object.

    First argument of the decorated function should be
    the object whose state needs to be checked.
    :param state: valid set of states
    :param excp: If True then raise an exception if in invalid state
    """
    if state is not None and not isinstance(state, set):
        state = set(state)

    def outer(f):
        @functools.wraps(f)
        def inner(obj, *args, **kw):
            if state is not None and obj.state not in state:
                l_states = list(state)
                if excp:
                    raise error.OVSvAppNeutronAgentError(
                        "%s not allowed. "
                        "%s is in %s state. "
                        "To be in %s state" %
                        (f.__name__,
                         obj.__class__.__name__,
                         obj.state,
                         l_states))
                else:
                    LOG.info(_LI("%(name)s not allowed. "
                                 "%(obj)s is %(state)s state. "
                                 "Need to be in %(states)s state."),
                             {'name': f.__name__,
                              'obj': obj.__class__.__name__,
                              'state': obj.state,
                              'states': l_states})
                    return
            return f(obj, *args, **kw)
        return inner
    return outer


def get_cluster_based_topic(cluster, device):
    if cluster:
        return cluster.replace('/', '_') + '_' + device
    else:
        return device
