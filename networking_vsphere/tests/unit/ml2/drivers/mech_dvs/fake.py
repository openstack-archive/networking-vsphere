# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2012 VMware, Inc.
# Copyright (c) 2011 Citrix Systems, Inc.
# Copyright 2011 OpenStack Foundation
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
A fake VMware VI API implementation.
"""
import collections

from neutron.openstack.common import jsonutils


class FakeRetrieveResult(object):
    """Object to retrieve a ObjectContent list."""

    def __init__(self, token=None):
        self.objects = []
        if token is not None:
            self.token = token

    def add_object(self, object):
        self.objects.append(object)


class ManagedObjectReference(object):
    """A managed object reference is a remote identifier."""

    def __init__(self, name="ManagedObject", value=None):
        super(ManagedObjectReference, self)
        # Managed Object Reference value attributes
        # typically have values like vm-123 or
        # host-232 and not UUID.
        self.value = value
        # Managed Object Reference type
        # attributes hold the name of the type
        # of the vCenter object the value
        # attribute is the identifier for
        self.type = name
        self._type = name


class ObjectContent(object):
    """ObjectContent array holds dynamic properties."""

    # This class is a *fake* of a class sent back to us by
    # SOAP. It has its own names. These names are decided
    # for us by the API we are *faking* here.
    def __init__(self, obj_ref, prop_list=None, missing_list=None):
        self.obj = obj_ref

        if not isinstance(prop_list, collections.Iterable):
            prop_list = []

        if not isinstance(missing_list, collections.Iterable):
            missing_list = []

        # propSet is the name your Python code will need to
        # use since this is the name that the API will use
        if prop_list:
            self.propSet = prop_list

        # missingSet is the name your python code will
        # need to use since this is the name that the
        # API we are talking to will use.
        if missing_list:
            self.missingSet = missing_list


class Prop(object):
    """Property Object base class."""

    def __init__(self, name=None, val=None):
        self.name = name
        self.val = val


class ContextBase(object):
    """Context for ml2 plugin"""

    def set(self, attr, val):
        """Sets an attribute value. Not using the __setattr__ directly for we
        want to set attributes of the type 'a.b.c' and using this function
        class we set the same.
        """
        self.__setattr__(attr, val)

    def get(self, attr):
        """Gets an attribute. Used as an intermediary to get nested
        property like 'a.b.c' value.
        """
        return self.__getattr__(attr)


class NetworkContext(ContextBase):
    def __init__(self, current={}, original={}, network_segments={}):
        object.__setattr__(self, 'current', current)
        object.__setattr__(self, 'original', original)
        object.__setattr__(self, 'network_segments',
                           network_segments)


class PortContext(ContextBase):
    def __init__(self, current={}, network=None):
        object.__setattr__(self, 'current', current)
        object.__setattr__(self, 'network', network)

    def set_binding(self):
        pass


class ManagedObject(object):
    """Managed Object base class."""
    _counter = 0

    def __init__(self, mo_id_prefix="obj"):
        """Sets the obj property which acts as a reference to the object."""
        object.__setattr__(self, 'mo_id', self._generate_moid(mo_id_prefix))
        object.__setattr__(self, 'propSet', [])
        object.__setattr__(self, 'obj',
                           ManagedObjectReference(self.__class__.__name__,
                                                  self.mo_id))

    def set(self, attr, val):
        """Sets an attribute value. Not using the __setattr__ directly for we
        want to set attributes of the type 'a.b.c' and using this function
        class we set the same.
        """
        self.__setattr__(attr, val)

    def get(self, attr):
        """Gets an attribute. Used as an intermediary to get nested
        property like 'a.b.c' value.
        """
        return self.__getattr__(attr)

    def __setattr__(self, attr, val):
        # TODO(hartsocks): this is adds unnecessary complexity to the class
        for prop in self.propSet:
            if prop.name == attr:
                prop.val = val
                return
        elem = Prop()
        elem.name = attr
        elem.val = val
        self.propSet.append(elem)

    def __getattr__(self, attr):
        # TODO(hartsocks): remove this
        # in a real ManagedObject you have to iterate the propSet
        # in a real ManagedObject, the propSet is a *set* not a list
        for elem in self.propSet:
            if elem.name == attr:
                return elem.val
        msg = _("Property %(attr)s not set for the managed object %(name)s")
        raise Exception(msg % {'attr': attr,
                               'name': self.__class__.__name__})

    def _generate_moid(self, prefix):
        """Generates a new Managed Object ID."""
        self.__class__._counter += 1
        return prefix + "-" + str(self.__class__._counter)

    def __repr__(self):
        return jsonutils.dumps(dict([(elem.name, elem.val)
                               for elem in self.propSet]))


class DataObject(object):
    """Data object base class."""

    def __init__(self, obj_name=None):
        self.obj_name = obj_name

    def __repr__(self):
        return str(self.__dict__)


class Datacenter(ManagedObject):
    """Datacenter class."""

    def __init__(self, name="ha-datacenter", ds_ref=None):
        super(Datacenter, self).__init__("dc")
        self.set("name", name)
        self.set("vmFolder", "vm_folder_ref")
        #if _db_content.get("Network", None) is None:
        #    create_network()
        #net_ref = _db_content["Network"][_db_content["Network"].keys()[0]].obj
        #network_do = DataObject()
        #network_do.ManagedObjectReference = [net_ref]
        #self.set("network", network_do)
        if ds_ref:
            datastore = DataObject()
            datastore.ManagedObjectReference = [ds_ref]
        else:
            datastore = None
        self.set("datastore", datastore)


class ResultCollection(object):
    def __init__(self, collections=[]):
        self.ManagedObjectReference = collections

    def reset(self):
        self.ManagedObjectReference = []

    def add(self, item):
        self.ManagedObjectReference.append(item)


class NetworkFolder(ManagedObjectReference):
    """Network Folder class."""
    def __init__(self, value, **kwargs):
        super(NetworkFolder, self).__init__("Folder", value)


class Network(ManagedObjectReference):
    """Network Folder class."""
    def __init__(self, value, **kwargs):
        super(Network, self).__init__("Network", value)


class VmwareDistributedVirtualSwitch(ManagedObjectReference):
    def __init__(self, value, **kwargs):
        super(VmwareDistributedVirtualSwitch, self).__init__(
            "VmwareDistributedVirtualSwitch", value)


class DistributedVirtualPortgroup(ManagedObjectReference):
    def __init__(self, value, **kwargs):
        super(DistributedVirtualPortgroup, self).__init__(
            "DistributedVirtualPortgroup", value)
