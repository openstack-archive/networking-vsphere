# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
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


import uuid

_CLASSES = ['session', 'VirtualMachine', 'HostSystem', 'HostNetworkSystem',
            'ClusterComputeResource']

_db_content = {}


class Constants:
    VM_UUID = "1111-2222-3333-4444"
    VM_NAME = "TEST_VIRTUAL_MACHINE"
    HOST_NAME = "TEST_HOST"


def reset():
    """Resets the db contents."""
    for c in _CLASSES:
        _db_content[c] = {}

    create_host_network_system()
    create_host()
    create_virtual_machine()
    create_cluster_compute_resource()


def cleanup():
    """Clear the db contents."""
    for c in _CLASSES:
        _db_content[c] = {}


def _create_object(table, table_obj):
    """Create an object in the db."""
    _db_content[table][table_obj.value] = table_obj


class Prop(object):
    """Property Object base class."""

    def __init__(self):
        self.name = None
        self.val = None


class ManagedObject(object):
    """Managed Data Object base class."""

    def __init__(self, name="ManagedObject", obj_ref=None):
        """Sets the obj property which acts as a reference to the object."""
        super(ManagedObject, self).__setattr__('objName', name)
        if obj_ref is None:
            obj_ref = str(uuid.uuid4())
        object.__setattr__(self, 'obj', self)
        object.__setattr__(self, 'propSet', [])
        object.__setattr__(self, 'value', obj_ref)
        object.__setattr__(self, '_type', name)

    def set(self, attr, val):
        """Sets an attribute value.

        Not using the __setattr__ directly for we want to set attributes
        of the type 'a.b.c' and using this function class we set the same.
        """
        self.__setattr__(attr, val)

    def get(self, attr):
        """Gets an attribute.

        Used as an intermediary to get nested property like 'a.b.c' value.
        """
        return self.__getattr__(attr)

    def __setattr__(self, attr, val):
        for prop in self.propSet:
            if prop.name == attr:
                prop.val = val
                return
        elem = Prop()
        elem.name = attr
        elem.val = val
        self.propSet.append(elem)

    def __getattr__(self, attr):
        for elem in self.propSet:
            if elem.name == attr:
                return elem.val
        msg = _("Property %(attr)s not set for the managed object %(name)s")
        raise AttributeError(msg % {'attr': attr, 'name': self.objName})


class DataObject(object):
    """Data object base class."""
    pass


class ClusterComputeResource(ManagedObject):
    """ClusterComputeResource class."""

    def __init__(self, **kwargs):
        super(ClusterComputeResource, self).__init__("ClusterComputeResource")
        host = _db_content["HostSystem"].values()[0]
        host.set("parent", self)
        host_sytem = DataObject()
        host_sytem.ManagedObjectReference = [host]
        self.set("host", host_sytem)


class HostNetworkSystem(ManagedObject):
    """HostNetworkSystem class."""

    def __init__(self):
        super(HostNetworkSystem, self).__init__("HostNetworkSystem")
        self.set("name", "networkSystem")


class HostSystem(ManagedObject):
    """Host System class."""

    def __init__(self):
        super(HostSystem, self).__init__("HostSystem")
        self.set("name", Constants.HOST_NAME)

        if _db_content.get("HostNetworkSystem", None) is None:
            create_host_network_system()
        host_net_key = _db_content["HostNetworkSystem"].keys()[0]
        host_net_sys = _db_content["HostNetworkSystem"][host_net_key].value
        self.set("configManager.networkSystem", host_net_sys)


class VirtualMachine(ManagedObject):
    """Virtual Machine class."""

    def __init__(self, **kwargs):
        super(VirtualMachine, self).__init__("VirtualMachine")
        self.set("name", Constants.VM_NAME)
        config = DataObject()
        extra_config = DataObject()
        extra_config_option = DataObject()
        extra_config_option.key = "nvp.vm-uuid"
        extra_config_option.value = Constants.VM_UUID
        extra_config.OptionValue = [extra_config_option]
        config.extraConfig = extra_config
        self.set("config", config)
        self.set('config.extraConfig', extra_config)
        self.set('config.extraConfig["nvp.vm-uuid"]', extra_config_option)
        runtime = DataObject()
        host_ref = _db_content["HostSystem"][
            _db_content["HostSystem"].keys()[0]]
        runtime.host = host_ref
        self.set("runtime", runtime)
        self.set("runtime.host", runtime.host)


def create_host_network_system():
    host_net_system = HostNetworkSystem()
    _create_object("HostNetworkSystem", host_net_system)
    return host_net_system


def create_host():
    host_system = HostSystem()
    _create_object('HostSystem', host_system)
    return host_system


def create_cluster_compute_resource():
    cluster = ClusterComputeResource()
    _create_object('ClusterComputeResource', cluster)
    return cluster


def create_virtual_machine():
    virtual_machine = VirtualMachine()
    _create_object('VirtualMachine', virtual_machine)
    return virtual_machine


class FakeFactory(object):
    """Fake factory class with create method."""

    def create(self, obj_name):
        """Creates a namespace object."""
        return DataObject()


class FakeVim(object):
    """Fake VIM Class."""

    def __init__(self, protocol="https", host="localhost", trace=None):
        """Initializes a fake Vim object.

        Sets the service contents and cookies for the session.
        """
        self._session = None
        self.client = DataObject()
        self.client.factory = FakeFactory()

        service_content = self.client.factory.create('ns0:ServiceContent')
        service_content.propertyCollector = "PropCollector"
        service_content.sessionManager = "SessionManager"
        service_content.rootFolder = DataObject()
        service_content.rootFolder.value = "RootFolder"
        self.service_content = service_content

    def get_service_content(self):
        return self.service_content

    def _login(self):
        """Logs in and sets the session object in the db."""
        self._session = str(uuid.uuid4())
        session = DataObject()
        session.key = self._session
        _db_content['session'][self._session] = session
        return session

    def _retrieve_properties(self, method, *args, **kwargs):
        """Retrieves properties based on the type."""
        spec_set = kwargs.get("specSet")[0]
        type = spec_set.propSet[0].type
        properties = spec_set.propSet[0].pathSet
        objectSets = spec_set.objectSet
        lst_ret_objs = []
        for objectSet in objectSets:
            try:
                obj_ref = objectSet.obj
                if obj_ref == self.get_service_content().rootFolder:
                    for mdo_ref in _db_content[type]:
                        mdo = _db_content[type][mdo_ref]
                        temp_mdo = ManagedObject(mdo.objName, mdo.value)
                        for prop in properties:
                            temp_mdo.set(prop, mdo.get(prop))
                        lst_ret_objs.append(temp_mdo)
                else:
                    if isinstance(obj_ref, ManagedObject):
                        obj_ref = obj_ref.value
                    if obj_ref in _db_content[type]:
                        mdo = _db_content[type][obj_ref]
                        temp_mdo = ManagedObject(mdo.objName, obj_ref)
                        for prop in properties:
                            temp_mdo.set(prop, mdo.get(prop))
                        lst_ret_objs.append(temp_mdo)
            except Exception:
                continue
        if method == "RetrievePropertiesEx":
            res = DataObject()
            res.objects = lst_ret_objs
            return res
        else:
            return lst_ret_objs

    def __getattr__(self, attr_name):
        if attr_name == "Login":
            return lambda *args, **kwargs: self._login()
        elif attr_name == "RetrievePropertiesEx":
            return (lambda *args, **kwargs:
                    self._retrieve_properties(attr_name, *args, **kwargs))


class FakeDynamicPropertyObject(object):
    """Fake Dynamic Property object."""

    def __init__(self):
        self.name = "name"
        self.val = "val"


class FakeObjectContent(object):
    """Fake ObjectContent object."""

    def __init__(self):
        self.propSet = [FakeDynamicPropertyObject()]


class FakeRetrieveResultObject(object):
    """Fake RetrieveResult object."""

    def __init__(self):
        self.objects = [FakeObjectContent()]
        self.token = "1234"


class FakeVimUtil(object):
    """Fake Vim util object class."""

    def __init__(self):
        self.client = DataObject()
        self.client.factory = FakeFactory()

        service_content = self.client.factory.create('ns0:ServiceContent')
        service_content.propertyCollector = "PropCollector"
        service_content.rootFolder = DataObject()
        service_content.rootFolder.value = "RootFolder"
        self.service_content = service_content

        self.RetrievePropertiesExCalled = False
        self.ContinueRetrievePropertiesExCalled = False
        self.CreateFilterCalled = False
        self.CreatePropertyCollectorCalled = False

    def RetrievePropertiesEx(self, prop_coll, specSet, options):
        self.RetrievePropertiesExCalled = True
        res = FakeRetrieveResultObject()
        return res

    def ContinueRetrievePropertiesEx(self, prop_coll, token=None):
        self.ContinueRetrievePropertiesExCalled = True
        return