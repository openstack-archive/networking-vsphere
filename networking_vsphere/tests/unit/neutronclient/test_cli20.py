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

from mox3 import mox
from neutronclient.neutron import v2_0 as ovsvappV2_0
from neutronclient import shell as neutronshell
from neutronclient.tests.unit import test_cli20 as neutron_test_cli20
from neutronclient.v2_0 import client as ovsvappclient

TOKEN = neutron_test_cli20.TOKEN
end_url = neutron_test_cli20.end_url


class MyResp(neutron_test_cli20.MyResp):

    pass


class MyApp(neutron_test_cli20.MyApp):

    pass


class MyComparator(neutron_test_cli20.MyComparator):

    pass


class MyUrlComparator(neutron_test_cli20.MyUrlComparator):

    pass


class CLITestV20Base(neutron_test_cli20.CLITestV20Base):

    def setUp(self, plurals=None):
        super(CLITestV20Base, self).setUp()
        self.client = ovsvappclient.Client(token=TOKEN,
                                           endpoint_url=self.endurl)

    def _test_create_resource(self, resource, cmd, name, myid, args,
                              position_names, position_values,
                              tenant_id=None, tags=None, admin_state_up=True,
                              extra_body=None, cmd_resource=None,
                              parent_id=None, **kwargs):
        self.mox.StubOutWithMock(cmd, "get_client")
        self.mox.StubOutWithMock(self.client.httpclient, "request")
        cmd.get_client().MultipleTimes().AndReturn(self.client)
        if not cmd_resource:
            cmd_resource = resource
        body = {resource: {}, }
        body[resource].update(kwargs)

        for i in range(len(position_names)):
            body[resource].update({position_names[i]: position_values[i]})
        ress = {resource:
                {self.id_field: myid}, }
        if name:
            ress[resource].update({'name': name})
        self.client.format = self.format
        resstr = self.client.serialize(ress)
        # url method body
        resource_plural = ovsvappV2_0._get_resource_plural(cmd_resource,
                                                           self.client)
        path = getattr(self.client, resource_plural + "_path")
        if self.format == 'json':
            mox_body = MyComparator(body, self.client)
        else:
            mox_body = self.client.serialize(body)
        self.client.httpclient.request(
            end_url(path, format=self.format), 'POST',
            body=mox_body,
            headers=mox.ContainsKeyValue(
                'X-Auth-Token', TOKEN)).AndReturn((MyResp(200), resstr))
        args.extend(['--request-format', self.format])
        self.mox.ReplayAll()
        cmd_parser = cmd.get_parser('create_' + resource)
        neutronshell.run_command(cmd, cmd_parser, args)
        self.mox.VerifyAll()
        self.mox.UnsetStubs()
        _str = self.fake_stdout.make_string()
        self.assertIn(myid, _str)
        if name:
            self.assertIn(name, _str)

    def _test_update_resource(self, resource, cmd, myid, args, extrafields,
                              cmd_resource=None, parent_id=None):
        self.mox.StubOutWithMock(cmd, "get_client")
        self.mox.StubOutWithMock(self.client.httpclient, "request")
        cmd.get_client().MultipleTimes().AndReturn(self.client)
        if not cmd_resource:
            cmd_resource = resource

        body = {resource: extrafields}
        path = getattr(self.client, cmd_resource + "_path")

        if parent_id:
            path = path % (parent_id, myid)
        else:
            path = path % extrafields['vcenter_id']
        mox_body = MyComparator(body, self.client)

        self.client.httpclient.request(
            MyUrlComparator(end_url(path, format=self.format),
                            self.client),
            'PUT',
            body=mox_body,
            headers=mox.ContainsKeyValue(
                'X-Auth-Token', TOKEN)).AndReturn((MyResp(204), None))
        self.mox.ReplayAll()
        cmd_parser = cmd.get_parser("update_" + cmd_resource)
        neutronshell.run_command(cmd, cmd_parser, args)
        self.mox.VerifyAll()
        self.mox.UnsetStubs()
        _str = self.fake_stdout.make_string()
        # Delete a given vcenter cluster with given details
        # will return nothing
        self.assertEqual(_str, '')
