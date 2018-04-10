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

import mock

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


class ContainsKeyValue(neutron_test_cli20.ContainsKeyValue):
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
        resstr = self.client.serialize(ress)
        # url method body
        resource_plural = self.client.get_resource_plural(cmd_resource)
        path = getattr(self.client, resource_plural + "_path")
        mock_body = MyComparator(body, self.client)

        cmd_parser = cmd.get_parser('create_' + resource)

        resp = (MyResp(200), resstr)

        with mock.patch.object(cmd, "get_client",
                               return_value=self.client), \
                mock.patch.object(self.client.httpclient, "request",
                                  return_value=resp) as mock_request:

            neutronshell.run_command(cmd, cmd_parser, args)

            _str = self.fake_stdout.make_string()
            self.assertIn(myid, _str)
            if name:
                self.assertIn(name, _str)

            mock_request.asswert_called_once_with(
                MyUrlComparator(end_url(path), self.client),
                'PUT',
                body=mock_body,
                headers=ContainsKeyValue({'X-Auth-Token': TOKEN}))

    def _test_update_resource(self, resource, cmd, myid, args, extrafields,
                              cmd_resource=None, parent_id=None):
        if not cmd_resource:
            cmd_resource = resource

        # print 'ARGS: ' + repr(args)

        body = {resource: extrafields}
        path = getattr(self.client, cmd_resource + "_path")

        if parent_id:
            path = path % (parent_id, myid)
        else:
            path = path % extrafields['vcenter_id']
        mock_body = MyComparator(body, self.client)

        cmd_parser = cmd.get_parser("update_" + cmd_resource)

        resp = (MyResp(204), None)
        with mock.patch.object(cmd, "get_client",
                               return_value=self.client), \
                mock.patch.object(self.client.httpclient, "request",
                                  return_value=resp) as mock_request:

            neutronshell.run_command(cmd, cmd_parser, args)
            _str = self.fake_stdout.make_string()
            self.assertEqual(_str, '')

            mock_request.asswert_called_once_with(
                MyUrlComparator(end_url(path), self.client),
                'PUT',
                body=mock_body,
                headers=ContainsKeyValue({'X-Auth-Token': TOKEN}))
