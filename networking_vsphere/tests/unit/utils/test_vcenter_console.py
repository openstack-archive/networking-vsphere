
from mock import patch, MagicMock
from unittest import TestCase

from networking_vsphere.utils.vcenter_console import VcenterConsole


class TestBase(TestCase):
    def setUp(self):
        self.connection_patcher = patch(
            'networking_vsphere.utils.vim_objects.api.VMwareAPISession')
        self.mocked_session = self.connection_patcher.start()
        session_instance = MagicMock()
        session_instance.invoke_api.return_value = [MagicMock(), MagicMock()]
        self.mocked_session.return_value = session_instance

    def tearDown(self):
        self.connection_patcher.stop()
        # self.mocked_get_type.stop()


class TestVcenterConsole(TestBase):

    def setUp(self):
        super(TestVcenterConsole, self).setUp()
        self.sut = VcenterConsole(name='test_dvs',
                                  vcenter_user='username',
                                  vcenter_ip='127.0.0.1',
                                  vcenter_port=443,
                                  vcenter_password='test'
                                  )

    def test_user_name_getter(self):
        self.assertEquals(self.sut.user_name, self.sut.vcenter_user)

    def test_user_name_setter(self):
        self.sut.user_name = "newuser"
        self.assertEquals(self.sut.vcenter_user, "newuser")

    def test_password_getter(self):
        self.assertNotEquals(self.sut.password, self.sut.vcenter_password)

    def test_password_setter(self):
        self.sut.password = "new password"
        self.assertEquals(self.sut.vcenter_password, "new password")

    def test_connection_ip_getter(self):
        self.assertEquals(self.sut.connection_ip, self.sut.vcenter_ip)

    def test_connection_ip_setter(self):
        self.sut.connection_ip = "new ip"
        self.assertEquals(self.sut.vcenter_ip, "new ip")

    def test_connection_port_getter(self):
        self.assertEquals(self.sut.connection_port, self.sut.vcenter_port)

    def test_connection_port_setter(self):
        self.sut.connection_port = "new port"
        self.assertEquals(self.sut.vcenter_port, "new port")

    def test_credentials(self):
        self.assertIn('username', self.sut.credentials.values())

    def test_connected(self):
        self.assertFalse(self.sut.connected)

