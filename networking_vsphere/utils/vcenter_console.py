from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from networking_vsphere.utils.vim_objects import VcenterProxy


class VcenterConsole( VcenterProxy):
    """ Class is meant to provide an object which can be loaded
    from withint a python repl. The object can the be used to interact
    with a vcenter service.

    Example: (from within ipython)

    In[142]: import networking_vsphere.utils.vim_objects as vo
    Out[142]: <module 'networking_vsphere.utils.vim_objects'
                       from 'networking_vsphere/utils/vim_objects.py'>

    In[143]: vc = vc = vo.VcenterConsole('some_name',
                        vcenter_ip='192.168.0.1',
                        vcenter_user='VcenterUserNmae',
                        vcenter_password='VcenterPassword')


    In [144]: vc.connect
    Out[144]: 'SUCCESS'

    In [94]: vc.get_used_pnics_in_host('192.168.200.80')
    Out[94]: [key-vim.host.PhysicalNic-vmnic0,
              key-vim.host.PhysicalNic-vmnic1]

    """

    def __init__(self, *args, **kwargs):
        super(VcenterConsole, self).__init__(*args, **kwargs)
        disable_warnings(InsecureRequestWarning)
        self._connected = False

    @property
    def user_name(self):
        return self.vcenter_user

    @user_name.setter
    def user_name(self, name):
        self.vcenter_user = name

    @property
    def password(self):
        return "*******"

    @password.setter
    def password(self, pswd):
        self.vcenter_password = pswd

    @property
    def connection_ip(self):
        return self.vcenter_ip

    @connection_ip.setter
    def connection_ip(self, ip):
        self.vcenter_ip = ip

    @property
    def connection_port(self):
        return self.vcenter_port

    @connection_port.setter
    def connection_port(self, port):
        self.vcenter_port = port

    @property
    def credentials(self):
        return {
            'user_name': self.user_name,
            'password': self.password,
            'ip address': self.vcenter_ip,
            'tcp port': self.vcenter_port,

        }

    @property
    def connected(self):
        return self._connected

    @property
    def connect(self):
        self.connect_to_vcenter()
        self._connected = True
        return "SUCCESS"
