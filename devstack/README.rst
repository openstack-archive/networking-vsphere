======================
 Enabling in Devstack
======================

1. Download DevStack

2. Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     enable_plugin networking-vsphere http://git.openstack.org/stackforge/networking-vsphere
     enable_service ovsvapp-server ovsvapp-compute ovsvapp-agent


3. run ``stack.sh``
