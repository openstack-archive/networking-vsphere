======================
 Enabling in Devstack
======================

1. Download DevStack

2. Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     enable_plugin networking-vsphere https://github.com/stackforge/networking-vsphere
     enable_service vsphere-server vsphere-compute vsphere-agent


3. run ``stack.sh``
