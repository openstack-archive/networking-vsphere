======================
 Enabling in Devstack
======================

1. Download DevStack

2. Add this repo as an external repository for OVSvApp Solution::

     > cat local.conf
     [[local|localrc]]
     enable_plugin networking-vsphere http://git.openstack.org/stackforge/networking-vsphere


3. Add the following required flags in local.conf to enable the OVSvApp L2 Agent::

     Provide IP address for vCenter.
     OVSVAPP_VCENTER_IP=$vCenter_ip_address

     Provide vCenter Credentials.
     OVSVAPP_VCENTER_USERNAME=$vCenter_user_name
     OVSVAPP_VCENTER_PASSWORD=$vCenter_password

     Provide ESX host name or IP address where OVSvApp VM is hosted.
     OVSVAPP_ESX_HOSTNAME=$esx_hostname

     Provide Cluster to DVS/vDS mapping.
     OVSVAPP_CLUSTER_DVS_MAPPING=
     For Example:
     OVSVAPP_CLUSTER_DVS_MAPPING=DatacenterName/host/ClusterName:vDSName

     Provide Physical Bridge name.
     OVSVAPP_PHYSICAL_BRIDGE=
     For Example:
     OVSVAPP_PHYSICAL_BRIDGE=br-ethx

     Provide Physical Interface to add port to Physical Bridge.
     OVSVAPP_PHYSICAL_INTERFACE=
     For Example:
     OVSVAPP_PHYSICAL_INTERFACE=ethx

     Provide Physical Bridge Mappings.
     OVSVAPP_BRIDGE_MAPPINGS=
     For Example:
     OVSVAPP_BRIDGE_MAPPINGS=physnet1:ethx

     Provide Trunk Interface.
     OVSVAPP_TRUNK_INTERFACE=
     For Example:
     OVSVAPP_TRUNK_INTERFACE=ethy

     Provide Security Bridge Mapping.
     OVSVAPP_SECURITY_BRIDGE_MAPPINGS=
     For Example:
     OVSVAPP_SECURITY_BRIDGE_MAPPING=br-sec:ethy

     Kindly, refer the ovsvapp_agent.ini for other default config parameters.


4.  Add the following required flags in local.conf to enable the OVSvApp Compute VCDriver::

     VIRT_DRIVER=vsphere
     VMWAREAPI_IP=$vCenter_ip_address
     VMWAREAPI_USER=$vCenter_user_name
     VMWAREAPI_PASSWORD=$vCenter_password
     VMWAREAPI_CLUSTER=$cluster_name

     kindly, refer the following link:- https://wiki.openstack.org/wiki/NovaVMware/DeveloperGuide


4. Read the settings file for more details.

6. run ``stack.sh``