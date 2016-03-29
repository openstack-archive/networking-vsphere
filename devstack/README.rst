======================
 Enabling in Devstack
======================

1. Download DevStack

2. Add this repo as an external repository for OVSvApp Solution::

     > cat local.conf
     [[local|localrc]]
     enable_plugin networking-vsphere http://git.openstack.org/openstack/networking-vsphere


3. Add the following required flag in local.conf to enable the OVSvApp ML2 MechanismDriver::

     Q_ML2_PLUGIN_MECHANISM_DRIVERS=ovsvapp


4. Add the following required flags in local.conf to enable the OVSvApp Agent::

     # Provide IP address for vCenter.
     OVSVAPP_VCENTER_IP=$vCenter_ip_address

     # Provide vCenter Credentials.
     OVSVAPP_VCENTER_USERNAME=$vCenter_user_name
     OVSVAPP_VCENTER_PASSWORD=$vCenter_password

     # Provide ESX host name or IP address where OVSvApp VM is hosted.
     OVSVAPP_ESX_HOSTNAME=$esx_hostname

     # Provide Cluster to DVS/vDS mapping.
     OVSVAPP_CLUSTER_DVS_MAPPING=
     # For Example:
     # OVSVAPP_CLUSTER_DVS_MAPPING=DatacenterName/host/ClusterName:vDSName

     # Provide the tenant network type (VLAN, VXLAN or BOTH).
     OVSVAPP_TENANT_NETWORK_TYPES=

     # Provide the IP for VXLAN tunnel endpoint.
     OVSVAPP_LOCAL_IP=

     # Provide Physical Bridge name.
     OVSVAPP_PHYSICAL_BRIDGE=
     # For Example:
     # OVSVAPP_PHYSICAL_BRIDGE=br-ethx

     # Provide Physical Interface to add port to Physical Bridge.
     OVSVAPP_PHYSICAL_INTERFACE=
     # For Example:
     # OVSVAPP_PHYSICAL_INTERFACE=ethx

     # Provide Physical Bridge Mappings.
     OVSVAPP_BRIDGE_MAPPINGS=
     # For Example:
     # OVSVAPP_BRIDGE_MAPPINGS=physnet1:ethx

     # Provide Trunk Interface.
     OVSVAPP_TRUNK_INTERFACE=
     # For Example:
     # OVSVAPP_TRUNK_INTERFACE=ethy

     # Provide Security Bridge Mapping.
     OVSVAPP_SECURITY_BRIDGE_MAPPINGS=
     # For Example:
     # OVSVAPP_SECURITY_BRIDGE_MAPPING=br-sec:ethy

     Kindly, refer the ovsvapp_agent.ini for other default config parameters.

     # We have to disable the Neutron L2 agent. OVSvApp solution does not use the
     # Neutron L2 agent, instead uses a OVSvApp Agent to program OVS on each
     # ESX host.
     disable_service q-agt

     # Provide to enable Fault Tolerance for OVSvApp.
     ENABLE_OVSVAPP_MONITOR=
     # Set this flag in ml2_conf.ini on neutron-server
     # For Example:
     # [OVSVAPP]
     # enable_ovsvapp_monitor=True

5.  Add the following required flags in local.conf to enable the OVSvApp Compute VCDriver::

     VIRT_DRIVER=vsphere
     VMWAREAPI_IP=$vCenter_ip_address
     VMWAREAPI_USER=$vCenter_user_name
     VMWAREAPI_PASSWORD=$vCenter_password
     VMWAREAPI_CLUSTER=$cluster_name

     kindly, refer the following link:- https://wiki.openstack.org/wiki/NovaVMware/DeveloperGuide


6. Read the settings file for more details.

7. run ``stack.sh``
