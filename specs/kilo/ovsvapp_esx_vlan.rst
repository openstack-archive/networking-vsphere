..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

================================
OVSvApp Solution : ESX with VLAN
================================

When a cloud operator wants to use OpenStack with vSphere using open source
elements, he/she can only do so by relying on nova-network. Currently there
is no integration between Nova and Neutron that would allow the operator to
deploy ESXi compute hypervisors so that he/she can start using some of the
Neutron capabilities in a similar deployment fashion. This blueprint is
about providing cloud operators with a Neutron supported solution for
vSphere deployments in the form of a service VM called OVSvApp VM
which steers the ESX tenant VMs' traffic through it.

The value-add with this solution is faster deployment of solutions on ESX
environments together with minimum effort required for adding new Openstack
features like DVR, LBaaS, VPNaaS etc.

Include the URL of your launchpad blueprint:

https://blueprints.launchpad.net/neutron/+spec/ovsvapp-solution-for-esx-
deployments

Problem Description
===================

Currently, there is no viable open source reference implementation for
supporting vSphere deployments that would help the cloud operator to leverage
some of the advanced networking capabilities that Neutron provides.


Proposed Change
===============

To address the above challenge, the proposed solution allows the customers
to host VMs on ESX hypervisors together with the flexibility of creating
portgroups dynamically on Distributed Virtual Switch/Virtual Standard Switch,
and then steer its traffic through the OVSvApp VM which provides VLAN and
Security Group features based on Openstack.

The Neutron Server side implementation for VLAN provisioning, Security Groups
is used as is and will have very minimal changes to process the ESX VM
networking information.

Data Model Impact
-----------------

None

REST API Impact
---------------

None

Security Impact
---------------

None

Notifications Impact
--------------------

None

Other End User Impact
---------------------

None

Performance Impact
------------------

Existence of a Trunk Portgroup for all tenant data traffic to pass
through OVSvApp VM may hit performance.

IPv6 Impact
-----------

None

Other Deployer Impact
---------------------

None

Developer Impact
----------------

None

Community Impact
----------------

None

Alternatives
------------

Use nova-network without Neutron features.


Implementation
==============

OVSvApp VM is a VM with Open vSwitch installed and it runs an OVSvApp agent,
which would wait for cluster events like "VM_CREATE", "VM_DELETE" and
"VM_UPDATE" from vCenter and process accordingly by fetching the Open vSwitch
FLOWs information from the Neutron Server and program the Open vSwitch.

OVSvApp agent manages at least 3 OVS Bridges namely Security Group Bridge
(br-sec),Integration Bridge(br-int) and Physical Bridges (br-ethX) to connect
to the network interfaces.

The VM traffic initially reaches the Security Group Bridge which will have
FLOWs based on the customer's Openstack Security Groups rules which will
either allow/block the traffic from the tenant VMs. Open vSwitch based
Firewall Driver is added to accomplish Security Groups functionality,
similar to iptable Firewall Driver.

The Integration Bridge connects Security Group Bridge and Physical Bridge.
The reason to have Integration Bridge is to leverage existing Openstack Open
vSwitch L2 agent feature to a maximum. The Physical Bridge functionality
is similar to the one existing in Openstack.

Dependencies
============

Open vSwitch, oslo.vmware, Nova(vmware.VCDriver)
