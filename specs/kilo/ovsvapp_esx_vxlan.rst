..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==========================================
OVSvApp Solution : ESX + VXLAN
==========================================

The idea of this proposal is to provide a decentralized management model for
ESX-VXLAN deployments based on Openstack's KVM VXLAN solution using a virtual
machine (OVSvApp) for ESXi Networks. The solution provides 2^24 networks using
VMware VLAN primitive APIs, which can only provide 4096 networks.

Include the URL of your launchpad blueprint:
https://blueprints.launchpad.net/neutron/+spec/ovsvapp-esxi-vxlan

Architecture - OVSvApp Internals & Data Flow:

asciiflow::

                   +-------------+
       +-----------+  neutron    +-----------------------------------+
       |           |  server     |                                   |
       |           +---+---------+                                   |
       |               |                                             |
     +-+--------+      |                      +----------+           |
     |  nova    |------+--------------------->|vCenter   |-------+   |
     |compute   |      |   +------------------+          |       |   |
     +----------+      |   |                  +----------+       |   |
                    +----------------+                   +------+v---v----+
   +-------+  +-----> OVSvAPP VM-1   |  +-------+  +-----> OVSvAPP VM-2   |
   |   vm-1|  |     | (l2 agent)     |  |  vm-2 |  |     | (l2 agent )    |
   +---+---+  |     +------+---------v  +---+---+  |     +------+---------v
   +---|------|------------|-----+      +---|------|------------|-----+
   |   |      |            |     |      |   |      |            |     |
   | +-v------+------+     |     |      | +-v------+------+     |     |
   | |               |     |     |      | |               |     |     |
   | | DVS-1         |     |     |      | | DVS-1         |     |     |
   | +---------------+     |     |      + +---------------+     |     |
   |                       |     |      |                       |     |
   |                       |     |      |                       |     |
   |         +-------------v--+  |      |         +-------------v--+  |
   |         |                |                   |                |  |
   |         |    DVS-2       |  |      |         |    DVS-2       |  |
   v         +-----+----------+  |      |         ++---------------+  |
   |               |             |      |          |                  |
   |  ESX-1 hypervi|or           |      |  ESX-2 hy|ervisor           |
   +-------+-------|-------------+      +----------|------------------+
                   |                               |
            uplink -esx-1                    uplink-esx-2
                   |                               |
                   +---------data network----------+



        +-----------------+                   +-----------------+
        |   Compute Node  |                   |   Compute Node  |
        |                 |                   |                 |
        +-----------------+                   +-----------------+

    +--------+       +--------+           +--------+       +--------+
    |   VM1  |   +--+|    VM2 |           |   VM1  |       |    VM2 |
    +------+-+   |   +----+---+           +-------++       +----+---+
           |     |                                |             |
     <-----+-----+------------->           +------|-------------|----+
     |   +-v-----v-++---------+|           |   +--v------++-----v---+|
     |   |   PG-1  ||   PG-2  ||  +        |   |   PG-1  ||   PG-10 ||
     |   |         ||         ||           |   |         ||         ||
     |   +---------++---------+|           |   +---------++---------+|
     |                         |           |                         |
     +--------------+----------+           +--------------+----------+
                    |                                     |
    +-----+------v--v----------------+    +-----+---------v----------------+
    |     |      +------------+      |    |     |      +------------+      |
    |     |      |    BR-INT  |      |    |     |      |    BR-INT  |      |
    |  V  |      |            |      |    |  V  |      |            |      |
    |     |      +------+-----+      |    |     |      +------+-----+      |
    |  M  |             |            |    |  M  |             |            |
    |     |      +------v-----+      |    |     |      +------v-----+      |
    |     |      |    BR-TUN  |      |    |     |      |    BR-TUN  |      |
    |     |      |            |      |    |     |      |            |      |
    |     |      +------+-----+      |    |     |      +------+-----+      |
    |     |             |            |    |     |             |            |
    +-----+-------------+------------+    +-----+-------------+------------+
                        |                                     |
                        |                                     |
                        +--------data network-----------------+


Problem Description
===================

The idea of this proposal is to discuss the design options for the OVSvApp
solution for supporting VXLAN on ESXi networks based on Openstack.

Proposed Change
===============

To address the above challenge, the proposed solution allows the customers
to host VMs on ESX hypervisors together with the flexibility of creating
portgroups dynamically on Distributed Virtual Switch/Virtual Standard Switch,
and then steer its traffic through the OVSvApp VM which provides VXLAN
tunnelling based on Openstack.

The solution uses/modifies Openstack's Neutron Server and OVS agent to provide
VXLAN connectivity. Existing Neutron Server will be used as is to provide
tenants, networks, subnets, ports, tunnel information to OVS agent.

OVS agent will be enhanced to process VM Creation/VM deletion event from
VCenter Manager (Vmware Manager to provision the Hosts on the ESXi Hypervsior).
It maps VLAN created by Vmware primitive APIs to VXLAN VNI provided by the
Neutron Server. The VLANs will be local to the Hypervisor and will be mapped to
a Global VXLAN VNI (let’s assume: 5000). On Hypervisor (HV) 1, this will map to
a Local VLAN of 1, but on HV 2, this same VNI will map to VLAN 5. This in-memory
mapping helps the solution to provide high scalability numbers theoretically:
2^24.

This solution deployment comprises of two ESXi Distributed Virtual Switch (DVS),
software switches by VMware and OVSvApp VM.
Tenant VMs are booted on 1st DVS and will not have any 'uplinks'
(external network connectivity) but will provide connectivity to VMs and
OVSvApp.2nd DVS consists of uplinks to provide data connectivity to OVSvApp
and management connectivity to the Neutron Server.

Use Cases:

Intra-VXLAN on same Hypervisor:
L2 learning capabilities of DVS are used for intra-VXLAN traffic on the same
hypervisor.

Intra-VXLAN across Hypervisors:
VM traffic flows through the Logical Port on Integration Bridge and reaches
Tunnel Bridge. Tunnel Bridge strips VLAN tags (hypervisor local significance)
and adds VXLAN header (Global VNI) and forwards the traffic on the wire.

Inter-VXLAN traffic (same/across Hypervisors):
VM Traffic flows through the Network Node (NN) which then forwards to VXLAN
tunnel.


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

NSX-vSphere Neutron plugin
https://review.openstack.org/#/c/102720/

Dependencies
============

Open vSwitch, oslo.vmware, Nova(vmware.VCDriver)
