..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

========================================
Hyper-V Neutron Agent NVGRE network type
========================================

https://blueprints.launchpad.net/networking-hyperv/+spec/hyper-v-nvgre

Hyper-V Network Virtualization (HNV) was first introduced in Windows Hyper-V /
Server 2012 and has the purpose of enabling the virtualization of Layer 2 and
Layer 3 networking models. One of the HNV configuration approches is called
NVGRE (Network Virtualization through GRE). [1]

Problem Description
===================

NVGRE can be used between Windows Hyper-V / Server 2012 and Windows Hyper-V /
Server 2012 R2 VMs, but the usage can be extended to other hypervisors which
support GRE by using OpenVSwitch.

Proposed Change
===============

In order to implement this feature, there are a few considerations things that
need to be kept in mind:

* NVGRE does not exist prior to Windows / Hyper-V Server 2012. The
  implementation will have to make sure it won't break the Hyper-V Neutron
  Agent on a Windows / Hyper-V 2008 R2 compute node.

* HNV is not enabled by default in Windows / Hyper-V Server 2012.

* The vSwitch used for the NVGRE tunneling must have the Alow Management OS
  flag turned off.

* Additional information is needed from Neutron in order to for the feature
  to behave as expected. In order to retrieve the information, Neutron
  credentials are necessary.

* The network's segmentation_id, or the NVGRE's equivalent, VirtualSubnetId has
  to be higher than 4095. Hyper-V cannot create Customer Routes or
  Lookup Records if the SegmentationId is lower or equal to 4095.

* The NVGRE network cannot have a gateway ending in '.1', as Hyper-V does not
  allow it. Any other gateway (including networks without a gateway) is
  acceptable.

* Only one subnet per network. The reason is that it cannot be created more
  Customer Routes for the same VirtualSubnetID. Adding new routes for the same
  VirtualSubnetId will cause exceptions.

* Lookup Records should be added for the metadata address (default is
  169.254.169.254) in order for instances to properly fetch their metadata.

* Lookup Records should be added for 0.0.0.0. One reason why they're necessary
  is that they are required in order to receive DHCP offers.

* ProviderAddress, ProviderRoute, CustomerRoute and LookupRecord WMI objects
  are not persistent. Which means they will not exist after the host restarts.

Configuration
-------------

A few configuration options can be set in order for the feature to function
properly. These configuration options are to be set in the [NVGRE] section
of the .conf file:

* enable_support (default=False). Enables Hyper-V NVGRE as a network type for
  the agent.

* provider_vlan_id (default=0). The VLAN ID set to the physical network.

* provider_tunnel_ip. Specifies the local IP which will be used for NVGRE
  tunneling.

Work Items
----------

* NVGRE Utils classes, which uses the ``//./root/StandardCimv2`` WMI namespace.
  It will be responsible with creating the WMI objects required for the
  feature to function properly: ProviderAddress, ProviderRoute, CustomerRoute,
  Lookup Record objects; while considering the limitations described above.

* Create local database in order to persist the above objects and load them
  when the agent starts. The database should be kept clean.

* Create method to synchronize LookupRecords with other Hyper-V Neutron Agents
  that have NVGRE enabled, as they must exist on both ends of the NVGRE tunnel.

* Class that retrieves necessary information from Neutron in order to correctly
  create the mentioned WMI objects.

* The Hyper-V Neutron Agent should report the following agent configuration, if
  NVGRE is supported and enabled:
  - ``tunneling_ip``: the host's IP which is used as a ProviderAddress.
  - ``tunnel_types``: NVGRE

* HypervMechanismDriver.get_allowed_network_types method should check the
  agent's reported ``tunnel_types`` and include it in the return value.

* Implement NVGRE network type in Neutron.

References
==========

[1] https://technet.microsoft.com/en-us/library/JJ134174.aspx
