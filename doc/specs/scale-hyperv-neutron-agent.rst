..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

===========================
Scale Hyper-V Neutron Agent
===========================

https://blueprints.launchpad.net/networking-hyperv/+spec/scale-hyperv-neutron-agent

A typical medium-sized hybrid cloud deployment consists of more than
50 Hyper-V compute nodes along with computes like KVM or ESX.
The rate at which VMs are spawned/updated under such a deployment is
around 25 operations/minute. And these operations consists of spawning,
updating and deleting of the VMs and their properties (like security group
rules). At this rate the possibility of concurrent spawn or update operations
on a given compute is High. What is typically observed is a spawn rate of
~2 VM(s)/minute. Since WMI is not that performant, a VM port binding in
Hyper-V neutron agent takes 10x amount of time when compared to KVM IPtables.
The situation worsens when the number of SG Rules to apply increases for a
given port (with the number of SG members), and there are many ports in queue
to treat. Under such a scenario neutron agent running on Hyper-v compute fails
to complete binding security rules to the VM port in given time, and VM remains
inaccessible on the allocated IP address.
This blueprint addresses the Neutron Hyper-V Agent's port binding rate by
introducing port binding concurrency.

Problem Description
===================

Under enterprise class cloud environment the possibility of single compute
receiving more than one VM spawn request grows. It is the nova scheduler that
chooses the compute node on which the VM will be spawned. The neutron part
on compute node runs as an independent task which does the port related
configuration for the spawned VM. Today, neutron agent runs in a single
threaded environment, the main thread is responsible for doing the port
binding (i.e. vlan configuration and applying port rules) for the spawned VM
and sending agent keep alive message to controller, while green threads are
responsible for processing the port updates (i.e. updating port acls/rules).

The threading mechanism is implemented using python's green thread library,
the green thread by nature operated in run until completion or preemption
mode, which means that a green thread will not yield the CPU until it
completes its job or it is preempted explicitly.

The above mentioned nature of green thread impacts the Hyper-V scale.
The problem starts when a compute already has around 15 VMs hosted and
security group update is in process, at the same time neutron agent's
deamon loop wakes up and finds that there were ports added for which binding
is pending. Because the update thread is holding the CPU, the port binding
main thread will not get turn to execute resulting in delayed port binding.
Since the nova-compute service runs in isolation independent of neutron, it
will not wait for neutron to complete port binding and will power on the VM.
The booted VM will start sending the DHCP discovery which ultimately gets
dropped resulting in VM not getting DHCP IP.

The problem becomes worse with growing number of VMs because more VMs in
network mean more time to complete port update, and the list of added ports
pending for port binding also grows due to arrival of new VMs.

Proposed Change
===============

This blueprint proposes solution to the above discussed problem in two parts.

**Part 1.** The Hyper-V Neutron Agent and the nova-compute service can be
syncronized, which can help solve the first part of the problem: the VMs are
currently starting before the neutron ports are properly bound. By waiting for
the ports to be processed, the VMs will be able to properly acquire the DHCP
replies.

Currently, Neutron generates a `vif plugged` notification when a port has been
reported as `up` (``update_device_up``), which is already done by the Neutron
Hyper-V Agent when it finished processing a port. The implementation for
waiting for the mentioned notification event in the nova Hyper-V Driver will
be addressed by the blueprint [1].

**Part 2.** The second part of the proposal is to improve the logic behind
the Neutron Hyper-V Agent's port processing. In this regard, there are a couple
of things that can be done.

**a.** Replace WMI. Performance-wise, WMI is notoriously bad. In order to
address this, the PyMI module has been created and it will be used instead [2].
PyMI is a drop-in replacement of WMI, as it maintains the same interface, via
its WMI wrapper, meaning that PyMI can be used on any previous, current and
future branches of networking-hyperv. It has been observed that PyMI
reduces the execution time by roughly 2.0-2.2X, compared to the old WMI.

**b.** Implement vNIC creation / deletion event listeners. Currently, the
agent periodically polls for all the present vNICs on the host (which can be
an expensive operation when there are hundreds of vNICs) and then query the
Neutron server for port details for all of them. This is repeated if the
port binding failed even for one of them.

By implementing the vNIC creation / deletion event listeners, querying all the
vNICs is no longer necessary. Furthermore, the Neutron server will not have to
be queried for all of the vNICs when a single one of them failed to be bound,
reducing the load on the Neutron server.

**c.** Parallel port binding. Currently, the ports are being processed
sequencially. Processing them in parallel can lead to a performance boost.
Plus, PyMI was built while having parallelism in mind, as oposed to the old
WMI, meaning that the performance gain by using both PyMI and parallel port
binding will be even greater.

We will be using Native Threads for the purpose of port binding, as they can
span multiple processors (green threads do not). On a host with 32 cores,
using 10 Native Threads as workers + PyMI has a ~6X better performance than
the previous, single-threaded processing using PyMI, leading to a total ~12X
improvement over the single-threaded processing using WMI.

It is notable to mention that there a very small performance gain between
10 Native Thread workers and 20 (~5%). As a recommendation the best
experience, the number of workers should be set between 10 and 15, or the
number of cores on the host, whichever is lowest.

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

This blueprint will improve the Hyper-V neutron agent performance.

IPv6 Impact
-----------

None

Other Deployer Impact
---------------------

The number of Native Thread workers can be set in the ``worker_count``
configuration option in ``neutron-hyperv-agent.conf``. As default, it is set
to 10.

Developer Impact
----------------

None

Community Impact
----------------

Scaling Openstack neutron is always a challenge and this change will allow
Hyper-V neutron to scale around 1000 VM with 10 tenants.

Alternatives
------------

None

Implementation
==============

Assignee(s)
-----------

Primary assignee:
  <cbelu@cloudbasesolutions.com>

Other contributors:
  <sonu.sudhakaran@hp.com>
  <vinod.kumar5@hp.com>
  <krishna.kanth-mallela@hp.com >

Work Items
----------

* Implementing vNIC creation / deletion event listeners.
* Implementing Native Thread workers.
* Writing unit test.
* Functionality testing.
* Scale testing.


Dependencies
============

* Nova to process neutron vif notification.

Testing
=======

The changes will be tested by deploying cloud with around 20 computes nodes
and spawning 1000 VMs at concurrency of 6 VMs per minute for overall cloud
with 10 tenants each having their own network.

Tempest Tests
-------------

TBD

Functional Tests
----------------

TBD

API Tests
---------

None

Documentation Impact
====================

None

User Documentation
------------------

Nova boot time may increase due to Neutron to Nova notification, the delay
could be seen when there are large number of security groups rules associated
with a port.

Developer Documentation
-----------------------

None

References
==========

[1] Hyper-V Spawn on Neutron Event nova blueprint:
  https://blueprints.launchpad.net/nova/+spec/hyper-v-spawn-on-neutron-event

[2] PyMI github repository:
  https://github.com/cloudbase/PyMI/
