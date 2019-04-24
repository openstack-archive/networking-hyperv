========================
Team and repository tags
========================

.. image:: https://governance.openstack.org/tc/badges/networking-hyperv.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

.. Change things from this point on

=================
networking-hyperv
=================

This project tracks the work to integrate the Hyper-V networking with Neutron.
This project contains the Hyper-V Neutron Agent, Security Groups Driver, and
ML2 Mechanism Driver, which are used to properly bind neutron ports on a
Hyper-V host.

This project resulted from the neutron core vendor decomposition.

Supports Python 2.7, Python 3.3, Python 3.4, and Python 3.5.

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/networking-hyperv
* Source: https://opendev.org/openstack/networking-hyperv
* Bugs: https://bugs.launchpad.net/networking-hyperv
* Release notes: https://docs.openstack.org/releasenotes/networking-hyperv/index.html

How to Install
--------------

Run the following command to install the agent on the system:

::

    C:\networking-hyperv> python setup.py install

To use the ``neutron-hyperv-agent``, the Neutron Controller will have to be
properly configured. For this, the config option ``core_plugin`` in the
``/etc/neutron/neutron.conf`` file must be set as follows:

::

    core_plugin = neutron.plugins.ml2.plugin.Ml2Plugin

Additionally, ``hyperv`` will have to be added as a mechanism driver in the
``/etc/neutron/plugins/ml2/ml2_conf.ini`` configuration file:

::

    mechanism_drivers = openvswitch,hyperv

In order for these changes to take effect, the ``neutron-server`` service will
have to be restarted.

Finally, make sure the ``tenant_network_types`` field contains network types
supported by Hyper-V: local, flat, vlan, gre.


Tests
-----

You will have to install the test dependencies first to be able to run the
tests.

::

    C:\networking-hyperv> pip install -r requirements.txt
    C:\networking-hyperv> pip install -r test-requirements.txt

You can run the unit tests with the following command.

::

    C:\networking-hyperv> nosetests networking_hyperv\tests


How to contribute
-----------------

To contribute to this project, please go through the following steps.

1. Clone the project and keep your working tree updated.
2. Make modifications on your working tree.
3. Run unit tests.
4. If the tests pass, commit your code.
5. Submit your code via ``git review -v``.
6. Check that Jenkins and the Microsoft Hyper-V CI pass on your patch.
7. If there are issues with your commit, amend, and submit it again via
   ``git review -v``.
8. Wait for the patch to be reviewed.


Features
--------

* Supports Flat, VLAN, GRE / NVGRE network types.
* Supports Neutron Security Groups.
* Contains ML2 Mechanism Driver.
* Parallel port processing.
