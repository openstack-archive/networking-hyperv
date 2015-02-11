=================
networking-hyperv
=================

This project tracks the work to integrate the Hyper-V networking with Neutron. This project contains the Hyper-V Neutron Agent Mixin, Security Groups Driver, ML2 Mechanism Driver and the utils modules they use in order to properly bind neutron ports on a Hyper-V host.

This project resulted from the neutron core vendor decomposition.

Supports Python 2.7 and Python 3.3.

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/networking-hyperv
* Source: http://git.openstack.org/cgit/stackforge/networking-hyperv
* Bugs: http://bugs.launchpad.net/networking-hyperv


How to Install
--------------

Run the following command to install the agent in the system:

::

    C:\networking-hyperv> python setup.py install

To properly use the agent, you will have to set the core_plugin in
``neutron.conf`` to:

::

    core_plugin = neutron.plugins.ml2.plugin.Ml2Plugin

Additionally, you will have to add Hyper-V as a mechanism in ``ml2_conf.ini``:

::

    mechanism_drivers = openvswitch,hyperv

Finally, make sure the tenant_network_types field contains network types
supported by Hyper-V: local, flat, vlan.


Tests
-----

You will have to install the test dependencies first to be able to run the
tests.

::

    C:\networking-hyperv> pip install -r test-requirements.txt

You can run the unit tests with the following command.

::

    C:\networking-hyperv> nosetests hyperv\tests


HACKING
-------

To contribute to this repo, please go through the following steps.

1. Keep your working tree updated
2. Make modifications on your working tree
3. Run tests
4. If the tests pass, create a pull request on our github repo.
5. Wait for the pull request to be reviewed.


Features
--------

* TODO
