neutron-ml2-hyperv
==================

This is the downstream Hyper-V Neutron Agent.


How to Install
--------------

Run the following command to install the agent in the system:

::

    C:\neutron-ml2-hyperv> python setup.py install

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

    C:\neutron-ml2-hyperv> pip install -r test-requirements.txt

You can run the unit tests with the following command.

::

    C:\neutron-ml2-hyperv> nosetests cloudbase\tests


HACKING
-------

To contribute to this repo, please go through the following steps.

1. Keep your working tree updated
2. Make modifications on your working tree
3. Run tests
4. If the tests pass, create a pull request on our github repo.
5. Wait for the pull request to be reviewed.
