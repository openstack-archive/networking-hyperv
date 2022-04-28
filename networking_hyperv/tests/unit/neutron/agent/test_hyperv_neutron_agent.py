# Copyright 2013 Cloudbase Solutions SRL
# Copyright 2013 Pedro Navarro Perez
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Unit tests for Windows Hyper-V virtual switch neutron driver
"""

import sys
from unittest import mock

import ddt
from neutron.agent import rpc as agent_rpc
from neutron_lib.agent import topics
from neutron_lib import rpc as n_rpc
from os_win import exceptions

from networking_hyperv.neutron.agent import hyperv_neutron_agent as \
    hyperv_agent
from networking_hyperv.neutron.agent import layer2
from networking_hyperv.neutron import constants
from networking_hyperv.neutron import exception
from networking_hyperv.tests import base


class TestHyperVSecurityAgent(base.BaseTestCase):
    @mock.patch.object(hyperv_agent.HyperVSecurityAgent, '__init__',
                       lambda *args, **kwargs: None)
    def setUp(self):
        super(TestHyperVSecurityAgent, self).setUp()
        self.agent = hyperv_agent.HyperVSecurityAgent()

    @mock.patch.object(hyperv_agent, 'HyperVSecurityCallbackMixin')
    @mock.patch.object(hyperv_agent.agent_rpc, 'create_consumers')
    def test_setup_rpc(self, mock_create_consumers, mock_HyperVSecurity):
        self.agent._setup_rpc()

        self.assertEqual(topics.AGENT, self.agent.topic)
        self.assertEqual([mock_HyperVSecurity.return_value],
                         self.agent.endpoints)
        self.assertEqual(mock_create_consumers.return_value,
                         self.agent.connection)
        mock_create_consumers.assert_called_once_with(
            self.agent.endpoints, self.agent.topic,
            [[topics.SECURITY_GROUP, topics.UPDATE]])


class TestHyperVNeutronAgent(base.HyperVBaseTestCase):

    _FAKE_PORT_ID = 'fake_port_id'

    @mock.patch.object(hyperv_agent.HyperVNeutronAgent, "_setup")
    @mock.patch.object(hyperv_agent.HyperVNeutronAgent, "_setup_rpc")
    @mock.patch.object(hyperv_agent.HyperVNeutronAgent, "_set_agent_state")
    def _get_agent(self, mock_set_agent_state, mock_setup_rpc, mock_setup):
        return hyperv_agent.HyperVNeutronAgent()

    def setUp(self):
        super(TestHyperVNeutronAgent, self).setUp()
        self.agent = self._get_agent()

        self.agent._nvgre_ops = mock.MagicMock(
            autospec=hyperv_agent.nvgre_ops.HyperVNvgreOps)

        self.agent._sec_groups_agent = mock.MagicMock(
            autospec=hyperv_agent.HyperVSecurityAgent)
        self.agent._vlan_driver = mock.MagicMock(
            autospec=hyperv_agent.trunk_driver.HyperVTrunkDriver)
        self.agent._qos_ext = mock.MagicMock(
            autospec=hyperv_agent.qos_extension.QosAgentExtension)

        self.agent._plugin_rpc = mock.MagicMock(autospec=agent_rpc.PluginApi)
        self.agent._client = mock.MagicMock(autospec=n_rpc.BackingOffClient)
        self.agent._connection = mock.MagicMock(autospec=n_rpc.Connection)
        self.agent._refresh_cache = False
        self.agent._added_ports = set()

    def test_get_agent_configurations(self):
        self.agent._physical_network_mappings = mock.sentinel.mappings
        fake_ip = '10.10.10.10'
        self.config(enable_support=True,
                    provider_tunnel_ip=fake_ip,
                    group="NVGRE")

        agent_configurations = self.agent._get_agent_configurations()

        expected_keys = ["vswitch_mappings", "arp_responder_enabled",
                         "tunneling_ip", "devices", "l2_population",
                         "tunnel_types", "enable_distributed_routing",
                         "bridge_mappings"]
        self.assertEqual(sorted(expected_keys),
                         sorted(agent_configurations.keys()))
        self.assertEqual(mock.sentinel.mappings,
                         agent_configurations["vswitch_mappings"])
        self.assertEqual(fake_ip,
                         agent_configurations["tunneling_ip"])

    @mock.patch("networking_hyperv.neutron.trunk_driver.HyperVTrunkDriver")
    @mock.patch("neutron.api.rpc.handlers.securitygroups_rpc."
                "SecurityGroupServerRpcApi")
    @mock.patch("networking_hyperv.neutron.agent.hyperv_neutron_agent"
                ".HyperVSecurityAgent")
    @mock.patch.object(layer2.Layer2Agent, "_setup")
    def test_setup(self, mock_setup, mock_security_agent, mock_sg_rpc,
                   mock_trunk_driver):
        self.agent._context = mock.sentinel.admin_context
        self.agent._consumers = []
        self.config(enable_support=True, group="NVGRE")

        self.agent._setup()

        expected_consumers = [[constants.TUNNEL, topics.UPDATE],
                              [constants.LOOKUP, constants.UPDATE]]
        mock_setup.assert_called_once_with()
        mock_sg_rpc.assert_called_once_with(topics.PLUGIN)
        mock_security_agent.assert_called_once_with(
            mock.sentinel.admin_context, mock_sg_rpc.return_value)
        mock_trunk_driver.assert_called_once_with(mock.sentinel.admin_context)
        self.assertEqual(expected_consumers, self.agent._consumers)

    @mock.patch("neutron.agent.l2.extensions.qos.QosAgentExtension")
    def test_setup_qos_extension(self, mock_qos_agent):
        self.config(enable_qos_extension=True, group="AGENT")
        mock_qos_agent_extension = mock.Mock()
        mock_qos_agent.return_value = mock_qos_agent_extension

        self.agent._setup_qos_extension()

        mock_qos_agent_extension.consume_api.assert_called_once_with(
            self.agent)
        mock_qos_agent_extension.initialize(self.agent._connection, "hyperv")

    @mock.patch.object(hyperv_agent.nvgre_ops, 'HyperVNvgreOps')
    def test_init_nvgre_disabled(self, mock_hyperv_nvgre_ops):
        self.agent._init_nvgre()
        self.assertFalse(mock_hyperv_nvgre_ops.called)
        self.assertFalse(self.agent._nvgre_enabled)

    @mock.patch.object(hyperv_agent.nvgre_ops, 'HyperVNvgreOps')
    def test_init_nvgre_no_tunnel_ip(self, mock_hyperv_nvgre_ops):
        self.config(enable_support=True, group='NVGRE')
        self.assertRaises(exception.NetworkingHyperVException,
                          self.agent._init_nvgre)

    @mock.patch.object(hyperv_agent.nvgre_ops, 'HyperVNvgreOps')
    def test_init_nvgre_enabled(self, mock_hyperv_nvgre_ops):
        self.config(enable_support=True, group='NVGRE')
        fake_ip = '10.10.10.10'
        self.config(provider_tunnel_ip=fake_ip,
                    group='NVGRE')
        self.agent._init_nvgre()
        mock_hyperv_nvgre_ops.assert_called_once_with(
            list(self.agent._physical_network_mappings.values()))

        self.assertTrue(self.agent._nvgre_enabled)
        self.agent._nvgre_ops.init_notifier.assert_called_once_with(
            self.agent._context, self.agent._client)

    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       "_get_vswitch_name")
    def test_provision_network_exception(self, mock_get_vswitch_name):
        self.assertRaises(exception.NetworkingHyperVException,
                          self.agent._provision_network,
                          mock.sentinel.FAKE_PORT_ID,
                          mock.sentinel.FAKE_NET_UUID,
                          mock.sentinel.FAKE_NETWORK_TYPE,
                          mock.sentinel.FAKE_PHYSICAL_NETWORK,
                          mock.sentinel.FAKE_SEGMENTATION_ID)
        mock_get_vswitch_name.assert_called_once_with(
            mock.sentinel.FAKE_NETWORK_TYPE,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       "_get_vswitch_name")
    def test_provision_network_vlan(self, mock_get_vswitch_name):
        self.agent._provision_network(mock.sentinel.FAKE_PORT_ID,
                                      mock.sentinel.FAKE_NET_UUID,
                                      constants.TYPE_VLAN,
                                      mock.sentinel.FAKE_PHYSICAL_NETWORK,
                                      mock.sentinel.FAKE_SEGMENTATION_ID)
        mock_get_vswitch_name.assert_called_once_with(
            constants.TYPE_VLAN,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       "_get_vswitch_name")
    def test_provision_network_nvgre(self, mock_get_vswitch_name):
        self.agent._nvgre_enabled = True
        vswitch_name = mock_get_vswitch_name.return_value
        self.agent._provision_network(mock.sentinel.FAKE_PORT_ID,
                                      mock.sentinel.FAKE_NET_UUID,
                                      constants.TYPE_NVGRE,
                                      mock.sentinel.FAKE_PHYSICAL_NETWORK,
                                      mock.sentinel.FAKE_SEGMENTATION_ID)

        mock_get_vswitch_name.assert_called_once_with(
            constants.TYPE_NVGRE,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)
        self.agent._nvgre_ops.bind_nvgre_network.assert_called_once_with(
            mock.sentinel.FAKE_SEGMENTATION_ID,
            mock.sentinel.FAKE_NET_UUID,
            vswitch_name)

    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       "_get_vswitch_name")
    def test_provision_network_flat(self, mock_get_vswitch_name):
        self.agent._provision_network(mock.sentinel.FAKE_PORT_ID,
                                      mock.sentinel.FAKE_NET_UUID,
                                      constants.TYPE_FLAT,
                                      mock.sentinel.FAKE_PHYSICAL_NETWORK,
                                      mock.sentinel.FAKE_SEGMENTATION_ID)
        mock_get_vswitch_name.assert_called_once_with(
            constants.TYPE_FLAT,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       "_get_vswitch_name")
    def test_provision_network_local(self, mock_get_vswitch_name):
        self.agent._provision_network(mock.sentinel.FAKE_PORT_ID,
                                      mock.sentinel.FAKE_NET_UUID,
                                      constants.TYPE_LOCAL,
                                      mock.sentinel.FAKE_PHYSICAL_NETWORK,
                                      mock.sentinel.FAKE_SEGMENTATION_ID)
        mock_get_vswitch_name.assert_called_once_with(
            constants.TYPE_LOCAL,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @ddt.data({'enable_security_groups': True},
              {'network_type': constants.TYPE_LOCAL},
              {'network_type': constants.TYPE_VLAN},
              {'network_type': constants.TYPE_NVGRE})
    @ddt.unpack
    @mock.patch.object(layer2.Layer2Agent, '_port_bound')
    def test_port_bound(self, mock_super_bound,
                        network_type=constants.TYPE_FLAT,
                        enable_security_groups=False):
        net_uuid = 'my-net-uuid'
        self.agent._enable_metrics_collection = True
        self.agent._enable_security_groups = enable_security_groups
        self.agent._network_vswitch_map[net_uuid] = mock.sentinel.vswitch_name

        self.agent._port_bound(mock.sentinel.port_id, net_uuid,
                               network_type,
                               mock.sentinel.physical_network,
                               mock.sentinel.segmentation_id,
                               mock.sentinel.port_security_enabled,
                               False)

        mock_super_bound.assert_called_once_with(
            mock.sentinel.port_id, net_uuid, network_type,
            mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, mock.sentinel.port_security_enabled,
            False)

        if network_type == constants.TYPE_VLAN:
            self.agent._vlan_driver.bind_vlan_port.assert_called_once_with(
                mock.sentinel.port_id, mock.sentinel.segmentation_id)
        elif network_type == constants.TYPE_NVGRE:
            self.agent._nvgre_ops.bind_nvgre_port.assert_called_once_with(
                mock.sentinel.segmentation_id, mock.sentinel.vswitch_name,
                mock.sentinel.port_id)

        self.agent._utils.add_metrics_collection_acls.assert_called_once_with(
            mock.sentinel.port_id)

        if enable_security_groups:
            refresh_firewall = self.agent._sec_groups_agent.refresh_firewall
            refresh_firewall.assert_called_once_with([mock.sentinel.port_id])
        else:
            remove_sec_rules = self.agent._utils.remove_all_security_rules
            remove_sec_rules.assert_called_once_with(mock.sentinel.port_id)

        set_mac_spoofing = self.agent._utils.set_vswitch_port_mac_spoofing
        set_mac_spoofing.assert_called_once_with(
            mock.sentinel.port_id, mock.sentinel.port_security_enabled)

    def test_port_enable_control_metrics_ok(self):
        self.agent._enable_metrics_collection = True
        self.agent._port_metric_retries[self._FAKE_PORT_ID] = (
            self.agent._metrics_max_retries)

        self.agent._utils.is_metrics_collection_allowed.return_value = True
        self.agent._port_enable_control_metrics()

        enable_port_metrics_collection = (
            self.agent._metricsutils.enable_port_metrics_collection)
        enable_port_metrics_collection.assert_called_with(self._FAKE_PORT_ID)
        self.assertNotIn(self._FAKE_PORT_ID, self.agent._port_metric_retries)

    def test_port_enable_control_metrics_maxed(self):
        self.agent._enable_metrics_collection = True
        self.agent._metrics_max_retries = 3
        self.agent._port_metric_retries[self._FAKE_PORT_ID] = 3

        self.agent._utils.is_metrics_collection_allowed.return_value = False
        for _ in range(4):
            self.assertIn(self._FAKE_PORT_ID,
                          self.agent._port_metric_retries)
            self.agent._port_enable_control_metrics()

        self.assertNotIn(self._FAKE_PORT_ID, self.agent._port_metric_retries)

    def test_port_enable_control_metrics_no_vnic(self):
        self.agent._enable_metrics_collection = True
        self.agent._port_metric_retries[self._FAKE_PORT_ID] = 3
        self.agent._utils.is_metrics_collection_allowed.side_effect = (
            exceptions.NotFound(resource=self._FAKE_PORT_ID))

        self.agent._port_enable_control_metrics()
        self.assertNotIn(self._FAKE_PORT_ID, self.agent._port_metric_retries)

    @mock.patch.object(layer2.Layer2Agent, '_port_unbound')
    def test_port_unbound(self, mock_super_unbound):
        self.agent._port_unbound(mock.sentinel.port_id,
                                 mock.sentinel.vnic_deleted)

        mock_super_unbound.assert_called_once_with(
            mock.sentinel.port_id, mock.sentinel.vnic_deleted)
        remove_dev_filter = self.agent._sec_groups_agent.remove_devices_filter
        remove_dev_filter.assert_called_once_with([mock.sentinel.port_id])

    @mock.patch.object(layer2.Layer2Agent, "_process_added_port")
    def test_process_added_port(self, mock_process):
        self.config(enable_qos_extension=True, group="AGENT")

        self.agent._process_added_port(mock.sentinel.device_details)

        mock_process.assert_called_once_with(mock.sentinel.device_details)
        self.agent._qos_ext.handle_port.assert_called_once_with(
            self.agent._context, mock.sentinel.device_details)

    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       '_port_unbound')
    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       '_update_port_status_cache')
    def test_process_removed_port_exception(self, mock_update_port_cache,
                                            mock_port_unbound):
        self.agent._removed_ports = set([mock.sentinel.port_id])
        remove_devices = self.agent._sec_groups_agent.remove_devices_filter
        remove_devices.side_effect = exception.NetworkingHyperVException

        self.assertRaises(exception.NetworkingHyperVException,
                          self.agent._process_removed_port,
                          mock.sentinel.port_id)

        mock_update_port_cache.assert_called_once_with(
            mock.sentinel.port_id, device_bound=False)
        self.assertIn(mock.sentinel.port_id, self.agent._removed_ports)

    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       '_port_unbound')
    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       '_update_port_status_cache')
    def test_process_removed_port(self, mock_update_port_cache,
                                  mock_port_unbound):
        self.agent._removed_ports = set([mock.sentinel.port_id])

        self.agent._process_removed_port(mock.sentinel.port_id)

        mock_update_port_cache.assert_called_once_with(
            mock.sentinel.port_id, device_bound=False)
        mock_port_unbound.assert_called_once_with(mock.sentinel.port_id,
                                                  vnic_deleted=True)
        self.agent._sec_groups_agent.remove_devices_filter(
            [mock.sentinel.port_id])
        self.assertNotIn(mock.sentinel.port_id, self.agent._removed_ports)

    @mock.patch.object(layer2.Layer2Agent, "_work")
    @mock.patch.object(hyperv_agent.HyperVNeutronAgent,
                       '_port_enable_control_metrics')
    def test_work(self, mock_port_enable_metrics, mock_work):
        self.agent._nvgre_enabled = True

        self.agent._work()

        mock_work.assert_called_once_with()
        self.agent._nvgre_ops.refresh_nvgre_records.assert_called_once_with()
        mock_port_enable_metrics.assert_called_with()


class TestMain(base.BaseTestCase):

    @mock.patch.object(hyperv_agent, 'HyperVNeutronAgent')
    @mock.patch.object(hyperv_agent, 'common_config')
    @mock.patch.object(hyperv_agent, 'neutron_config')
    def test_main(self, mock_config, mock_common_config, mock_hyperv_agent):
        hyperv_agent.main()

        mock_config.register_agent_state_opts_helper.assert_called_once_with(
            hyperv_agent.CONF)
        mock_common_config.init.assert_called_once_with(sys.argv[1:])
        mock_config.setup_logging.assert_called_once_with()
        mock_hyperv_agent.assert_called_once_with()
        mock_hyperv_agent.return_value.daemon_loop.assert_called_once_with()
