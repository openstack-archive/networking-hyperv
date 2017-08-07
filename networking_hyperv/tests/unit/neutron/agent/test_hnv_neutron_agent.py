# Copyright 2017 Cloudbase Solutions SRL
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
Unit tests for the Neutron HNV L2 Agent.
"""

import sys

import mock

from networking_hyperv.neutron.agent import hnv_neutron_agent as hnv_agent
from networking_hyperv.neutron import constants
from networking_hyperv.tests import base as test_base


class TestHNVAgent(test_base.HyperVBaseTestCase):

    @mock.patch.object(hnv_agent.HNVAgent, "_setup")
    @mock.patch.object(hnv_agent.HNVAgent, "_setup_rpc")
    @mock.patch.object(hnv_agent.HNVAgent, "_set_agent_state")
    def _get_agent(self, mock_set_agent_state, mock_setup_rpc, mock_setup):
        return hnv_agent.HNVAgent()

    def setUp(self):
        super(TestHNVAgent, self).setUp()

        self.agent = self._get_agent()
        self.agent._neutron_client = mock.Mock()

    def test_get_agent_configurations(self):
        self.config(logical_network=mock.sentinel.logical_network,
                    group="HNV")
        self.agent._physical_network_mappings = mock.sentinel.mappings

        agent_configurations = self.agent._get_agent_configurations()

        expected_keys = ["logical_network", "vswitch_mappings",
                         "devices", "l2_population", "tunnel_types",
                         "bridge_mappings", "enable_distributed_routing"]
        self.assertEqual(sorted(expected_keys),
                         sorted(agent_configurations.keys()))
        self.assertEqual(mock.sentinel.mappings,
                         agent_configurations["vswitch_mappings"])
        self.assertEqual(str(mock.sentinel.logical_network),
                         agent_configurations["logical_network"])

    @mock.patch.object(hnv_agent.HNVAgent, "_get_vswitch_name")
    def test_provision_network(self, mock_get_vswitch_name):
        self.agent._provision_network(mock.sentinel.port_id,
                                      mock.sentinel.net_uuid,
                                      mock.sentinel.network_type,
                                      mock.sentinel.physical_network,
                                      mock.sentinel.segmentation_id)

        mock_get_vswitch_name.assert_called_once_with(
            mock.sentinel.network_type,
            mock.sentinel.physical_network)

        vswitch_map = self.agent._network_vswitch_map[mock.sentinel.net_uuid]
        self.assertEqual(mock.sentinel.network_type,
                         vswitch_map['network_type'])
        self.assertEqual(mock_get_vswitch_name.return_value,
                         vswitch_map['vswitch_name'])
        self.assertEqual(mock.sentinel.segmentation_id,
                         vswitch_map['vlan_id'])

    @mock.patch.object(hnv_agent.hyperv_base.Layer2Agent, '_port_bound')
    def test_port_bound(self, mock_super_port_bound):
        self.agent._port_bound(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id)

        mock_super_port_bound.assert_called_once_with(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id)
        mock_neutron_client = self.agent._neutron_client
        mock_neutron_client.get_port_profile_id.assert_called_once_with(
            mock.sentinel.port_id)
        self.agent._utils.set_vswitch_port_profile_id.assert_called_once_with(
            switch_port_name=mock.sentinel.port_id,
            profile_id=mock_neutron_client.get_port_profile_id.return_value,
            profile_data=constants.PROFILE_DATA,
            profile_name=constants.PROFILE_NAME,
            net_cfg_instance_id=constants.NET_CFG_INSTANCE_ID,
            cdn_label_id=constants.CDN_LABEL_ID,
            cdn_label_string=constants.CDN_LABEL_STRING,
            vendor_id=constants.VENDOR_ID,
            vendor_name=constants.VENDOR_NAME)

    @mock.patch.object(hnv_agent.HNVAgent, '_port_bound')
    def test_treat_vif_port_state_up(self, mock_port_bound):
        self.agent._treat_vif_port(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, True)

        mock_port_bound.assert_called_once_with(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id)

    @mock.patch.object(hnv_agent.HNVAgent, '_port_unbound')
    def test_treat_vif_port_state_down(self, mock_port_unbound):
        self.agent._treat_vif_port(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, False)

        mock_port_unbound.assert_called_once_with(mock.sentinel.port_id)


class TestMain(test_base.BaseTestCase):

    @mock.patch.object(hnv_agent, 'HNVAgent')
    @mock.patch.object(hnv_agent, 'common_config')
    @mock.patch.object(hnv_agent, 'neutron_config')
    def test_main(self, mock_config, mock_common_config, mock_hnv_agent):
        hnv_agent.main()

        mock_config.register_agent_state_opts_helper.assert_called_once_with(
            hnv_agent.CONF)
        mock_common_config.init.assert_called_once_with(sys.argv[1:])
        mock_config.setup_logging.assert_called_once_with()
        mock_hnv_agent.assert_called_once_with()
        mock_hnv_agent.return_value.daemon_loop.assert_called_once_with()
