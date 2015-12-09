# Copyright 2015 Cloudbase Solutions Srl
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
Unit tests for Windows Hyper-V L2 agent.
"""

import platform
import sys

import mock
from neutron.common import constants as n_const
from neutron.common import topics
from oslo_config import cfg

from hyperv.neutron import constants
from hyperv.neutron import l2_agent
from hyperv.tests import base

CONF = cfg.CONF


class TestHyperVSecurityAgent(base.BaseTestCase):
    @mock.patch.object(l2_agent.HyperVSecurityAgent, '__init__',
                       lambda *args, **kwargs: None)
    def setUp(self):
        super(TestHyperVSecurityAgent, self).setUp()
        self.agent = l2_agent.HyperVSecurityAgent()

    @mock.patch.object(l2_agent, 'HyperVSecurityCallbackMixin')
    @mock.patch.object(l2_agent.agent_rpc, 'create_consumers')
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


class TestHyperVNeutronAgent(base.BaseTestCase):

    @mock.patch.object(l2_agent.HyperVNeutronAgent, '__init__',
                       lambda *args, **kwargs: None)
    def setUp(self):
        super(TestHyperVNeutronAgent, self).setUp()

        self.agent = l2_agent.HyperVNeutronAgent()
        self.agent.context = mock.sentinel.context
        self.agent._physical_network_mappings = {}

    @mock.patch.object(l2_agent.HyperVNeutronAgent,
                       '_get_agent_configurations')
    def test_set_agent_state(self, mock_get_config):
        mock_get_config.return_value = {mock.sentinel.key: mock.sentinel.val}

        self.agent._set_agent_state()

        expected = {
            'binary': 'neutron-hyperv-agent',
            'host': CONF.host,
            'configurations': {mock.sentinel.key: mock.sentinel.val},
            'agent_type': constants.AGENT_TYPE_HYPERV,
            'topic': n_const.L2_AGENT_TOPIC,
            'start_flag': True
        }
        self.assertEqual(expected, self.agent.agent_state)

    def test_get_agent_configurations(self):
        actual = self.agent._get_agent_configurations()

        self.assertEqual(self.agent._physical_network_mappings,
                         actual['vswitch_mappings'])
        self.assertNotIn('tunnel_types', actual)
        self.assertNotIn('tunneling_ip', actual)

    def test_get_agent_configurations_nvgre(self):
        self.config(enable_support=True, group='NVGRE')
        self.config(provider_tunnel_ip=mock.sentinel.tunneling_ip,
                    group='NVGRE')
        actual = self.agent._get_agent_configurations()

        self.assertEqual(self.agent._physical_network_mappings,
                         actual['vswitch_mappings'])
        self.assertEqual([constants.TYPE_NVGRE], actual['tunnel_types'])
        self.assertEqual(mock.sentinel.tunneling_ip, actual['tunneling_ip'])

    def test_report_state(self):
        self.agent.agent_state = {'start_flag': True}
        self.agent.state_rpc = mock.MagicMock()

        self.agent._report_state()
        self.assertNotIn('start_flag', self.agent.agent_state)

    def test_report_state_exception(self):
        self.agent.agent_state = {'start_flag': True}
        self.agent.state_rpc = mock.MagicMock()
        self.agent.state_rpc.report_state.side_effect = Exception

        self.agent._report_state()

        self.agent.state_rpc.report_state.assert_called_once_with(
            self.agent.context, {'start_flag': True})
        self.assertTrue(self.agent.agent_state['start_flag'])

    @mock.patch.object(l2_agent.loopingcall, 'FixedIntervalLoopingCall')
    @mock.patch.object(l2_agent.n_rpc, 'get_client')
    @mock.patch.object(l2_agent, 'HyperVSecurityAgent')
    @mock.patch.object(l2_agent.sg_rpc, 'SecurityGroupServerRpcApi')
    @mock.patch.object(l2_agent, 'agent_rpc')
    @mock.patch.object(l2_agent, 'CONF')
    def test_setup_rpc(self, mock_CONF, mock_agent_rpc, mock_SGRpcApi,
                       mock_HyperVSecurityAgent, mock_get_client,
                       mock_LoopingCall):
        mock_CONF.NVGRE.enable_support = True
        mock_CONF.AGENT.report_interval = mock.sentinel.report_interval
        self.agent._setup_rpc()

        self.assertEqual('hyperv_%s' % platform.node(), self.agent.agent_id)
        self.assertEqual(topics.AGENT, self.agent.topic)
        self.assertEqual(mock_agent_rpc.PluginApi.return_value,
                         self.agent.plugin_rpc)
        self.assertEqual(mock_HyperVSecurityAgent.return_value,
                         self.agent.sec_groups_agent)
        self.assertEqual([self.agent], self.agent.endpoints)
        self.assertEqual(mock_agent_rpc.create_consumers.return_value,
                         self.agent.connection)
        self.assertEqual(mock_get_client.return_value, self.agent.client)

        mock_HyperVSecurityAgent.assert_called_once_with(
            self.agent.context, self.agent.sg_plugin_rpc)

        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.PORT, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE],
                     [constants.LOOKUP, constants.UPDATE]]
        mock_agent_rpc.create_consumers.assert_called_once_with(
            self.agent.endpoints, self.agent.topic, consumers)
        mock_LoopingCall.return_value.start.assert_called_once_with(
            interval=mock.sentinel.report_interval)


class TestMain(base.BaseTestCase):

    @mock.patch.object(l2_agent, 'HyperVNeutronAgent')
    @mock.patch.object(l2_agent, 'common_config')
    @mock.patch.object(l2_agent, 'config')
    def test_main(self, mock_config, mock_common_config, mock_HyperVAgent):
        l2_agent.main()

        mock_config.register_agent_state_opts_helper.assert_called_once_with(
            CONF)
        mock_common_config.init.assert_called_once_with(sys.argv[1:])
        mock_config.setup_logging.assert_called_once_with()
        mock_HyperVAgent.assert_called_once_with()
        mock_HyperVAgent.return_value.daemon_loop.assert_called_once_with()
