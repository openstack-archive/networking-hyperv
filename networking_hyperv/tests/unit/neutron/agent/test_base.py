# Copyright 2017 Cloudbase Solutions Srl
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
Unit tests for Neutron base agent.
"""

import mock

from networking_hyperv.neutron.agent import base as agent_base
from networking_hyperv.tests import base as test_base


class _BaseAgent(agent_base.BaseAgent):

    def _get_agent_configurations(self):
        pass

    def _setup_rpc(self):
        pass

    def _work(self):
        pass


class TestBaseAgent(test_base.HyperVBaseTestCase):

    def setUp(self):
        super(TestBaseAgent, self).setUp()

        self._agent = _BaseAgent()

        self._agent._agent_id = mock.sentinel.agent_id
        self._agent._context = mock.sentinel.admin_context
        self._agent._utils = mock.MagicMock()

        self._agent._client = mock.MagicMock()
        self._agent._plugin_rpc = mock.Mock()
        self._agent._connection = mock.MagicMock()

        self._agent._state_rpc = mock.MagicMock()

    def test_set_agent_state(self):
        self._agent._agent_state = {}
        self._agent._host = mock.sentinel.host

        self._agent._set_agent_state()

        expected_keys = ["binary", "host", "configurations", "agent_type",
                         "topic", "start_flag"]
        self.assertEqual(sorted(expected_keys),
                         sorted(self._agent._agent_state.keys()))
        self.assertEqual(mock.sentinel.host, self._agent._agent_state["host"])

    @mock.patch('time.time')
    @mock.patch('time.sleep')
    @mock.patch.object(_BaseAgent, '_work')
    @mock.patch.object(_BaseAgent, '_prologue')
    def test_daemon_loop(self, mock_prologue, mock_work,
                         mock_sleep, mock_time):
        mock_work.side_effect = [Exception()]
        mock_time.side_effect = [1, 3, KeyboardInterrupt]

        self.assertRaises(KeyboardInterrupt, self._agent.daemon_loop)

        mock_prologue.assert_called_once_with()

    def test_report_state(self):
        self._agent._agent_state = {'start_flag': True}

        self._agent._report_state()

        self.assertNotIn('start_flag', self._agent._agent_state)

    def test_report_state_exception(self):
        self._agent._agent_state = {'start_flag': True}
        self._agent._state_rpc.report_state.side_effect = Exception

        self._agent._report_state()

        self._agent._state_rpc.report_state.assert_called_once_with(
            self._agent._context, {'start_flag': True})
        self.assertTrue(self._agent._agent_state['start_flag'])
