# Copyright 2015 Cloudbase Solutions SRL
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
Unit Tests for Hyper-V Agent Notifier.
"""

import mock

from networking_hyperv.neutron import constants
from networking_hyperv.neutron import hyperv_agent_notifier
from networking_hyperv.tests import base


class TestAgentNotifierApi(base.BaseTestCase):

    def setUp(self):
        super(TestAgentNotifierApi, self).setUp()

        self.notifier = hyperv_agent_notifier.AgentNotifierApi(
            topic=constants.AGENT_TOPIC, client=mock.MagicMock())

    def test_tunnel_update(self):
        expected_topic = hyperv_agent_notifier.get_topic_name(
            constants.AGENT_TOPIC, constants.TUNNEL, constants.UPDATE)

        self.notifier.tunnel_update(mock.sentinel.context,
                                    mock.sentinel.tunnel_ip,
                                    constants.TYPE_NVGRE)

        self.notifier._client.prepare.assert_called_once_with(
            topic=expected_topic, fanout=True)
        prepared_client = self.notifier._client.prepare.return_value
        prepared_client.cast.assert_called_once_with(
            mock.sentinel.context, 'tunnel_update',
            tunnel_ip=mock.sentinel.tunnel_ip,
            tunnel_type=constants.TYPE_NVGRE)

    def test_lookup_update(self):
        expected_topic = hyperv_agent_notifier.get_topic_name(
            constants.AGENT_TOPIC, constants.LOOKUP, constants.UPDATE)

        self.notifier.lookup_update(mock.sentinel.context,
                                    mock.sentinel.lookup_ip,
                                    mock.sentinel.lookup_details)

        self.notifier._client.prepare.assert_called_once_with(
            topic=expected_topic, fanout=True)
        prepared_client = self.notifier._client.prepare.return_value
        prepared_client.cast.assert_called_once_with(
            mock.sentinel.context, 'lookup_update',
            lookup_ip=mock.sentinel.lookup_ip,
            lookup_details=mock.sentinel.lookup_details)
