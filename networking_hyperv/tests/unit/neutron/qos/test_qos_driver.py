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
Unit tests for Windows Hyper-V QoS Driver.
"""

import mock
from neutron.services.qos import qos_consts

from networking_hyperv.neutron.qos import qos_driver
from networking_hyperv.tests import base


class TestQosHyperVAgentDriver(base.BaseTestCase):
    @mock.patch.object(qos_driver.QosHyperVAgentDriver, '__init__',
                       lambda *args, **kwargs: None)
    def setUp(self):
        super(TestQosHyperVAgentDriver, self).setUp()
        self.driver = qos_driver.QosHyperVAgentDriver()
        self.driver._utils = mock.Mock()

    @mock.patch.object(qos_driver, 'networkutils')
    def test_initialize(self, mock_networkutils):
        self.driver.initialize()
        mock_networkutils.NetworkUtils.assert_called_once_with()

    @mock.patch.object(qos_driver.QosHyperVAgentDriver, '_get_policy_values')
    def test_create(self, mock_get_policy_values):
        self.driver.create({'port_id': mock.sentinel.port_id},
                           mock.sentinel.qos_policy)
        mock_get_policy_values.assert_called_once_with(
            mock.sentinel.qos_policy)
        self.driver._utils.set_port_qos_rule.assert_called_once_with(
            mock.sentinel.port_id, mock_get_policy_values.return_value)

    @mock.patch.object(qos_driver.QosHyperVAgentDriver, '_get_policy_values')
    def test_update(self, mock_get_policy_values):
        self.driver.update({'port_id': mock.sentinel.port_id},
                           mock.sentinel.qos_policy)
        mock_get_policy_values.assert_called_once_with(
            mock.sentinel.qos_policy)
        self.driver._utils.set_port_qos_rule.assert_called_once_with(
            mock.sentinel.port_id, mock_get_policy_values.return_value)

    def test_delete(self):
        self.driver.delete({'port_id': mock.sentinel.port_id})
        self.driver._utils.remove_port_qos_rule.assert_called_once_with(
            mock.sentinel.port_id)

    def test_get_policy_values(self):
        qos_rule_0 = mock.Mock(spec=['min_kbps', 'rule_type'])
        qos_rule_0.rule_type = qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH
        qos_rule_1 = mock.Mock(spec=['max_kbps', 'max_burst_kbps',
                                     'rule_type'])
        qos_rule_1.rule_type = qos_consts.RULE_TYPE_BANDWIDTH_LIMIT
        qos_policy = mock.Mock(rules=[qos_rule_0, qos_rule_1])

        expected_val = dict(min_kbps=qos_rule_0.min_kbps,
                            max_kbps=qos_rule_1.max_kbps,
                            max_burst_kbps=qos_rule_1.max_burst_kbps)
        policy_val = self.driver._get_policy_values(qos_policy)

        self.assertEqual(expected_val, policy_val)
