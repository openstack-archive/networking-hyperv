# Copyright 2014 Cloudbase Solutions SRL
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
Unit tests for the Hyper-V Security Groups Driver.
"""

import mock
from oslo_config import cfg

from hyperv.neutron import security_groups_driver as sg_driver
from hyperv.neutron import utilsfactory
from hyperv.tests import base

CONF = cfg.CONF


class SecurityGroupRuleTestHelper(base.BaseTestCase):
    _FAKE_DIRECTION = 'egress'
    _FAKE_ETHERTYPE = 'IPv4'
    _FAKE_ETHERTYPE_IPV6 = 'IPv6'
    _FAKE_PROTOCOL = 'tcp'
    _FAKE_ACTION = sg_driver.ACL_PROP_MAP['action']['allow']
    _FAKE_DEST_IP_PREFIX = '10.0.0.0/24'
    _FAKE_SOURCE_IP_PREFIX = '10.0.1.0/24'
    _FAKE_IPV6_LEN128_IP = 'fddd:cafd:e664:0:f816:3eff:fe8d:59d2/128'

    _FAKE_PORT_MIN = 9001
    _FAKE_PORT_MAX = 9011

    def _create_security_rule(self):
        return {
            'direction': self._FAKE_DIRECTION,
            'ethertype': self._FAKE_ETHERTYPE,
            'protocol': self._FAKE_PROTOCOL,
            'dest_ip_prefix': self._FAKE_DEST_IP_PREFIX,
            'source_ip_prefix': self._FAKE_SOURCE_IP_PREFIX,
            'port_range_min': self._FAKE_PORT_MIN,
            'port_range_max': self._FAKE_PORT_MAX
        }

    @classmethod
    def _acl(self, key1, key2):
        return sg_driver.ACL_PROP_MAP[key1][key2]


class TestHyperVSecurityGroupsDriverMixin(SecurityGroupRuleTestHelper):

    _FAKE_DEVICE = 'fake_device'
    _FAKE_ID = 'fake_id'
    _FAKE_PARAM_NAME = 'fake_param_name'
    _FAKE_PARAM_VALUE = 'fake_param_value'

    def setUp(self):
        super(TestHyperVSecurityGroupsDriverMixin, self).setUp()
        self._mock_windows_version = mock.patch.object(utilsfactory,
                                                       'get_hypervutils')
        self._mock_windows_version.start()
        self._driver = sg_driver.HyperVSecurityGroupsDriverMixin()
        self._driver._utils = mock.MagicMock()
        self._driver._sg_gen = mock.MagicMock()

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriverMixin,
                       '_create_port_rules')
    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriverMixin,
                       '_add_sg_port_rules')
    def test_prepare_port_filter(self, mock_add_rules, mock_create_rules):
        mock_port = self._get_port()
        mock_create_default = self._driver._sg_gen.create_default_sg_rules

        self._driver.prepare_port_filter(mock_port)

        self.assertEqual(mock_port,
                         self._driver._security_ports[self._FAKE_DEVICE])

        mock_add_rules.assert_called_once_with(
            self._FAKE_ID, mock_create_default.return_value)
        self._driver._create_port_rules.assert_called_once_with(
            self._FAKE_ID, mock_port['security_group_rules'])

    def test_update_port_filter(self):
        mock_port = self._get_port()
        new_mock_port = self._get_port()
        new_mock_port['id'] += '2'
        new_mock_port['security_group_rules'][0]['ethertype'] += "2"

        self._driver._security_ports[mock_port['device']] = mock_port
        self._driver._create_port_rules = mock.MagicMock()
        self._driver._remove_port_rules = mock.MagicMock()
        self._driver.update_port_filter(new_mock_port)

        self._driver._remove_port_rules.assert_called_once_with(
            mock_port['id'], mock_port['security_group_rules'])
        self._driver._create_port_rules.assert_called_once_with(
            new_mock_port['id'], new_mock_port['security_group_rules'])
        self.assertEqual(new_mock_port,
                         self._driver._security_ports[new_mock_port['device']])

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriverMixin,
                       'prepare_port_filter')
    def test_update_port_filter_new_port(self, mock_method):
        mock_port = self._get_port()
        self._driver.prepare_port_filter = mock.MagicMock()
        self._driver.update_port_filter(mock_port)

        self._driver.prepare_port_filter.assert_called_once_with(mock_port)

    def test_remove_port_filter(self):
        mock_port = self._get_port()
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._security_ports[mock_port['device']] = mock_port
        self._driver.remove_port_filter(mock_port)
        self.assertNotIn(mock_port['device'], self._driver._security_ports)
        self.assertNotIn(mock_port['id'], self._driver._sec_group_rules)

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriverMixin,
                       '_add_sg_port_rules')
    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriverMixin,
                       '_remove_sg_port_rules')
    def test_create_port_rules(self, mock_remove, mock_add):
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._sg_gen.create_security_group_rules.return_value = [
            mock_rule]
        self._driver._sg_gen.compute_new_rules_add.return_value = (
            [mock_rule, mock_rule], [mock_rule, mock_rule])

        self._driver._create_port_rules(self._FAKE_ID, [mock_rule])

        self._driver._sg_gen.compute_new_rules_add.assert_called_once_with(
            [mock_rule], [mock_rule])
        mock_remove.assert_called_once_with(self._FAKE_ID, [mock_rule])
        mock_add.assert_called_once_with(self._FAKE_ID, [mock_rule])

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriverMixin,
                       '_remove_sg_port_rules')
    def test_remove_port_rules(self, mock_remove):
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._sg_gen.create_security_group_rules.return_value = [
            mock_rule]

        self._driver._remove_port_rules(self._FAKE_ID, [mock_rule])

        mock_remove.assert_called_once_with(self._FAKE_ID, [mock_rule])

    def test_add_sg_port_rules_exception(self):
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = []
        self._driver._utils.create_security_rules.side_effect = Exception(
            'Generated Exception for testing.')

        self._driver._add_sg_port_rules(self._FAKE_ID, [mock_rule])

        self.assertNotIn(mock_rule,
                         self._driver._sec_group_rules[self._FAKE_ID])

    def test_add_sg_port_rules(self):
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = []
        self._driver._add_sg_port_rules(self._FAKE_ID, [mock_rule])

        self._driver._utils.create_security_rules.assert_called_once_with(
            self._FAKE_ID, [mock_rule])
        self.assertIn(mock_rule, self._driver._sec_group_rules[self._FAKE_ID])

    def test_add_sg_port_rules_empty(self):
        self._driver._add_sg_port_rules(mock.sentinel.id, [])
        self.assertFalse(self._driver._utils.create_security_rules.called)

    def test_remove_sg_port_rules_exception(self):
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._utils.remove_security_rules.side_effect = Exception(
            'Generated Exception for testing.')
        self._driver._remove_sg_port_rules(self._FAKE_ID, [mock_rule])

        self.assertIn(mock_rule, self._driver._sec_group_rules[self._FAKE_ID])

    def test_remove_sg_port_rules(self):
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._remove_sg_port_rules(self._FAKE_ID, [mock_rule])

        self._driver._utils.remove_security_rules.assert_called_once_with(
            self._FAKE_ID, [mock_rule])
        self.assertNotIn(mock_rule,
                         self._driver._sec_group_rules[self._FAKE_ID])

    def test_remove_sg_port_rules_empty(self):
        self._driver._remove_sg_port_rules(mock.sentinel.id, [])
        self.assertFalse(self._driver._utils.remove_security_rules.called)

    def _get_port(self):
        return {
            'device': self._FAKE_DEVICE,
            'id': self._FAKE_ID,
            'security_group_rules': [mock.MagicMock()]
        }


class SecurityGroupRuleR2BaseTestCase(SecurityGroupRuleTestHelper):
    def _create_sg_rule(self, protocol=None, action=None, direction='egress'):
        protocol = protocol or self._FAKE_PROTOCOL
        action = action or self._FAKE_ACTION
        remote_addr = (self._FAKE_DEST_IP_PREFIX if direction is 'egress' else
                       self._FAKE_SOURCE_IP_PREFIX)
        return sg_driver.SecurityGroupRuleR2(
            self._acl('direction', self._FAKE_DIRECTION),
            '%s-%s' % (self._FAKE_PORT_MIN, self._FAKE_PORT_MAX),
            protocol, remote_addr, action)


class SecurityGroupRuleGeneratorTestCase(SecurityGroupRuleR2BaseTestCase):

    def setUp(self):
        super(SecurityGroupRuleGeneratorTestCase, self).setUp()

        self.sg_gen = sg_driver.SecurityGroupRuleGenerator()

    @mock.patch.object(sg_driver.SecurityGroupRuleGenerator,
                       'create_security_group_rule')
    def test_create_security_group_rules(self, mock_create_sec_group_rule):
        sg_rule = self._create_sg_rule()
        mock_create_sec_group_rule.return_value = [sg_rule]
        expected = [sg_rule] * 2
        rules = [self._create_security_rule()] * 2

        actual = self.sg_gen.create_security_group_rules(rules)
        self.assertEqual(expected, actual)

    def test_convert_any_address_to_same_ingress(self):
        rule = self._create_security_rule()
        rule['direction'] = 'ingress'
        actual = self.sg_gen._get_rule_remote_address(rule)
        self.assertEqual(self._FAKE_SOURCE_IP_PREFIX, actual)

    def test_convert_any_address_to_same_egress(self):
        rule = self._create_security_rule()
        rule['direction'] += '2'
        actual = self.sg_gen._get_rule_remote_address(rule)
        self.assertEqual(self._FAKE_DEST_IP_PREFIX, actual)

    def test_convert_any_address_to_ipv4(self):
        rule = self._create_security_rule()
        del rule['dest_ip_prefix']
        actual = self.sg_gen._get_rule_remote_address(rule)
        self.assertEqual(self._acl('address_default', 'IPv4'), actual)

    def test_convert_any_address_to_ipv6(self):
        rule = self._create_security_rule()
        del rule['dest_ip_prefix']
        rule['ethertype'] = self._FAKE_ETHERTYPE_IPV6
        actual = self.sg_gen._get_rule_remote_address(rule)
        self.assertEqual(self._acl('address_default', 'IPv6'), actual)


class SecurityGroupRuleGeneratorR2TestCase(SecurityGroupRuleR2BaseTestCase):

    def setUp(self):
        super(SecurityGroupRuleGeneratorR2TestCase, self).setUp()

        self.sg_gen = sg_driver.SecurityGroupRuleGeneratorR2()

    def test_create_security_group_rule(self):
        expected = [self._create_sg_rule()]
        rule = self._create_security_rule()

        actual = self.sg_gen.create_security_group_rule(rule)
        self.assertEqual(expected, actual)

    def test_create_security_group_rule_len128(self):
        expected = [self._create_sg_rule()]
        expected[0].RemoteIPAddress = self._FAKE_IPV6_LEN128_IP.split(
            '/128', 1)[0]
        rule = self._create_security_rule()
        rule['dest_ip_prefix'] = self._FAKE_IPV6_LEN128_IP

        actual = self.sg_gen.create_security_group_rule(rule)
        self.assertEqual(expected, actual)

    def test_create_security_group_rule_any(self):
        sg_rule1 = self._create_sg_rule(self._acl('protocol', 'tcp'))
        sg_rule2 = self._create_sg_rule(self._acl('protocol', 'udp'))
        sg_rule3 = self._create_sg_rule(self._acl('protocol', 'icmp'))
        sg_rule4 = self._create_sg_rule(self._acl('protocol', 'icmpv6'))

        rule = self._create_security_rule()
        rule['protocol'] = sg_driver.ACL_PROP_MAP["default"]

        actual = self.sg_gen.create_security_group_rule(rule)
        expected = [sg_rule1, sg_rule2, sg_rule3, sg_rule4]
        self.assertEqual(sorted(expected), sorted(actual))

    def test_create_default_sg_rules(self):
        actual = self.sg_gen.create_default_sg_rules()
        self.assertEqual(16, len(actual))

    def test_compute_new_rules_add(self):
        new_rule = self._create_sg_rule()
        old_rule = self._create_sg_rule()
        old_rule.Direction = mock.sentinel.FAKE_DIRECTION

        add_rules, remove_rules = self.sg_gen.compute_new_rules_add(
            [old_rule], [new_rule, old_rule])

        self.assertEqual([new_rule], add_rules)

    def test_get_rule_port_range(self):
        rule = self._create_security_rule()
        expected = '%s-%s' % (self._FAKE_PORT_MIN, self._FAKE_PORT_MAX)
        actual = self.sg_gen._get_rule_port_range(rule)

        self.assertEqual(expected, actual)

    def test_get_rule_port_range_default(self):
        rule = self._create_security_rule()
        del rule['port_range_min']
        expected = sg_driver.ACL_PROP_MAP['default']
        actual = self.sg_gen._get_rule_port_range(rule)

        self.assertEqual(expected, actual)

    def test_get_rule_protocol_icmp(self):
        self._check_get_rule_protocol('icmp', self._acl('protocol', 'icmp'))

    def test_get_rule_protocol_no_icmp(self):
        self._check_get_rule_protocol('tcp', 'tcp')

    def _check_get_rule_protocol(self, protocol, expected):
        rule = self._create_security_rule()
        rule['protocol'] = protocol
        actual = self.sg_gen._get_rule_protocol(rule)

        self.assertEqual(expected, actual)


class SecurityGroupRuleR2TestCase(SecurityGroupRuleR2BaseTestCase):

    def test_sg_rule_to_dict(self):
        expected = {'Direction': self._acl('direction', self._FAKE_DIRECTION),
                    'Action': self._FAKE_ACTION,
                    'Protocol': self._FAKE_PROTOCOL,
                    'LocalPort': '%s-%s' % (self._FAKE_PORT_MIN,
                                            self._FAKE_PORT_MAX),
                    'RemoteIPAddress': self._FAKE_DEST_IP_PREFIX,
                    'Stateful': True,
                    'IdleSessionTimeout': 0}

        sg_rule = self._create_sg_rule()
        self.assertEqual(expected, sg_rule.to_dict())

    def test_localport(self):
        sg_rule = self._create_sg_rule()
        expected = '%s-%s' % (self._FAKE_PORT_MIN, self._FAKE_PORT_MAX)
        self.assertEqual(expected, sg_rule.LocalPort)

    def test_localport_icmp(self):
        sg_rule = self._create_sg_rule(self._acl('protocol', 'icmp'))
        self.assertEqual('', sg_rule.LocalPort)

    def test_stateful_icmp(self):
        sg_rule = self._create_sg_rule(self._acl('protocol', 'icmp'))
        self.assertFalse(sg_rule.Stateful)

    def test_stateful_icmpv6(self):
        sg_rule = self._create_sg_rule(self._acl('protocol', 'icmpv6'))
        self.assertFalse(sg_rule.Stateful)

    def test_stateful_deny(self):
        sg_rule = self._create_sg_rule(action=self._acl('action', 'deny'))
        self.assertFalse(sg_rule.Stateful)

    def test_stateful_true(self):
        sg_rule = self._create_sg_rule()
        self.assertTrue(sg_rule.Stateful)

    def test_rule_uniqueness(self):
        sg_rule = self._create_sg_rule()
        sg_rule2 = self._create_sg_rule(self._acl('protocol', 'icmp'))

        self.assertEqual([sg_rule], list(set([sg_rule] * 2)))
        self.assertEqual(sorted([sg_rule, sg_rule2]),
                         sorted(list(set([sg_rule, sg_rule2]))))
