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
from os_win import exceptions

from networking_hyperv.neutron import security_groups_driver as sg_driver
from networking_hyperv.tests import base


class SecurityGroupRuleTestHelper(base.HyperVBaseTestCase):
    _FAKE_DIRECTION = 'egress'
    _FAKE_ETHERTYPE = 'IPv4'
    _FAKE_ETHERTYPE_IPV6 = 'IPv6'
    _FAKE_PROTOCOL = 'tcp'
    _FAKE_ACTION = sg_driver.ACL_PROP_MAP['action']['allow']
    _FAKE_DEST_IP_PREFIX = '10.0.0.0/24'
    _FAKE_SOURCE_IP_PREFIX = '10.0.1.0/24'
    _FAKE_MEMBER_IP = '10.0.0.1'
    _FAKE_IPV6_LEN128_IP = 'fddd:cafd:e664:0:f816:3eff:fe8d:59d2/128'
    _FAKE_SG_ID = 'fake_sg_id'

    _FAKE_PORT_MIN = 9001
    _FAKE_PORT_MAX = 9011

    def _create_security_rule(self, **rule_updates):
        rule = {
            'direction': self._FAKE_DIRECTION,
            'ethertype': self._FAKE_ETHERTYPE,
            'protocol': self._FAKE_PROTOCOL,
            'dest_ip_prefix': self._FAKE_DEST_IP_PREFIX,
            'source_ip_prefix': self._FAKE_SOURCE_IP_PREFIX,
            'port_range_min': self._FAKE_PORT_MIN,
            'port_range_max': self._FAKE_PORT_MAX,
            'security_group_id': self._FAKE_SG_ID
        }
        rule.update(rule_updates)
        return rule

    @classmethod
    def _acl(self, key1, key2):
        return sg_driver.ACL_PROP_MAP[key1][key2]


class TestHyperVSecurityGroupsDriver(SecurityGroupRuleTestHelper):

    _FAKE_DEVICE = 'fake_device'
    _FAKE_ID = 'fake_id'
    _FAKE_PARAM_NAME = 'fake_param_name'
    _FAKE_PARAM_VALUE = 'fake_param_value'

    def setUp(self):
        super(TestHyperVSecurityGroupsDriver, self).setUp()

        self._driver = sg_driver.HyperVSecurityGroupsDriver()
        self._driver._utils = mock.MagicMock()
        self._driver._sg_gen = mock.MagicMock()

    def test__select_sg_rules_for_port(self):
        mock_port = self._get_port()
        mock_port['fixed_ips'] = [mock.MagicMock()]
        mock_port['security_groups'] = [self._FAKE_SG_ID]

        fake_sg_template = self._create_security_rule()
        fake_sg_template['direction'] = 'ingress'
        self._driver._sg_rule_templates[self._FAKE_SG_ID] = [fake_sg_template]

        # Test without remote_group_id
        rule_list = self._driver._select_sg_rules_for_port(mock_port,
                                                           'ingress')
        self.assertNotIn('security_group_id', rule_list[0])

        # Test with remote_group_id
        fake_sg_template['remote_group_id'] = self._FAKE_SG_ID
        self._driver._sg_members[self._FAKE_SG_ID] = {self._FAKE_ETHERTYPE:
                                                      [self._FAKE_MEMBER_IP]}
        rule_list = self._driver._select_sg_rules_for_port(mock_port,
                                                           'ingress')
        self.assertEqual('10.0.0.1/32', rule_list[0]['source_ip_prefix'])
        self.assertNotIn('security_group_id', rule_list[0])
        self.assertNotIn('remote_group_id', rule_list[0])

        # Test for fixed 'ip' existing in 'sg_members'
        self._driver._sg_members[self._FAKE_SG_ID][self._FAKE_ETHERTYPE] = [
            '10.0.0.2']

        mock_port['fixed_ips'] = ['10.0.0.2']
        rule_list = self._driver._select_sg_rules_for_port(mock_port,
                                                           'ingress')
        self.assertEqual([], rule_list)

        # Test for 'egress' direction
        fake_sg_template['direction'] = 'egress'
        fix_ip = [self._FAKE_MEMBER_IP, '10.0.0.2']
        self._driver._sg_members[self._FAKE_SG_ID][self._FAKE_ETHERTYPE] = (
            fix_ip)

        rule_list = self._driver._select_sg_rules_for_port(mock_port,
                                                           'egress')
        self.assertEqual('10.0.0.1/32', rule_list[0]['dest_ip_prefix'])

        # Test for rules with a different direction
        rule_list = self._driver._select_sg_rules_for_port(mock_port,
                                                           'ingress')
        self.assertEqual([], rule_list)

    def test_update_security_group_rules(self):
        mock_rule = [self._create_security_rule()]
        self._driver.update_security_group_rules(self._FAKE_ID, mock_rule)
        self.assertEqual(mock_rule,
                         self._driver._sg_rule_templates[self._FAKE_ID])

    def test_update_security_group_members(self):
        mock_member = ['10.0.0.1/32']
        self._driver.update_security_group_members(self._FAKE_ID, mock_member)
        self.assertEqual(mock_member, self._driver._sg_members[self._FAKE_ID])

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_select_sg_rules_for_port')
    def test__generate_rules(self, mock_select_sg_rules):
        mock_rule = [self._create_security_rule()]
        mock_port = self._get_port()
        mock_select_sg_rules.return_value = mock_rule
        ports = self._driver._generate_rules([mock_port])

        # Expected result
        mock_rule.append(mock_rule[0])
        expected = {self._FAKE_ID: mock_rule}
        self.assertEqual(expected, ports)

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_generate_rules')
    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_create_port_rules')
    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_add_sg_port_rules')
    def test_prepare_port_filter(self, mock_add_rules, mock_create_rules,
                                 mock_gen_rules):
        mock_port = self._get_port()
        mock_create_default = self._driver._sg_gen.create_default_sg_rules

        fake_rule = self._create_security_rule()
        self._driver._get_rule_remote_address = mock.MagicMock(
            return_value=self._FAKE_SOURCE_IP_PREFIX)
        mock_gen_rules.return_value = {mock_port['id']: [fake_rule]}

        self._driver.prepare_port_filter(mock_port)

        self.assertEqual(mock_port,
                         self._driver._security_ports[self._FAKE_DEVICE])
        mock_gen_rules.assert_called_with([self._driver._security_ports
                                          [self._FAKE_DEVICE]])
        mock_add_rules.assert_called_once_with(
            mock_port, mock_create_default.return_value)

        self._driver._create_port_rules.assert_called_with(
            mock_port, [fake_rule])

    def test_prepare_port_filter_security_disabled(self):
        mock_port = self._get_port()
        mock_port.pop('port_security_enabled')

        self._driver.prepare_port_filter(mock_port)

        self.assertNotIn(mock_port['device'], self._driver._security_ports)
        self.assertNotIn(mock_port['id'], self._driver._sec_group_rules)

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_generate_rules')
    def test_update_port_filter(self, mock_gen_rules):
        mock_port = self._get_port()
        new_mock_port = self._get_port()
        new_mock_port['id'] += '2'
        new_mock_port['security_group_rules'][0]['ethertype'] += "2"

        fake_rule_new = self._create_security_rule()
        self._driver._get_rule_remote_address = mock.MagicMock(
            return_value=self._FAKE_SOURCE_IP_PREFIX)

        mock_gen_rules.return_value = {new_mock_port['id']: [fake_rule_new]}

        self._driver._security_ports[mock_port['device']] = mock_port
        self._driver._sec_group_rules[new_mock_port['id']] = []

        self._driver._create_port_rules = mock.MagicMock()
        self._driver._remove_port_rules = mock.MagicMock()
        self._driver.update_port_filter(new_mock_port)

        self._driver._remove_port_rules.assert_called_once_with(
            mock_port, mock_port['security_group_rules'])
        self._driver._create_port_rules.assert_called_once_with(
            new_mock_port, [new_mock_port['security_group_rules'][0],
                            fake_rule_new])
        self.assertEqual(new_mock_port,
                         self._driver._security_ports[new_mock_port['device']])

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       'prepare_port_filter')
    def test_update_port_filter_new_port(self, mock_method):
        mock_port = self._get_port()
        new_mock_port = self._get_port()
        new_mock_port['id'] += '2'
        new_mock_port['device'] += '2'
        new_mock_port['security_group_rules'][0]['ethertype'] += "2"

        self._driver._security_ports[mock_port['device']] = mock_port
        self._driver.update_port_filter(new_mock_port)

        self.assertNotIn(new_mock_port['device'], self._driver._security_ports)
        mock_method.assert_called_once_with(new_mock_port)

    def test_update_port_filter_security_disabled(self):
        mock_port = self._get_port()
        mock_port['port_security_enabled'] = False

        self._driver.update_port_filter(mock_port)

        self.assertFalse(self._driver._utils.remove_all_security_rules.called)
        self.assertNotIn(mock_port['device'], self._driver._security_ports)
        self.assertNotIn(mock_port['id'], self._driver._sec_group_rules)

    def test_update_port_filter_security_disabled_existing_rules(self):
        mock_port = self._get_port()
        mock_port.pop('port_security_enabled')
        self._driver._sec_group_rules[mock_port['id']] = mock.ANY
        self._driver._security_ports[mock_port['device']] = mock.sentinel.port

        self._driver.update_port_filter(mock_port)

        self._driver._utils.remove_all_security_rules.assert_called_once_with(
            mock_port['id'])
        self.assertNotIn(mock_port['device'], self._driver._security_ports)
        self.assertNotIn(mock_port['id'], self._driver._sec_group_rules)

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_generate_rules')
    def test_update_port_filter_existing_wildcard_rules(self, mock_gen_rules):
        mock_port = self._get_port()
        new_mock_port = self._get_port()
        new_mock_port['id'] += '2'
        new_mock_port['security_group_rules'][0]['ethertype'] += "2"

        fake_rule_new = self._create_security_rule(direction='egress',
                                                   protocol='udp')
        fake_wildcard_rule_new = self._create_security_rule(protocol='ANY',
                                                            direction='egress')
        fake_expanded_rules = [
            self._create_security_rule(direction='egress', protocol='tcp'),
            self._create_security_rule(direction='egress', protocol='udp'),
            self._create_security_rule(direction='egress', protocol='icmp')]
        self._driver._sg_gen.expand_wildcard_rules.return_value = (
            fake_expanded_rules)

        mock_gen_rules.return_value = {
            new_mock_port['id']: [fake_rule_new, fake_wildcard_rule_new]}

        self._driver._security_ports[mock_port['device']] = mock_port
        self._driver._sec_group_rules[new_mock_port['id']] = [
            self._create_security_rule(direction='egress', protocol='icmp')]

        filtered_new_rules = [new_mock_port['security_group_rules'][0],
                              fake_wildcard_rule_new]
        filtered_remove_rules = mock_port['security_group_rules']

        self._driver._create_port_rules = mock.MagicMock()
        self._driver._remove_port_rules = mock.MagicMock()
        self._driver.update_port_filter(new_mock_port)

        self._driver._sg_gen.expand_wildcard_rules.assert_called_once_with(
            [fake_rule_new, fake_wildcard_rule_new])
        self._driver._remove_port_rules.assert_called_once_with(
            mock_port, filtered_remove_rules)
        self._driver._create_port_rules.assert_called_once_with(
            new_mock_port, filtered_new_rules)
        self.assertEqual(new_mock_port,
                         self._driver._security_ports[new_mock_port['device']])

    def test_remove_port_filter(self):
        mock_port = self._get_port()
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._security_ports[mock_port['device']] = mock_port
        self._driver.remove_port_filter(mock_port)
        self.assertNotIn(mock_port['device'], self._driver._security_ports)
        self.assertNotIn(mock_port['id'], self._driver._sec_group_rules)
        self._driver._utils.clear_port_sg_acls_cache(mock_port['id'])

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_add_sg_port_rules')
    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_remove_sg_port_rules')
    def test_create_port_rules(self, mock_remove, mock_add):
        mock_port = self._get_port()
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._sg_gen.create_security_group_rules.return_value = [
            mock_rule]
        self._driver._sg_gen.compute_new_rules_add.return_value = (
            [mock_rule, mock_rule], [mock_rule, mock_rule])

        self._driver._create_port_rules(mock_port, [mock_rule])

        self._driver._sg_gen.compute_new_rules_add.assert_called_once_with(
            [mock_rule], [mock_rule])
        mock_remove.assert_called_once_with(mock_port, [mock_rule])
        mock_add.assert_called_once_with(mock_port, [mock_rule])

    @mock.patch.object(sg_driver.HyperVSecurityGroupsDriver,
                       '_remove_sg_port_rules')
    def test_remove_port_rules(self, mock_remove):
        mock_port = self._get_port()
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._sg_gen.create_security_group_rules.return_value = [
            mock_rule]

        self._driver._remove_port_rules(mock_port, [mock_rule])

        mock_remove.assert_called_once_with(mock_port, [mock_rule])

    def test_add_sg_port_rules_exception(self):
        mock_port = self._get_port()
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = []
        self._driver._utils.create_security_rules.side_effect = (
            exceptions.HyperVException(msg='Generated Exception for testing.'))

        self.assertRaises(exceptions.HyperVException,
                          self._driver._add_sg_port_rules,
                          mock_port, [mock_rule])

        self.assertNotIn(mock_rule,
                         self._driver._sec_group_rules[self._FAKE_ID])

    def test_add_sg_port_rules_port_not_found(self):
        mock_port = self._get_port()
        self._driver._sec_group_rules[self._FAKE_ID] = []
        self._driver._security_ports[self._FAKE_DEVICE] = mock.sentinel.port
        self._driver._utils.create_security_rules.side_effect = (
            exceptions.NotFound(resource='port_id'))

        self.assertRaises(exceptions.NotFound,
                          self._driver._add_sg_port_rules,
                          mock_port, [mock.sentinel.rule])

        self.assertNotIn(self._FAKE_ID, self._driver._sec_group_rules)
        self.assertNotIn(self._FAKE_DEVICE, self._driver._security_ports)

    def test_add_sg_port_rules(self):
        mock_port = self._get_port()
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = []
        self._driver._add_sg_port_rules(mock_port, [mock_rule])

        self._driver._utils.create_security_rules.assert_called_once_with(
            self._FAKE_ID, [mock_rule])
        self.assertIn(mock_rule, self._driver._sec_group_rules[self._FAKE_ID])

    def test_add_sg_port_rules_empty(self):
        mock_port = self._get_port()
        self._driver._add_sg_port_rules(mock_port, [])
        self.assertFalse(self._driver._utils.create_security_rules.called)

    def test_remove_sg_port_rules_exception(self):
        mock_port = self._get_port()
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._utils.remove_security_rules.side_effect = (
            exceptions.HyperVException(msg='Generated Exception for testing.'))

        self.assertRaises(exceptions.HyperVException,
                          self._driver._remove_sg_port_rules,
                          mock_port, [mock_rule])

        self.assertIn(mock_rule, self._driver._sec_group_rules[self._FAKE_ID])

    def test_remove_sg_port_rules_port_not_found(self):
        mock_port = self._get_port()
        self._driver._sec_group_rules[self._FAKE_ID] = []
        self._driver._security_ports[self._FAKE_DEVICE] = mock.sentinel.port
        self._driver._utils.remove_security_rules.side_effect = (
            exceptions.NotFound(resource='port_id'))

        self.assertRaises(exceptions.NotFound,
                          self._driver._remove_sg_port_rules,
                          mock_port, [mock.sentinel.rule])

        self.assertNotIn(self._FAKE_ID, self._driver._sec_group_rules)
        self.assertNotIn(self._FAKE_DEVICE, self._driver._security_ports)

    def test_remove_sg_port_rules(self):
        mock_port = self._get_port()
        mock_rule = mock.MagicMock()
        self._driver._sec_group_rules[self._FAKE_ID] = [mock_rule]
        self._driver._remove_sg_port_rules(
            mock_port, [mock_rule, mock.sentinel.other_rule])

        self._driver._utils.remove_security_rules.assert_called_once_with(
            self._FAKE_ID, [mock_rule, mock.sentinel.other_rule])
        self.assertNotIn(mock_rule,
                         self._driver._sec_group_rules[self._FAKE_ID])

    def test_remove_sg_port_rules_empty(self):
        mock_port = self._get_port()
        self._driver._remove_sg_port_rules(mock_port, [])
        self.assertFalse(self._driver._utils.remove_security_rules.called)

    def _get_port(self):
        return {
            'device': self._FAKE_DEVICE,
            'id': self._FAKE_ID,
            'security_group_rules': [mock.MagicMock()],
            'port_security_enabled': True
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
        sg_rule4 = self._create_sg_rule(self._acl('protocol', 'ipv6-icmp'))

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

    def test_expand_wildcard_rules(self):
        egress_wildcard_rule = self._create_security_rule(
            protocol='ANY',
            direction='egress')
        ingress_wildcard_rule = self._create_security_rule(
            protocol='ANY',
            direction='ingress')
        normal_rule = self._create_security_rule()
        rules = [egress_wildcard_rule, ingress_wildcard_rule, normal_rule]

        actual_expanded_rules = self.sg_gen.expand_wildcard_rules(rules)

        expanded_rules = []
        for proto in sg_driver.ACL_PROP_MAP['protocol'].keys():
            expanded_rules.extend(
                [self._create_security_rule(protocol=proto,
                                            direction='egress'),
                 self._create_security_rule(protocol=proto,
                                            direction='ingress')])
        diff_expanded_rules = [r for r in expanded_rules
                               if r not in actual_expanded_rules]
        self.assertEqual([], diff_expanded_rules)

    def test_expand_no_wildcard_rules(self):
        normal_rule = self._create_security_rule(direction='egress')
        another_normal_rule = self._create_security_rule(direction='ingress')

        actual_expanded_rules = self.sg_gen.expand_wildcard_rules(
            [normal_rule, another_normal_rule])

        self.assertEqual([], actual_expanded_rules)

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

    def test_get_rule_protocol_icmp_ipv6(self):
        self._check_get_rule_protocol(
            expected=self._acl('protocol', 'ipv6-icmp'),
            protocol='icmp',
            ethertype='IPv6')

    def test_get_rule_protocol_icmp(self):
        self._check_get_rule_protocol(expected=self._acl('protocol', 'icmp'),
                                      protocol='icmp')

    def test_get_rule_protocol_no_icmp(self):
        self._check_get_rule_protocol(expected='tcp',
                                      protocol='tcp')

    def _check_get_rule_protocol(self, expected, **rule_updates):
        rule = self._create_security_rule(**rule_updates)
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

    def test_stateful_ipv6_icmp(self):
        sg_rule = self._create_sg_rule(self._acl('protocol', 'ipv6-icmp'))
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
