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
Unit tests for the Hyper-V Mechanism Driver.
"""

import mock

from networking_hyperv.neutron import constants
from networking_hyperv.neutron.ml2 import mech_hyperv
from networking_hyperv.tests import base


class TestHypervMechanismDriver(base.BaseTestCase):

    def setUp(self):
        super(TestHypervMechanismDriver, self).setUp()
        self.mech_hyperv = mech_hyperv.HypervMechanismDriver()

    def test_get_allowed_network_types(self):
        agent = {'configurations': {'tunnel_types': []}}
        actual_net_types = self.mech_hyperv.get_allowed_network_types(agent)

        network_types = [constants.TYPE_LOCAL, constants.TYPE_FLAT,
                         constants.TYPE_VLAN]
        self.assertEqual(network_types, actual_net_types)

    def test_get_allowed_network_types_nvgre(self):
        agent = {'configurations': {'tunnel_types': [constants.TYPE_NVGRE]}}
        actual_net_types = self.mech_hyperv.get_allowed_network_types(agent)

        network_types = [constants.TYPE_LOCAL, constants.TYPE_FLAT,
                         constants.TYPE_VLAN, constants.TYPE_NVGRE]
        self.assertEqual(network_types, actual_net_types)

    def test_get_mappings(self):
        agent = {'configurations': {
            'vswitch_mappings': [mock.sentinel.mapping]}}
        mappings = self.mech_hyperv.get_mappings(agent)
        self.assertEqual([mock.sentinel.mapping], mappings)

    def test_physnet_in_mappings(self):
        physnet = 'test_physnet'
        match_mapping = '.*'
        different_mapping = 'fake'

        pattern_matched = self.mech_hyperv.physnet_in_mappings(
            physnet, [match_mapping])
        self.assertTrue(pattern_matched)

        pattern_matched = self.mech_hyperv.physnet_in_mappings(
            physnet, [different_mapping])
        self.assertFalse(pattern_matched)

        pattern_matched = self.mech_hyperv.physnet_in_mappings(
            physnet, [different_mapping, match_mapping])
        self.assertTrue(pattern_matched)
