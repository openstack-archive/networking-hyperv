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
Unit tests for the Hyper-V Trunk Driver.
"""

import mock
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.handlers import resources_rpc
from neutron.services.trunk import constants as t_const
from os_win import constants as os_win_const
import oslo_messaging
import testtools

from networking_hyperv.neutron import trunk_driver
from networking_hyperv.tests import base


class TestHyperVTrunkDriver(base.HyperVBaseTestCase):

    @mock.patch.object(trunk_driver.trunk_rpc, 'TrunkStub',
                       lambda *args, **kwargs: None)
    @mock.patch.object(trunk_driver.trunk_rpc.TrunkSkeleton, '__init__',
                       lambda *args, **kwargs: None)
    def setUp(self):
        super(TestHyperVTrunkDriver, self).setUp()

        self.trunk_driver = trunk_driver.HyperVTrunkDriver(
            mock.sentinel.context)
        self.trunk_driver._utils = mock.MagicMock()
        self.trunk_driver._trunk_rpc = mock.MagicMock()

    def test_handle_trunks_deleted(self):
        mock_trunk = mock.MagicMock()
        self.trunk_driver._trunks[mock_trunk.id] = mock_trunk

        self.trunk_driver.handle_trunks([mock_trunk], events.DELETED)
        self.assertNotIn(mock_trunk.id, self.trunk_driver._trunks)

    @mock.patch.object(trunk_driver.HyperVTrunkDriver, '_setup_trunk')
    def test_handle_trunks_created(self, mock_setup_trunk):
        sub_ports = []
        mock_trunk = mock.MagicMock(sub_ports=sub_ports)

        self.trunk_driver.handle_trunks([mock_trunk], events.CREATED)

        self.assertEqual(mock_trunk, self.trunk_driver._trunks[mock_trunk.id])
        mock_setup_trunk.assert_called_once_with(mock_trunk)

    @mock.patch.object(trunk_driver.HyperVTrunkDriver, '_set_port_vlan')
    @mock.patch.object(trunk_driver.HyperVTrunkDriver, '_fetch_trunk')
    def test_bind_vlan_port_not_trunk(self, mock_fetch_trunk, mock_set_vlan):
        mock_fetch_trunk.return_value = None

        self.trunk_driver.bind_vlan_port(mock.sentinel.port_id,
                                         mock.sentinel.segmentation_id)

        mock_fetch_trunk.assert_called_once_with(mock.sentinel.port_id)
        mock_set_vlan.assert_called_once_with(mock.sentinel.port_id,
                                              mock.sentinel.segmentation_id)

    @mock.patch.object(trunk_driver.HyperVTrunkDriver, '_setup_trunk')
    @mock.patch.object(trunk_driver.HyperVTrunkDriver, '_fetch_trunk')
    def test_bind_vlan_port(self, mock_fetch_trunk, mock_setup_trunk):
        self.trunk_driver.bind_vlan_port(mock.sentinel.port_id,
                                         mock.sentinel.segmentation_id)

        mock_fetch_trunk.assert_called_once_with(mock.sentinel.port_id)
        mock_setup_trunk.assert_called_once_with(mock_fetch_trunk.return_value,
                                                 mock.sentinel.segmentation_id)

    def test_fetch_trunk(self):
        mock_trunk = (
            self.trunk_driver._trunk_rpc.get_trunk_details.return_value)

        trunk = self.trunk_driver._fetch_trunk(mock.sentinel.port_id,
                                               mock.sentinel.context)

        self.assertEqual(mock_trunk, trunk)
        self.assertEqual(mock_trunk, self.trunk_driver._trunks[mock_trunk.id])
        self.trunk_driver._trunk_rpc.get_trunk_details.assert_called_once_with(
            mock.sentinel.context, mock.sentinel.port_id)

    def test_fetch_trunk_resource_not_found(self):
        self.trunk_driver._trunk_rpc.get_trunk_details.side_effect = (
            resources_rpc.ResourceNotFound)

        trunk = self.trunk_driver._fetch_trunk(mock.sentinel.port_id)
        self.assertIsNone(trunk)

    def test_fetch_trunk_resource_remote_error(self):
        self.trunk_driver._trunk_rpc.get_trunk_details.side_effect = (
            oslo_messaging.RemoteError('expected CallbackNotFound'))

        trunk = self.trunk_driver._fetch_trunk(mock.sentinel.port_id)
        self.assertIsNone(trunk)

    def test_fetch_trunk_resource_remote_error_reraised(self):
        self.trunk_driver._trunk_rpc.get_trunk_details.side_effect = (
            oslo_messaging.RemoteError)

        self.assertRaises(oslo_messaging.RemoteError,
                          self.trunk_driver._fetch_trunk,
                          mock.sentinel.port_id)

    @mock.patch.object(trunk_driver.HyperVTrunkDriver, '_set_port_vlan')
    def test_setup_trunk(self, mock_set_vlan):
        mock_subport = mock.MagicMock()
        mock_trunk = mock.MagicMock(sub_ports=[mock_subport])
        trunk_rpc = self.trunk_driver._trunk_rpc
        trunk_rpc.update_trunk_status.side_effect = [
            testtools.ExpectedException, None]

        self.trunk_driver._setup_trunk(mock_trunk, mock.sentinel.vlan_id)

        trunk_rpc.update_subport_bindings.assert_called_once_with(
            self.trunk_driver._context, [mock_subport])
        mock_set_vlan.assert_called_once_with(
            mock_trunk.port_id, mock.sentinel.vlan_id,
            [mock_subport.segmentation_id])
        mock_set_vlan.has_calls([
            mock.call(self.trunk_driver._context, mock_trunk.id, status)
            for status in [t_const.ACTIVE_STATUS, t_const.DEGRADED_STATUS]])

    def _check_set_port_vlan(self, vlan_trunk, operation_mode):
        self.trunk_driver._set_port_vlan(mock.sentinel.port_id,
                                         mock.sentinel.vlan_id,
                                         vlan_trunk)

        self.trunk_driver._utils.set_vswitch_port_vlan_id(
            mock.sentinel.vlan_id, mock.sentinel.port_id,
            operation_mode=operation_mode,
            vlan_trunk=vlan_trunk)

    def test_set_port_vlan_trunk_mode(self):
        self._check_set_port_vlan(mock.sentinel.vlan_trunk,
                                  os_win_const.VLAN_MODE_TRUNK)

    def test_set_port_vlan_access_mode(self):
        self._check_set_port_vlan(None, os_win_const.VLAN_MODE_ACCESS)
