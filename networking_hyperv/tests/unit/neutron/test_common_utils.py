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

import mock

from networking_hyperv.neutron import _common_utils
from networking_hyperv.tests import base


class TestCommonUtils(base.BaseTestCase):

    @mock.patch.object(_common_utils.lockutils, 'synchronized_with_prefix')
    def test_create_synchronized_decorator(self, mock_sync_with_prefix):
        fake_method_side_effect = mock.Mock()
        lock_prefix = 'test-'
        port_synchronized = _common_utils.get_port_synchronized_decorator(
            lock_prefix)

        @port_synchronized
        def fake_method(fake_arg, port_id):
            fake_method_side_effect(fake_arg, port_id)

        mock_synchronized = mock_sync_with_prefix.return_value
        mock_synchronized.return_value = lambda x: x
        expected_lock_name = 'test-port-lock-%s' % mock.sentinel.port_id

        fake_method(fake_arg=mock.sentinel.arg, port_id=mock.sentinel.port_id)
        mock_sync_with_prefix.assert_called_once_with(lock_prefix)
        mock_synchronized.assert_called_once_with(expected_lock_name)
        fake_method_side_effect.assert_called_once_with(
            mock.sentinel.arg, mock.sentinel.port_id)
