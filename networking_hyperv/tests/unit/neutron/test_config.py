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
Unit tests for the networking-hyperv config module.
"""

from unittest import mock

from networking_hyperv.neutron import config
from networking_hyperv.tests import base


class TestConfig(base.HyperVBaseTestCase):

    @mock.patch.object(config, 'ks_loading')
    @mock.patch.object(config, 'CONF')
    def test_register_opts(self, mock_CONF, mock_ks_loading):
        config.register_opts()

        all_groups = [pair[0] for pair in config.ALL_OPTS]
        mock_CONF.register_group.assert_has_calls([
            mock.call(group) for group in all_groups])

        mock_CONF.register_opts.assert_has_calls([
            mock.call(opts, group=group) for group, opts in config.ALL_OPTS])

        mock_ks_loading.register_session_conf_options.assert_called_once_with(
            mock_CONF, config.NEUTRON_GROUP)
        mock_ks_loading.register_auth_conf_options.assert_called_once_with(
            mock_CONF, config.NEUTRON_GROUP)
