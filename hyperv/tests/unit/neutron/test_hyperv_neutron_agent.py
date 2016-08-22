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

"""
Unit tests for Windows Hyper-V virtual switch neutron driver
"""

from concurrent import futures
import time

import mock
from os_win import exceptions
from os_win import utilsfactory
from oslo_config import cfg

from hyperv.neutron import constants
from hyperv.neutron import exception
from hyperv.neutron import hyperv_neutron_agent
from hyperv.tests import base

CONF = cfg.CONF


class TestHyperVNeutronAgent(base.BaseTestCase):

    _FAKE_PORT_ID = 'fake_port_id'

    def setUp(self):
        super(TestHyperVNeutronAgent, self).setUp()
        utilsfactory_patcher = mock.patch.object(utilsfactory, '_get_class')
        utilsfactory_patcher.start()
        self.addCleanup(utilsfactory_patcher.stop)

        self.agent = hyperv_neutron_agent.HyperVNeutronAgentMixin()
        self.agent.plugin_rpc = mock.Mock()
        self.agent._metricsutils = mock.MagicMock()
        self.agent._utils = mock.MagicMock()
        self.agent.sec_groups_agent = mock.MagicMock()
        self.agent.context = mock.Mock()
        self.agent.client = mock.MagicMock()
        self.agent.connection = mock.MagicMock()
        self.agent.agent_id = mock.Mock()
        self.agent.notifier = mock.Mock()
        self.agent._utils = mock.MagicMock()
        self.agent._nvgre_ops = mock.MagicMock()
        self.agent._workers = mock.MagicMock()

    def test_load_physical_network_mappings(self):
        test_mappings = ['fakenetwork1:fake_vswitch',
                         'fakenetwork2:fake_vswitch_2', '*:fake_vswitch_3',
                         'bad_mapping']
        expected = [('fakenetwork1$', 'fake_vswitch'),
                    ('fakenetwork2$', 'fake_vswitch_2'),
                    ('.*$', 'fake_vswitch_3')]

        self.agent._load_physical_network_mappings(test_mappings)

        self.assertEqual(expected,
                         list(self.agent._physical_network_mappings.items()))

    def test_get_vswitch_for_physical_network_with_default_switch(self):
        test_mappings = ['fakenetwork:fake_vswitch',
                         'fakenetwork2$:fake_vswitch_2',
                         'fakenetwork*:fake_vswitch_3']
        self.agent._load_physical_network_mappings(test_mappings)

        physnet = self.agent._get_vswitch_for_physical_network('fakenetwork')
        self.assertEqual('fake_vswitch', physnet)

        physnet = self.agent._get_vswitch_for_physical_network('fakenetwork2$')
        self.assertEqual('fake_vswitch_2', physnet)

        physnet = self.agent._get_vswitch_for_physical_network('fakenetwork3')
        self.assertEqual('fake_vswitch_3', physnet)

        physnet = self.agent._get_vswitch_for_physical_network('fakenetwork35')
        self.assertEqual('fake_vswitch_3', physnet)

        physnet = self.agent._get_vswitch_for_physical_network('fake_network1')
        self.assertEqual('fake_network1', physnet)

    def test_get_vswitch_for_physical_network_without_default_switch(self):
        test_mappings = ['fakenetwork:fake_vswitch',
                         'fakenetwork2:fake_vswitch_2']
        self.agent._load_physical_network_mappings(test_mappings)

        physnet = self.agent._get_vswitch_for_physical_network('fakenetwork')
        self.assertEqual('fake_vswitch', physnet)

        physnet = self.agent._get_vswitch_for_physical_network('fakenetwork2')
        self.assertEqual('fake_vswitch_2', physnet)

    def test_get_vswitch_for_physical_network_none(self):
        test_mappings = ['fakenetwork:fake_vswitch',
                         'fakenetwork2:fake_vswitch_2']
        self.agent._load_physical_network_mappings(test_mappings)

        physnet = self.agent._get_vswitch_for_physical_network(None)
        self.assertEqual('', physnet)

        test_mappings = ['fakenetwork:fake_vswitch',
                         'fakenetwork2:fake_vswitch_2', '*:fake_vswitch_3']
        self.agent._load_physical_network_mappings(test_mappings)

        physnet = self.agent._get_vswitch_for_physical_network(None)
        self.assertEqual('fake_vswitch_3', physnet)

    @mock.patch.object(hyperv_neutron_agent.nvgre_ops, 'HyperVNvgreOps')
    def test_init_nvgre_disabled(self, mock_hyperv_nvgre_ops):
        self.agent._init_nvgre()
        self.assertFalse(mock_hyperv_nvgre_ops.called)
        self.assertFalse(self.agent._nvgre_enabled)

    @mock.patch.object(hyperv_neutron_agent.nvgre_ops, 'HyperVNvgreOps')
    def test_init_nvgre_no_tunnel_ip(self, mock_hyperv_nvgre_ops):
        self.config(enable_support=True, group='NVGRE')
        self.assertRaises(exception.NetworkingHyperVException,
                          self.agent._init_nvgre)

    @mock.patch.object(hyperv_neutron_agent.nvgre_ops, 'HyperVNvgreOps')
    def test_init_nvgre_enabled(self, mock_hyperv_nvgre_ops):
        self.config(enable_support=True, group='NVGRE')
        self.config(provider_tunnel_ip=mock.sentinel.tunneling_ip,
                    group='NVGRE')
        self.agent._init_nvgre()
        mock_hyperv_nvgre_ops.assert_called_once_with(
            list(self.agent._physical_network_mappings.values()))

        self.assertTrue(self.agent._nvgre_enabled)
        self.agent._nvgre_ops.init_notifier.assert_called_once_with(
            self.agent.context, self.agent.client)

    def test_get_network_vswitch_map_by_port_id(self):
        net_uuid = 'net-uuid'
        self.agent._network_vswitch_map = {
            net_uuid: {'ports': [self._FAKE_PORT_ID]}
        }

        network, port_map = self.agent._get_network_vswitch_map_by_port_id(
            self._FAKE_PORT_ID)

        self.assertEqual(net_uuid, network)
        self.assertEqual({'ports': [self._FAKE_PORT_ID]}, port_map)

    def test_get_network_vswitch_map_by_port_id_not_found(self):
        net_uuid = 'net-uuid'
        self.agent._network_vswitch_map = {net_uuid: {'ports': []}}

        network, port_map = self.agent._get_network_vswitch_map_by_port_id(
            self._FAKE_PORT_ID)

        self.assertIsNone(network)
        self.assertIsNone(port_map)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_reclaim_local_network')
    def test_network_delete(self, mock_reclaim_local_network):
        self.agent._network_vswitch_map[mock.sentinel.net_id] = (
            mock.sentinel.vswitch)

        self.agent.network_delete(mock.sentinel.context, mock.sentinel.net_id)
        mock_reclaim_local_network.assert_called_once_with(
            mock.sentinel.net_id)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_reclaim_local_network')
    def test_network_delete_not_defined(self, mock_reclaim_local_network):
        self.agent.network_delete(mock.sentinel.context, mock.sentinel.net_id)
        self.assertFalse(mock_reclaim_local_network.called)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_treat_vif_port')
    def test_port_update_not_found(self, mock_treat_vif_port):
        self.agent._utils.vnic_port_exists.return_value = False
        port = {'id': mock.sentinel.port_id}
        self.agent.port_update(self.agent.context, port)

        self.assertFalse(mock_treat_vif_port.called)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_treat_vif_port')
    def test_port_update(self, mock_treat_vif_port):
        self.agent._utils.vnic_port_exists.return_value = True
        port = {'id': mock.sentinel.port_id,
                'network_id': mock.sentinel.network_id,
                'admin_state_up': mock.sentinel.admin_state_up}

        self.agent.port_update(self.agent.context, port,
                               mock.sentinel.network_type,
                               mock.sentinel.segmentation_id,
                               mock.sentinel.physical_network)

        mock_treat_vif_port.assert_called_once_with(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, mock.sentinel.admin_state_up)

    def test_tunnel_update(self):
        self.agent.tunnel_update(mock.sentinel.context,
                                 tunnel_ip=mock.sentinel.tunnel_ip,
                                 tunnel_type=mock.sentinel.tunnel_type)
        self.agent._nvgre_ops.tunnel_update.assert_called_once_with(
            mock.sentinel.context, mock.sentinel.tunnel_ip,
            mock.sentinel.tunnel_type)

    def test_tunnel_update_provider_ip(self):
        self.agent.tunnel_update(mock.sentinel.context,
                                 tunnel_ip=CONF.NVGRE.provider_tunnel_ip)
        self.assertFalse(self.agent._nvgre_ops.tunnel_update.called)

    def test_lookup_update(self):
        kwargs = {'lookup_ip': mock.sentinel.lookup_ip,
                  'lookup_details': mock.sentinel.lookup_details}

        self.agent.lookup_update(mock.sentinel.context, **kwargs)

        self.agent._nvgre_ops.lookup_update.assert_called_once_with(kwargs)

    def test_get_vswitch_name_local(self):
        self.agent._local_network_vswitch = 'test_local_switch'
        ret = self.agent._get_vswitch_name(constants.TYPE_LOCAL,
                                           mock.sentinel.FAKE_PHYSICAL_NETWORK)

        self.assertEqual('test_local_switch', ret)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       "_get_vswitch_for_physical_network")
    def test_get_vswitch_name_vlan(self, mock_get_vswitch_for_phys_net):
        ret = self.agent._get_vswitch_name(constants.TYPE_VLAN,
                                           mock.sentinel.FAKE_PHYSICAL_NETWORK)

        self.assertEqual(mock_get_vswitch_for_phys_net.return_value, ret)
        mock_get_vswitch_for_phys_net.assert_called_once_with(
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       "_get_vswitch_name")
    def test_provision_network_exception(self, mock_get_vswitch_name):
        self.assertRaises(exception.NetworkingHyperVException,
                          self.agent._provision_network,
                          mock.sentinel.FAKE_PORT_ID,
                          mock.sentinel.FAKE_NET_UUID,
                          mock.sentinel.FAKE_NETWORK_TYPE,
                          mock.sentinel.FAKE_PHYSICAL_NETWORK,
                          mock.sentinel.FAKE_SEGMENTATION_ID)
        mock_get_vswitch_name.assert_called_once_with(
            mock.sentinel.FAKE_NETWORK_TYPE,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       "_get_vswitch_name")
    def test_provision_network_vlan(self, mock_get_vswitch_name):
        self.agent._provision_network(mock.sentinel.FAKE_PORT_ID,
                                      mock.sentinel.FAKE_NET_UUID,
                                      constants.TYPE_VLAN,
                                      mock.sentinel.FAKE_PHYSICAL_NETWORK,
                                      mock.sentinel.FAKE_SEGMENTATION_ID)
        mock_get_vswitch_name.assert_called_once_with(
            constants.TYPE_VLAN,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       "_get_vswitch_name")
    def test_provision_network_nvgre(self, mock_get_vswitch_name):
        self.agent._nvgre_enabled = True
        vswitch_name = mock_get_vswitch_name.return_value
        self.agent._provision_network(mock.sentinel.FAKE_PORT_ID,
                                      mock.sentinel.FAKE_NET_UUID,
                                      constants.TYPE_NVGRE,
                                      mock.sentinel.FAKE_PHYSICAL_NETWORK,
                                      mock.sentinel.FAKE_SEGMENTATION_ID)

        mock_get_vswitch_name.assert_called_once_with(
            constants.TYPE_NVGRE,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)
        self.agent._nvgre_ops.bind_nvgre_network.assert_called_once_with(
            mock.sentinel.FAKE_SEGMENTATION_ID,
            mock.sentinel.FAKE_NET_UUID,
            vswitch_name)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       "_get_vswitch_name")
    def test_provision_network_flat(self, mock_get_vswitch_name):
        self.agent._provision_network(mock.sentinel.FAKE_PORT_ID,
                                      mock.sentinel.FAKE_NET_UUID,
                                      constants.TYPE_FLAT,
                                      mock.sentinel.FAKE_PHYSICAL_NETWORK,
                                      mock.sentinel.FAKE_SEGMENTATION_ID)
        mock_get_vswitch_name.assert_called_once_with(
            constants.TYPE_FLAT,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       "_get_vswitch_name")
    def test_provision_network_local(self, mock_get_vswitch_name):
        self.agent._provision_network(mock.sentinel.FAKE_PORT_ID,
                                      mock.sentinel.FAKE_NET_UUID,
                                      constants.TYPE_LOCAL,
                                      mock.sentinel.FAKE_PHYSICAL_NETWORK,
                                      mock.sentinel.FAKE_SEGMENTATION_ID)
        mock_get_vswitch_name.assert_called_once_with(
            constants.TYPE_LOCAL,
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    def test_reclaim_local_network(self):
        self.agent._network_vswitch_map[mock.sentinel.net_id] = (
            mock.sentinel.vswitch)

        self.agent._reclaim_local_network(mock.sentinel.net_id)
        self.assertNotIn(mock.sentinel.net_id, self.agent._network_vswitch_map)

    def test_port_bound_enable_metrics(self):
        self.agent.enable_metrics_collection = True
        self._test_port_bound(True)

    def test_port_bound_no_metrics(self):
        self.agent.enable_metrics_collection = False
        self._test_port_bound(False)

    def _test_port_bound(self, enable_metrics):
        port = mock.MagicMock()
        net_uuid = 'my-net-uuid'

        self.agent._port_bound(port, net_uuid, 'vlan', None, None)

        self.assertEqual(enable_metrics,
                         self.agent._utils.add_metrics_collection_acls.called)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_provision_network')
    def test_port_bound_nvgre(self, mock_provision_network):
        self.agent._nvgre_enabled = True
        network_type = constants.TYPE_NVGRE
        net_uuid = 'my-net-uuid'
        fake_map = {'vswitch_name': mock.sentinel.vswitch_name,
                    'ports': []}

        def fake_prov_network(*args, **kwargs):
            self.agent._network_vswitch_map[net_uuid] = fake_map

        mock_provision_network.side_effect = fake_prov_network

        self.agent._port_bound(mock.sentinel.port_id, net_uuid, network_type,
                               mock.sentinel.physical_network,
                               mock.sentinel.segmentation_id)

        self.assertIn(mock.sentinel.port_id, fake_map['ports'])
        mock_provision_network.assert_called_once_with(
            mock.sentinel.port_id, net_uuid, network_type,
            mock.sentinel.physical_network, mock.sentinel.segmentation_id)
        self.agent._utils.connect_vnic_to_vswitch.assert_called_once_with(
            mock.sentinel.vswitch_name, mock.sentinel.port_id)
        self.agent._nvgre_ops.bind_nvgre_port.assert_called_once_with(
            mock.sentinel.segmentation_id, mock.sentinel.vswitch_name,
            mock.sentinel.port_id)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_get_network_vswitch_map_by_port_id')
    def _check_port_unbound(self, mock_get_vswitch_map_by_port_id, ports=None,
                            net_uuid=None):
        map = {
            'network_type': 'vlan',
            'vswitch_name': 'fake-vswitch',
            'ports': ports,
            'vlan_id': 1}
        network_vswitch_map = (net_uuid, map)
        mock_get_vswitch_map_by_port_id.return_value = network_vswitch_map

        with mock.patch.object(
                self.agent._utils,
                'remove_switch_port') as mock_remove_switch_port:
            self.agent._port_unbound(self._FAKE_PORT_ID, vnic_deleted=False)

            if net_uuid:
                mock_remove_switch_port.assert_called_once_with(
                    self._FAKE_PORT_ID, False)
            else:
                self.assertFalse(mock_remove_switch_port.called)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_reclaim_local_network')
    def test_port_unbound(self, mock_reclaim_local_network):
        net_uuid = 'my-net-uuid'
        self._check_port_unbound(ports=[self._FAKE_PORT_ID],
                                 net_uuid=net_uuid)
        mock_reclaim_local_network.assert_called_once_with(net_uuid)

    def test_port_unbound_port_not_found(self):
        self._check_port_unbound()

    def test_port_enable_control_metrics_ok(self):
        self.agent.enable_metrics_collection = True
        self.agent._port_metric_retries[self._FAKE_PORT_ID] = (
            self.agent._metrics_max_retries)

        self.agent._utils.is_metrics_collection_allowed.return_value = True
        self.agent._port_enable_control_metrics()

        enable_port_metrics_collection = (
            self.agent._metricsutils.enable_port_metrics_collection)
        enable_port_metrics_collection.assert_called_with(self._FAKE_PORT_ID)
        self.assertNotIn(self._FAKE_PORT_ID, self.agent._port_metric_retries)

    def test_port_enable_control_metrics_maxed(self):
        self.agent.enable_metrics_collection = True
        self.agent._metrics_max_retries = 3
        self.agent._port_metric_retries[self._FAKE_PORT_ID] = 3

        self.agent._utils.is_metrics_collection_allowed.return_value = False
        for i in range(4):
            self.assertIn(self._FAKE_PORT_ID,
                          self.agent._port_metric_retries)
            self.agent._port_enable_control_metrics()

        self.assertNotIn(self._FAKE_PORT_ID, self.agent._port_metric_retries)

    def test_port_enable_control_metrics_no_vnic(self):
        self.agent.enable_metrics_collection = True
        self.agent._port_metric_retries[self._FAKE_PORT_ID] = 3
        self.agent._utils.is_metrics_collection_allowed.side_effect = (
            exceptions.NotFound(resource=self._FAKE_PORT_ID))

        self.agent._port_enable_control_metrics()
        self.assertNotIn(self._FAKE_PORT_ID, self.agent._port_metric_retries)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_port_unbound')
    def test_vif_port_state_down(self, mock_port_unbound):
        self.agent._treat_vif_port(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, False)

        mock_port_unbound.assert_called_once_with(mock.sentinel.port_id)
        sg_agent = self.agent.sec_groups_agent
        sg_agent.remove_devices_filter.assert_called_once_with(
            [mock.sentinel.port_id])

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_port_bound')
    def _check_treat_vif_port_state_up(self, mock_port_bound):
        self.agent._treat_vif_port(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, True)

        mock_port_bound.assert_called_once_with(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id)

    def test_treat_vif_port_sg_enabled(self):
        self.agent.enable_security_groups = True
        self._check_treat_vif_port_state_up()

        sg_agent = self.agent.sec_groups_agent
        sg_agent.refresh_firewall.assert_called_once_with(
            [mock.sentinel.port_id])

    def test_treat_vif_port_sg_disabled(self):
        self.agent.enable_security_groups = False
        self._check_treat_vif_port_state_up()
        self.agent._utils.remove_all_security_rules.assert_called_once_with(
            mock.sentinel.port_id)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_treat_vif_port')
    def test_process_added_port(self, mock_treat_vif_port):
        self.agent._added_ports = set()
        details = self._get_fake_port_details()

        self.agent._process_added_port(details)

        mock_treat_vif_port.assert_called_once_with(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, mock.sentinel.admin_state_up)
        self.agent.plugin_rpc.update_device_up.assert_called_once_with(
            self.agent.context, mock.sentinel.device,
            self.agent.agent_id, self.agent._host)
        self.assertNotIn(mock.sentinel.device, self.agent._added_ports)

    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_treat_vif_port')
    def test_process_added_port_failed(self, mock_treat_vif_port):
        mock_treat_vif_port.side_effect = exception.NetworkingHyperVException
        self.agent._added_ports = set()
        details = self._get_fake_port_details()

        self.agent._process_added_port(details)
        self.assertIn(mock.sentinel.device, self.agent._added_ports)

    def _get_fake_port_details(self):
        return {'device': mock.sentinel.device,
                'port_id': mock.sentinel.port_id,
                'network_id': mock.sentinel.network_id,
                'network_type': mock.sentinel.network_type,
                'physical_network': mock.sentinel.physical_network,
                'segmentation_id': mock.sentinel.segmentation_id,
                'admin_state_up': mock.sentinel.admin_state_up}

    def test_treat_devices_added_returns_true_for_missing_device(self):
        self.agent._added_ports = set([mock.sentinel.port_id])
        attrs = {'get_devices_details_list.side_effect': Exception()}
        self.agent.plugin_rpc.configure_mock(**attrs)
        self.agent._treat_devices_added()

        self.assertIn(mock.sentinel.port_id, self.agent._added_ports)

    def test_treat_devices_added_updates_known_port(self):
        self.agent._added_ports = set([mock.sentinel.device])
        details = self._get_fake_port_details()
        attrs = {'get_devices_details_list.return_value': [details]}
        self.agent.plugin_rpc.configure_mock(**attrs)

        self.agent._treat_devices_added()

        self.agent._workers.submit.assert_called_once_with(
            self.agent._process_added_port, details)
        self.assertNotIn(mock.sentinel.device, self.agent._added_ports)

    def test_treat_devices_added_missing_port_id(self):
        self.agent._added_ports = set([mock.sentinel.port_id])
        details = {'device': mock.sentinel.port_id}
        attrs = {'get_devices_details_list.return_value': [details]}
        self.agent.plugin_rpc.configure_mock(**attrs)

        self.agent._treat_devices_added()

        self.assertFalse(self.agent._workers.submit.called)
        self.assertNotIn(mock.sentinel.port_id, self.agent._added_ports)

    def test_treat_devices_removed_exception(self):
        self.agent._removed_ports = set([mock.sentinel.port_id])
        attrs = {'update_device_down.side_effect': Exception()}
        self.agent.plugin_rpc.configure_mock(**attrs)
        self.agent._treat_devices_removed()

        self.agent.plugin_rpc.update_device_down.assert_called_once_with(
            self.agent.context, mock.sentinel.port_id,
            self.agent.agent_id, self.agent._host)
        self.assertIn(mock.sentinel.port_id, self.agent._removed_ports)

    def mock_treat_devices_removed(self, port_exists):
        self.agent._removed_ports = set([mock.sentinel.port_id])
        details = dict(exists=port_exists)
        attrs = {'update_device_down.return_value': details}
        self.agent.plugin_rpc.configure_mock(**attrs)
        with mock.patch.object(self.agent, '_port_unbound') as func:
            self.agent._treat_devices_removed()
        self.assertEqual(func.called, not port_exists)
        self.assertEqual(
            self.agent.sec_groups_agent.remove_devices_filter.called,
            not port_exists)
        self.assertNotIn(mock.sentinel.port_id, self.agent._removed_ports)

    def test_treat_devices_removed_unbinds_port(self):
        self.mock_treat_devices_removed(False)

    def test_treat_devices_removed_ignores_missing_port(self):
        self.mock_treat_devices_removed(False)

    def test_process_added_port_event(self):
        self.agent._added_ports = set()
        self.agent._process_added_port_event(mock.sentinel.port_id)
        self.assertIn(mock.sentinel.port_id, self.agent._added_ports)

    def test_process_removed_port_event(self):
        self.agent._removed_ports = set([])
        self.agent._process_removed_port_event(mock.sentinel.port_id)
        self.assertIn(mock.sentinel.port_id, self.agent._removed_ports)

    @mock.patch.object(hyperv_neutron_agent.threading, 'Thread')
    def test_create_event_listeners(self, mock_Thread):
        self.agent._create_event_listeners()

        self.agent._utils.get_vnic_event_listener.assert_has_calls([
            mock.call(self.agent._utils.EVENT_TYPE_CREATE),
            mock.call(self.agent._utils.EVENT_TYPE_DELETE)])
        target = self.agent._utils.get_vnic_event_listener.return_value
        calls = [mock.call(target=target,
                           args=(self.agent._process_added_port_event, )),
                 mock.call(target=target,
                           args=(self.agent._process_removed_port_event, ))]
        mock_Thread.assert_has_calls(calls, any_order=True)
        self.assertEqual(2, mock_Thread.return_value.start.call_count)

    def test_thread_pool_execution(self):
        pool = futures.ThreadPoolExecutor(max_workers=3)
        mock_fn = mock.MagicMock()

        for i in range(8):
            pool.submit(mock_fn, mock.sentinel.parameter)

        # allow the threads to finish. one second is enough for a noop call.
        time.sleep(1)
        mock_fn.assert_has_calls([mock.call(mock.sentinel.parameter)] * 8)

    @mock.patch('time.sleep')
    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_port_enable_control_metrics')
    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_treat_devices_added')
    @mock.patch.object(hyperv_neutron_agent.HyperVNeutronAgentMixin,
                       '_create_event_listeners')
    def test_daemon_loop(self, mock_create_listeners, mock_treat_dev_added,
                         mock_port_enable_metrics, mock_sleep):
        self.agent._nvgre_enabled = True
        mock_port_enable_metrics.side_effect = KeyError
        mock_sleep.side_effect = KeyboardInterrupt

        self.assertRaises(KeyboardInterrupt, self.agent.daemon_loop)

        self.assertEqual(self.agent._utils.get_vnic_ids.return_value,
                         self.agent._added_ports)
        self.assertEqual(set(), self.agent._removed_ports)
        mock_create_listeners.assert_called_once_with()
        mock_treat_dev_added.assert_called_once_with()
        self.agent._nvgre_ops.refresh_nvgre_records.assert_called_once_with()
        mock_port_enable_metrics.assert_called_with()
        self.agent._utils.update_cache.assert_called_once_with()
