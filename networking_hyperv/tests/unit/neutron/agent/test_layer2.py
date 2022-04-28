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
Unit tests for Neutron layer 2 agent.
"""
import collections
import eventlet
from unittest import mock

import ddt
import neutron
from neutron.conf.agent import common as neutron_config
from neutron_lib.agent import topics
from neutron_lib import rpc as n_rpc
from os_win import constants as os_win_const
from os_win import exceptions as os_win_exc

from networking_hyperv.neutron.agent import layer2 as agent_base
from networking_hyperv.neutron import config
from networking_hyperv.neutron import constants
from networking_hyperv.neutron import exception
from networking_hyperv.tests import base as test_base

CONF = config.CONF


class _Layer2Agent(agent_base.Layer2Agent):

    def _get_agent_configurations(self):
        pass

    def _report_state(self):
        pass

    def _provision_network(self, port_id, net_uuid, network_type,
                           physical_network, segmentation_id):
        pass


@ddt.ddt
class TestLayer2Agent(test_base.HyperVBaseTestCase):

    _FAKE_PORT_ID = 'fake_port_id'

    @mock.patch.object(_Layer2Agent, "_setup")
    @mock.patch.object(_Layer2Agent, "_setup_rpc")
    @mock.patch.object(_Layer2Agent, "_set_agent_state")
    def _get_agent(self, mock_set_agent_state, mock_setup_rpc, mock_setup):
        return _Layer2Agent()

    def setUp(self):
        super(TestLayer2Agent, self).setUp()
        neutron_config.register_agent_state_opts_helper(CONF)

        self._agent = self._get_agent()

        self._agent._plugin_rpc = mock.Mock(
            autospec=agent_base.agent_rpc.PluginApi)
        self._agent._endpoints = mock.MagicMock()
        self._agent._client = mock.MagicMock(
            autospec=agent_base.n_rpc.BackingOffClient)
        self._agent._connection = mock.MagicMock(
            autospec=agent_base.n_rpc.Connection)
        self._agent._physical_network_mappings = collections.OrderedDict()
        self._agent._network_vswitch_map = {}

    def _get_fake_port_details(self):
        return {
            'device': mock.sentinel.device,
            'port_id': mock.sentinel.port_id,
            'network_id': mock.sentinel.network_id,
            'network_type': mock.sentinel.network_type,
            'physical_network': mock.sentinel.physical_network,
            'segmentation_id': mock.sentinel.segmentation_id,
            'admin_state_up': mock.sentinel.admin_state_up,
            'port_security_enabled': mock.sentinel.port_security_enabled,
        }

    @mock.patch.object(agent_base.Layer2Agent, '_process_removed_port_event',
                       mock.sentinel._process_removed_port_event)
    @mock.patch.object(agent_base.Layer2Agent, '_process_added_port_event',
                       mock.sentinel._process_added_port_event)
    @mock.patch.object(agent_base.Layer2Agent, '_validate_vswitches')
    @mock.patch.object(eventlet.tpool, 'set_num_threads')
    @mock.patch.object(agent_base.Layer2Agent,
                       '_load_physical_network_mappings')
    def test_setup(self, mock_load_phys_net_mapp,
                   mock_set_num_threads,
                   mock_validate_vswitches):
        self.config(
            group="AGENT",
            worker_count=12,
            physical_network_vswitch_mappings=["fake_mappings"],
            local_network_vswitch="local_network_vswitch")
        self._agent._event_callback_pairs = []

        self._agent._setup()

        mock_load_phys_net_mapp.assert_called_once_with(["fake_mappings"])
        mock_validate_vswitches.assert_called_once_with()
        self._agent._endpoints.append.assert_called_once_with(self._agent)
        self.assertIn((self._agent._utils.EVENT_TYPE_CREATE,
                       mock.sentinel._process_added_port_event),
                      self._agent._event_callback_pairs)
        self.assertIn((self._agent._utils.EVENT_TYPE_DELETE,
                       mock.sentinel._process_removed_port_event),
                      self._agent._event_callback_pairs)

    @mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall')
    @mock.patch.object(agent_base.Layer2Agent, '_setup_qos_extension')
    @mock.patch.object(neutron.agent.rpc, 'create_consumers')
    @mock.patch.object(n_rpc, 'get_client')
    @mock.patch.object(neutron.agent.rpc, 'PluginReportStateAPI')
    @mock.patch.object(neutron.agent.rpc, 'PluginApi')
    def test_setup_rpc(self, mock_plugin_api, mock_plugin_report_state_api,
                       mock_get_client, mock_create_consumers,
                       mock_setup_qos_extension, mock_looping_call):
        self.config(group="AGENT",
                    report_interval=1)
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.PORT, topics.DELETE]]

        mock_heartbeat = mock.MagicMock()
        mock_create_consumers.return_value = self._agent._connection
        mock_looping_call.return_value = mock_heartbeat

        self._agent._setup_rpc()

        mock_plugin_api.assert_called_once_with(topics.PLUGIN)
        mock_plugin_report_state_api.assert_called_once_with(topics.PLUGIN)
        mock_get_client.assert_called_once_with(self._agent.target)
        self.assertEqual(self._agent._consumers, consumers)
        mock_create_consumers.assert_called_once_with(
            self._agent._endpoints, self._agent._topic, self._agent._consumers,
            start_listening=False)
        mock_setup_qos_extension.assert_called_once_with()
        self._agent._connection.consume_in_threads.assert_called_once_with()
        mock_looping_call.assert_called_once_with(self._agent._report_state)
        mock_heartbeat.start.assert_called_once_with(
            interval=CONF.AGENT.report_interval)

    def test_process_added_port_event(self):
        self._agent._added_ports = set()
        self._agent._process_added_port_event(mock.sentinel.port_id)
        self.assertIn(mock.sentinel.port_id, self._agent._added_ports)

    def test_process_removed_port_event(self):
        self._agent._removed_ports = set([])
        self._agent._process_removed_port_event(mock.sentinel.port_id)
        self.assertIn(mock.sentinel.port_id, self._agent._removed_ports)

    def test_load_physical_network_mappings(self):
        test_mappings = [
            'fakenetwork1:fake_vswitch', 'fakenetwork2:fake_vswitch_2',
            '*:fake_vswitch_3', 'bad_mapping'
        ]
        expected = [
            ('fakenetwork1$', 'fake_vswitch'),
            ('fakenetwork2$', 'fake_vswitch_2'),
            ('.*$', 'fake_vswitch_3')
        ]
        self._agent._physical_network_mappings = collections.OrderedDict()

        self._agent._load_physical_network_mappings(test_mappings)

        self.assertEqual(
            sorted(expected),
            sorted(self._agent._physical_network_mappings.items())
        )

    @ddt.data(True, False)
    @mock.patch.object(agent_base.Layer2Agent, '_validate_vswitch')
    def test_validate_vswitches(self, all_valid, mock_validate_vswitch):
        phys_mappings = {
            'fakenetwork0': mock.sentinel.vswitch_name_0,
            'fakenetwork1': mock.sentinel.vswitch_name_1
        }
        self._agent._physical_network_mappings = phys_mappings
        self._agent._local_network_vswitch = mock.sentinel.local_vswitch

        exp_vswitch_names = (
            list(phys_mappings.values()) + [mock.sentinel.local_vswitch])

        mock_validate_vswitch.side_effect = (
            exception.ValidationError if not all_valid else None,
            None, None)

        if all_valid:
            self._agent._validate_vswitches()
        else:
            self.assertRaises(exception.ValidationError,
                              self._agent._validate_vswitches)

        mock_validate_vswitch.assert_has_calls(
            [mock.call(vswitch_name)
             for vswitch_name in exp_vswitch_names],
            any_order=True)

    def test_validate_vswitches_none_configured(self):
        self._agent._physical_network_mappings = {}
        self._agent._local_network_vswitch = None

        self.assertRaises(exception.ValidationError,
                          self._agent._validate_vswitches)

    def test_is_ovs_extension(self):
        valid_ovs_ext_names = ['Cloudbase Open vSwitch Extension',
                               'Open vSwitch Extension',
                               'VendorX ovs',
                               'open v-switch',
                               'openvswitch']
        for ovs_ext_name in valid_ovs_ext_names:
            ext = dict(name=ovs_ext_name)
            self.assertTrue(
                self._agent._is_ovs_extension(ext))

        ext = dict(name='fake extension')
        self.assertFalse(self._agent._is_ovs_extension(ext))

    @ddt.data({},
              {'is_valid': False, 'exists': False},
              {'is_valid': False,
               'is_ovs_ext': True,
               'enabled_state': os_win_const.CIM_STATE_ENABLED},
              {'is_ovs_ext': True,
               'enabled_state': os_win_const.CIM_STATE_DISABLED},
              {'enabled_state': os_win_const.CIM_STATE_ENABLED})
    @ddt.unpack
    @mock.patch.object(agent_base.Layer2Agent, '_is_ovs_extension')
    def test_validate_vswitch(self, mock_is_ovs_ext,
                              is_valid=True, exists=True, is_ovs_ext=False,
                              enabled_state=os_win_const.CIM_STATE_ENABLED):
        extension = dict(enabled_state=enabled_state)
        mock_is_ovs_ext.return_value = is_ovs_ext

        mock_get_ext = self._agent._utils.get_vswitch_extensions
        mock_get_ext.side_effect = (
            [[extension]] if exists
            else os_win_exc.HyperVvSwitchNotFound(message='fake_msg'))

        if is_valid:
            self._agent._validate_vswitch(mock.sentinel.vswitch_name)
            mock_is_ovs_ext.assert_called_once_with(extension)
        else:
            self.assertRaises(exception.ValidationError,
                              self._agent._validate_vswitch,
                              mock.sentinel.vswitch_name)

        mock_get_ext.assert_called_once_with(mock.sentinel.vswitch_name)

    def test_get_vswitch_for_physical_network_with_default_switch(self):
        test_mappings = [
            'fakenetwork:fake_vswitch',
            'fakenetwork2$:fake_vswitch_2',
            'fakenetwork*:fake_vswitch_3'
        ]
        self._agent._physical_network_mappings = collections.OrderedDict()
        self._agent._load_physical_network_mappings(test_mappings)
        get_vswitch = self._agent._get_vswitch_for_physical_network

        self.assertEqual('fake_vswitch', get_vswitch('fakenetwork'))
        self.assertEqual('fake_vswitch_2', get_vswitch('fakenetwork2$'))
        self.assertEqual('fake_vswitch_3', get_vswitch('fakenetwork3'))
        self.assertEqual('fake_vswitch_3', get_vswitch('fakenetwork35'))
        self.assertIsNone(get_vswitch('fake_network1'))

    def test_get_vswitch_for_physical_network_without_default_switch(self):
        test_mappings = [
            'fakenetwork:fake_vswitch',
            'fakenetwork2:fake_vswitch_2'
        ]
        self._agent._load_physical_network_mappings(test_mappings)
        get_vswitch = self._agent._get_vswitch_for_physical_network

        self.assertEqual('fake_vswitch', get_vswitch("fakenetwork"))
        self.assertEqual('fake_vswitch_2', get_vswitch("fakenetwork2"))

    def test_get_vswitch_for_physical_network_none(self):
        get_vswitch = self._agent._get_vswitch_for_physical_network

        test_mappings = [
            'fakenetwork:fake_vswitch',
            'fakenetwork2:fake_vswitch_2'
        ]
        self._agent._load_physical_network_mappings(test_mappings)
        self.assertIsNone(get_vswitch(None))

        test_mappings = [
            'fakenetwork:fake_vswitch',
            'fakenetwork2:fake_vswitch_2',
            '*:fake_vswitch_3'
        ]
        self._agent._load_physical_network_mappings(test_mappings)
        self.assertEqual('fake_vswitch_3', get_vswitch(None))

    def test_get_vswitch_name_local(self):
        self._agent._local_network_vswitch = 'test_local_switch'
        ret = self._agent._get_vswitch_name(
            constants.TYPE_LOCAL, mock.sentinel.FAKE_PHYSICAL_NETWORK)

        self.assertEqual('test_local_switch', ret)

    @mock.patch.object(agent_base.Layer2Agent,
                       "_get_vswitch_for_physical_network")
    def test_get_vswitch_name_vlan(self, mock_get_vswitch_for_phys_net):
        ret = self._agent._get_vswitch_name(
            constants.TYPE_VLAN, mock.sentinel.FAKE_PHYSICAL_NETWORK)

        self.assertEqual(mock_get_vswitch_for_phys_net.return_value, ret)
        mock_get_vswitch_for_phys_net.assert_called_once_with(
            mock.sentinel.FAKE_PHYSICAL_NETWORK)

    @mock.patch.object(agent_base.Layer2Agent,
                       "_get_vswitch_for_physical_network")
    @ddt.data(constants.TYPE_VLAN, constants.TYPE_LOCAL)
    def test_get_vswitch_name_missing(self, network_type,
                                      mock_get_vswitch_for_phys_net):
        mock_get_vswitch_for_phys_net.return_value = None
        self._agent._local_network_vswitch = ''

        self.assertRaises(exception.NetworkingHyperVException,
                          self._agent._get_vswitch_name,
                          network_type,
                          mock.sentinel.FAKE_PHYSICAL_NETWORK)

    def test_get_network_vswitch_map_by_port_id(self):
        net_uuid = 'net-uuid'
        self._agent._network_vswitch_map = {
            net_uuid: {'ports': [self._FAKE_PORT_ID]}
        }

        network, port_map = self._agent._get_network_vswitch_map_by_port_id(
            self._FAKE_PORT_ID)

        self.assertEqual(net_uuid, network)
        self.assertEqual({'ports': [self._FAKE_PORT_ID]}, port_map)

    def test_get_network_vswitch_map_by_port_id_not_found(self):
        net_uuid = 'net-uuid'
        self._agent._network_vswitch_map = {net_uuid: {'ports': []}}

        network, port_map = self._agent._get_network_vswitch_map_by_port_id(
            self._FAKE_PORT_ID)

        self.assertIsNone(network)
        self.assertIsNone(port_map)

    def test_update_port_status_cache_added(self):
        self._agent._unbound_ports = set([mock.sentinel.bound_port])
        self._agent._update_port_status_cache(mock.sentinel.bound_port)

        self.assertEqual(set([mock.sentinel.bound_port]),
                         self._agent._bound_ports)
        self.assertEqual(set([]), self._agent._unbound_ports)

    def test_update_port_status_cache_removed(self):
        self._agent._bound_ports = set([mock.sentinel.unbound_port])
        self._agent._update_port_status_cache(mock.sentinel.unbound_port,
                                              device_bound=False)

        self.assertEqual(set([]), self._agent._bound_ports)
        self.assertEqual(set([mock.sentinel.unbound_port]),
                         self._agent._unbound_ports)

    @mock.patch('eventlet.spawn_n')
    def test_create_event_listeners(self, mock_spawn):
        self._agent._event_callback_pairs = [
            (mock.sentinel.event_type, mock.sentinel.callback)]

        self._agent._create_event_listeners()

        self._agent._utils.get_vnic_event_listener.assert_called_once_with(
            mock.sentinel.event_type)
        mock_spawn.assert_called_once_with(
            self._agent._utils.get_vnic_event_listener.return_value,
            mock.sentinel.callback)

    @mock.patch.object(agent_base.Layer2Agent,
                       '_create_event_listeners')
    def test_prologue(self, mock_create_listeners):
        self._agent._prologue()

        # self._added_ports = self._utils.get_vnic_ids()
        self._agent._create_event_listeners.assert_called_once_with()

    def test_reclaim_local_network(self):
        self._agent._network_vswitch_map = {}
        self._agent._network_vswitch_map[mock.sentinel.net_id] = (
            mock.sentinel.vswitch)

        self._agent._reclaim_local_network(mock.sentinel.net_id)
        self.assertNotIn(mock.sentinel.net_id,
                         self._agent._network_vswitch_map)

    @mock.patch.object(_Layer2Agent, '_provision_network')
    def test_port_bound_net_type(self, mock_provision_network):
        net_uuid = 'my-net-uuid'
        fake_map = {'vswitch_name': mock.sentinel.vswitch_name,
                    'ports': []}

        def fake_prov_network(*args, **kwargs):
            self._agent._network_vswitch_map[net_uuid] = fake_map

        mock_provision_network.side_effect = fake_prov_network

        self._agent._port_bound(mock.sentinel.port_id,
                                net_uuid, mock.sentinel.network_type,
                                mock.sentinel.physical_network,
                                mock.sentinel.segmentation_id,
                                mock.sentinel.port_security_enabled, True)

        self.assertIn(mock.sentinel.port_id, fake_map['ports'])
        mock_provision_network.assert_called_once_with(
            mock.sentinel.port_id, net_uuid, mock.sentinel.network_type,
            mock.sentinel.physical_network, mock.sentinel.segmentation_id)
        self._agent._utils.connect_vnic_to_vswitch.assert_called_once_with(
            vswitch_name=mock.sentinel.vswitch_name,
            switch_port_name=mock.sentinel.port_id)
        self._agent._utils.set_vswitch_port_sriov.assert_called_once_with(
            mock.sentinel.port_id, True)

    @mock.patch.object(agent_base.Layer2Agent,
                       '_get_network_vswitch_map_by_port_id')
    def _check_port_unbound(self, mock_get_vswitch_map_by_port_id, ports=None,
                            net_uuid=None):
        vswitch_map = {
            'network_type': 'vlan',
            'vswitch_name': 'fake-vswitch',
            'ports': ports,
            'vlan_id': 1}
        network_vswitch_map = (net_uuid, vswitch_map)
        mock_get_vswitch_map_by_port_id.return_value = network_vswitch_map

        self._agent._port_unbound(self._FAKE_PORT_ID, vnic_deleted=False)

        if net_uuid:
            self._agent._utils.remove_switch_port.assert_called_once_with(
                self._FAKE_PORT_ID, False)
        else:
            self.assertFalse(self._agent._utils.remove_switch_port.called)

    @mock.patch.object(agent_base.Layer2Agent,
                       '_reclaim_local_network')
    def test_port_unbound(self, mock_reclaim_local_network):
        net_uuid = 'my-net-uuid'
        self._check_port_unbound(ports=[self._FAKE_PORT_ID],
                                 net_uuid=net_uuid)
        mock_reclaim_local_network.assert_called_once_with(net_uuid)

    def test_port_unbound_port_not_found(self):
        self._check_port_unbound()

    @mock.patch.object(_Layer2Agent, '_treat_vif_port')
    def test_process_added_port_sriov(self, mock_treat_vif_port):
        details = self._get_fake_port_details()
        details.pop('device')
        port_details = dict(profile={'pci_slot': mock.sentinel.pci_slot},
                            **self._get_fake_port_details())

        self._agent.process_added_port(port_details)
        mock_treat_vif_port.assert_called_once_with(set_port_sriov=True,
                                                    **details)

    @ddt.data(os_win_exc.HyperVvNicNotFound(vnic_name='fake_vnic'),
              os_win_exc.HyperVPortNotFoundException(port_name='fake_port'),
              Exception)
    @mock.patch.object(_Layer2Agent, '_treat_vif_port')
    def test_process_added_port_failed(self, side_effect, mock_treat_vif_port):
        mock_treat_vif_port.side_effect = side_effect
        self._agent._added_ports = set()
        details = self._get_fake_port_details()
        details.pop('device')
        port_details = self._get_fake_port_details()

        self._agent.process_added_port(port_details)

        if isinstance(side_effect, os_win_exc.HyperVvNicNotFound):
            self.assertNotIn(mock.sentinel.device, self._agent._added_ports)
        else:
            self.assertIn(mock.sentinel.device, self._agent._added_ports)

        mock_treat_vif_port.assert_called_once_with(set_port_sriov=False,
                                                    **details)

    def test_treat_devices_added_returns_true_for_missing_device(self):
        self._agent._added_ports = set([mock.sentinel.port_id])
        attrs = {'get_devices_details_list.side_effect': Exception()}
        self._agent._plugin_rpc.configure_mock(**attrs)
        self._agent._treat_devices_added()

        self.assertIn(mock.sentinel.port_id, self._agent._added_ports)

    @mock.patch('eventlet.spawn_n')
    def test_treat_devices_added_updates_known_port(self, mock_spawn):
        self._agent._added_ports = set([mock.sentinel.device])
        fake_port_details = self._get_fake_port_details()
        kwargs = {'get_devices_details_list.return_value': [fake_port_details]}
        self._agent._plugin_rpc.configure_mock(**kwargs)

        self._agent._treat_devices_added()

        mock_spawn.assert_called_once_with(
            self._agent.process_added_port, fake_port_details)
        self.assertNotIn(mock.sentinel.device, self._agent._added_ports)

    def test_treat_devices_added_missing_port_id(self):
        self._agent._added_ports = set([mock.sentinel.port_id])
        details = {'device': mock.sentinel.port_id}
        attrs = {'get_devices_details_list.return_value': [details]}
        self._agent._plugin_rpc.configure_mock(**attrs)

        self._agent._treat_devices_added()

        self.assertNotIn(mock.sentinel.port_id, self._agent._added_ports)

    @mock.patch.object(agent_base.Layer2Agent,
                       '_port_unbound')
    @mock.patch.object(agent_base.Layer2Agent,
                       '_update_port_status_cache')
    def test_process_removed_port_exception(self, mock_update_port_cache,
                                            mock_port_unbound):
        self._agent._removed_ports = set([mock.sentinel.port_id])

        raised_exc = exception.NetworkingHyperVException
        mock_port_unbound.side_effect = raised_exc

        self.assertRaises(raised_exc,
                          self._agent._process_removed_port,
                          mock.sentinel.port_id)

        mock_update_port_cache.assert_called_once_with(
            mock.sentinel.port_id, device_bound=False)
        self.assertIn(mock.sentinel.port_id, self._agent._removed_ports)

    @mock.patch.object(agent_base.Layer2Agent,
                       '_port_unbound')
    @mock.patch.object(agent_base.Layer2Agent,
                       '_update_port_status_cache')
    def test_process_removed_port(self, mock_update_port_cache,
                                  mock_port_unbound):
        self._agent._removed_ports = set([mock.sentinel.port_id])

        self._agent._process_removed_port(mock.sentinel.port_id)

        mock_update_port_cache.assert_called_once_with(
            mock.sentinel.port_id, device_bound=False)
        mock_port_unbound.assert_called_once_with(mock.sentinel.port_id,
                                                  vnic_deleted=True)
        self.assertNotIn(mock.sentinel.port_id, self._agent._removed_ports)

    @mock.patch('eventlet.spawn_n')
    def test_treat_devices_removed(self, mock_spawn):
        mock_removed_ports = [mock.sentinel.port0, mock.sentinel.port1]
        self._agent._removed_ports = set(mock_removed_ports)

        self._agent._treat_devices_removed()

        mock_spawn.assert_has_calls(
            [mock.call(self._agent._process_removed_port, port)
             for port in mock_removed_ports],
            any_order=True)

    def test_notify_plugin_no_updates(self):
        self._agent._bound_ports = set()
        self._agent._unbound_ports = set()

        self._agent._notify_plugin_on_port_updates()

        self.assertFalse(self._agent._plugin_rpc.update_device_list.called)

    def test_notify_plugin(self):
        self._agent._bound_ports = set([mock.sentinel.bound_port])
        self._agent._unbound_ports = set([mock.sentinel.unbound_port])

        self._agent._notify_plugin_on_port_updates()

        self._agent._plugin_rpc.update_device_list.assert_called_once_with(
            self._agent._context, [mock.sentinel.bound_port],
            [mock.sentinel.unbound_port], self._agent._agent_id,
            self._agent._host)
        self.assertEqual(set([]), self._agent._bound_ports)
        self.assertEqual(set([]), self._agent._unbound_ports)

    @mock.patch.object(agent_base.Layer2Agent, '_treat_devices_removed')
    @mock.patch.object(agent_base.Layer2Agent, '_treat_devices_added')
    @mock.patch('eventlet.spawn_n')
    def test_work(self, mock_spawn, mock_treat_dev_added,
                  mock_treat_dev_removed):
        self._agent._refresh_cache = True
        self._agent._bound_ports = set([mock.sentinel.bound_port])
        self._agent._added_ports = set([mock.sentinel.bound_port])
        self._agent._removed_ports = set([mock.sentinel.unbound_port])

        self._agent._work()

        self._agent._utils.update_cache.assert_called_once_with()
        self.assertFalse(self._agent._refresh_cache)
        mock_spawn.assert_called_once_with(
            self._agent._notify_plugin_on_port_updates)
        mock_treat_dev_added.assert_called_once_with()
        mock_treat_dev_removed.assert_called_once_with()

    @mock.patch.object(agent_base.Layer2Agent, '_treat_devices_removed')
    @mock.patch.object(agent_base.Layer2Agent, '_treat_devices_added')
    @mock.patch('eventlet.spawn_n')
    def test_work_noop(self, mock_spawn, mock_treat_dev_added,
                       mock_treat_dev_removed):
        self._agent._work()

        self.assertFalse(mock_spawn.called)
        self.assertFalse(mock_treat_dev_added.called)
        self.assertFalse(mock_treat_dev_removed.called)

    def test_port_update_not_found(self):
        self._agent._utils.vnic_port_exists.return_value = False
        port = {'id': mock.sentinel.port_id}
        self._agent.port_update(self._agent._context, port)

    @mock.patch.object(agent_base.Layer2Agent, '_treat_vif_port')
    def test_port_update(self, mock_treat_vif_port):
        self._agent._utils.vnic_port_exists.return_value = True
        port = {'id': mock.sentinel.port_id,
                'network_id': mock.sentinel.network_id,
                'admin_state_up': mock.sentinel.admin_state_up,
                'port_security_enabled': mock.sentinel.port_security_enabled}

        self._agent.port_update(self._agent._context, port,
                                mock.sentinel.network_type,
                                mock.sentinel.segmentation_id,
                                mock.sentinel.physical_network)

    @mock.patch.object(agent_base.Layer2Agent,
                       '_reclaim_local_network')
    def test_network_delete(self, mock_reclaim_local_network):
        self._agent._network_vswitch_map = {}
        self._agent._network_vswitch_map[mock.sentinel.net_id] = (
            mock.sentinel.vswitch)

        self._agent.network_delete(mock.sentinel.context, mock.sentinel.net_id)
        mock_reclaim_local_network.assert_called_once_with(
            mock.sentinel.net_id)

    @mock.patch.object(agent_base.Layer2Agent,
                       '_reclaim_local_network')
    def test_network_delete_not_defined(self, mock_reclaim_local_network):
        self._agent.network_delete(mock.sentinel.context, mock.sentinel.net_id)
        self.assertFalse(mock_reclaim_local_network.called)

    @mock.patch.object(agent_base.Layer2Agent, '_port_bound')
    def test_treat_vif_port_state_up(self, mock_port_bound):
        self._agent._treat_vif_port(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, True,
            mock.sentinel.port_security_enabled)

        mock_port_bound.assert_called_once_with(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, mock.sentinel.port_security_enabled,
            False)

    @mock.patch.object(agent_base.Layer2Agent, '_port_unbound')
    def test_treat_vif_port_state_down(self, mock_port_unbound):
        self._agent._treat_vif_port(
            mock.sentinel.port_id, mock.sentinel.network_id,
            mock.sentinel.network_type, mock.sentinel.physical_network,
            mock.sentinel.segmentation_id, False,
            mock.sentinel.port_security_enabled)

        mock_port_unbound.assert_called_once_with(mock.sentinel.port_id)
