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
Unit tests for Windows Hyper-V NVGRE driver.
"""

import mock

from networking_hyperv.neutron import config
from networking_hyperv.neutron import constants
from networking_hyperv.neutron import nvgre_ops
from networking_hyperv.tests import base

CONF = config.CONF


class TestHyperVNvgreOps(base.HyperVBaseTestCase):

    FAKE_MAC_ADDR = 'fa:ke:ma:ca:dd:re:ss'
    FAKE_CIDR = '10.0.0.0/24'
    FAKE_VSWITCH_NAME = 'fake_vswitch'

    def setUp(self):
        super(TestHyperVNvgreOps, self).setUp()

        self.context = 'context'
        self.ops = nvgre_ops.HyperVNvgreOps([])
        self.ops._vswitch_ips[mock.sentinel.network_name] = (
            mock.sentinel.ip_addr)
        self.ops.context = self.context
        self.ops._notifier = mock.MagicMock()
        self.ops._hyperv_utils = mock.MagicMock()
        self.ops._nvgre_utils = mock.MagicMock()
        self.ops._n_client = mock.MagicMock()
        self.ops._db = mock.MagicMock()

    @mock.patch.object(nvgre_ops.hyperv_agent_notifier, 'AgentNotifierApi')
    def test_init_notifier(self, mock_notifier):
        self.ops.init_notifier(mock.sentinel.context, mock.sentinel.rpc_client)
        mock_notifier.assert_called_once_with(
            constants.AGENT_TOPIC,
            mock.sentinel.rpc_client)
        self.assertEqual(mock_notifier.return_value, self.ops._notifier)
        self.assertEqual(mock.sentinel.context, self.ops.context)

    def test_init_nvgre(self):
        self.ops._nvgre_utils.get_network_iface_ip.return_value = (
            mock.sentinel.ip_addr, mock.sentinel.length)

        self.ops._init_nvgre([mock.sentinel.physical_network])

        self.assertEqual(self.ops._vswitch_ips[mock.sentinel.physical_network],
                         mock.sentinel.ip_addr)
        self.ops._nvgre_utils.create_provider_route.assert_called_once_with(
            mock.sentinel.physical_network)
        self.ops._nvgre_utils.create_provider_address.assert_called_once_with(
            mock.sentinel.physical_network, CONF.NVGRE.provider_vlan_id)

    def test_refresh_tunneling_agents(self):
        self.ops._n_client.get_tunneling_agents.return_value = {
            mock.sentinel.host: mock.sentinel.host_ip
        }
        self.ops._refresh_tunneling_agents()
        self.assertEqual(mock.sentinel.host_ip,
                         self.ops._tunneling_agents[mock.sentinel.host])

    @mock.patch.object(nvgre_ops.HyperVNvgreOps, '_register_lookup_record')
    def test_lookup_update(self, mock_register_record):
        args = {'lookup_ip': mock.sentinel.lookup_ip,
                'lookup_details': {
                    'customer_addr': mock.sentinel.customer_addr,
                    'mac_addr': mock.sentinel.mac_addr,
                    'customer_vsid': mock.sentinel.vsid}
                }

        self.ops.lookup_update(args)

        mock_register_record.assert_called_once_with(
            mock.sentinel.lookup_ip,
            mock.sentinel.customer_addr,
            mock.sentinel.mac_addr,
            mock.sentinel.vsid)

    def test_tunnel_update_nvgre(self):
        self.ops.tunnel_update(
            mock.sentinel.context,
            mock.sentinel.tunnel_ip,
            tunnel_type=constants.TYPE_NVGRE)

        self.ops._notifier.tunnel_update.assert_called_once_with(
            mock.sentinel.context,
            CONF.NVGRE.provider_tunnel_ip,
            constants.TYPE_NVGRE)

    def test_tunnel_update(self):
        self.ops.tunnel_update(
            mock.sentinel.context,
            mock.sentinel.tunnel_ip,
            mock.sentinel.tunnel_type)

        self.assertFalse(self.ops._notifier.tunnel_update.called)

    @mock.patch.object(nvgre_ops.HyperVNvgreOps, '_register_lookup_record')
    def test_lookup_update_no_details(self, mock_register_record):
        self.ops.lookup_update({})
        self.assertFalse(mock_register_record.called)

    def test_register_lookup_record(self):
        self.ops._register_lookup_record(
            mock.sentinel.provider_addr, mock.sentinel.customer_addr,
            mock.sentinel.mac_addr, mock.sentinel.vsid)

        self.ops._nvgre_utils.create_lookup_record.assert_called_once_with(
            mock.sentinel.provider_addr, mock.sentinel.customer_addr,
            mock.sentinel.mac_addr, mock.sentinel.vsid)

    @mock.patch.object(nvgre_ops.HyperVNvgreOps, '_register_lookup_record')
    def test_bind_nvgre_port(self, mock_register_record):
        self.ops._nvgre_utils.get_network_iface_ip.return_value = (
            mock.sentinel.provider_addr, mock.sentinel.prefix_len)

        mac_addr = self.ops._hyperv_utils.get_vnic_mac_address.return_value
        customer_addr = self.ops._n_client.get_port_ip_address.return_value

        self.ops.bind_nvgre_port(mock.sentinel.vsid,
                                 mock.sentinel.network_name,
                                 mock.sentinel.port_id)

        self.ops._hyperv_utils.set_vswitch_port_vsid.assert_called_once_with(
            mock.sentinel.vsid, mock.sentinel.port_id)
        mock_register_record.assert_has_calls([
            mock.call(mock.sentinel.provider_addr, customer_addr, mac_addr,
                      mock.sentinel.vsid),
            mock.call(mock.sentinel.ip_addr, constants.IPV4_DEFAULT, mac_addr,
                      mock.sentinel.vsid)])
        self.ops._notifier.lookup_update.assert_called_once_with(
            self.context, mock.sentinel.provider_addr, {
                'customer_addr': customer_addr,
                'mac_addr': mac_addr,
                'customer_vsid': mock.sentinel.vsid
            })

    def test_bind_nvgre_port_no_provider_addr(self):
        self.ops._nvgre_utils.get_network_iface_ip = mock.MagicMock(
            return_value=(None, None))

        self.ops.bind_nvgre_port(mock.sentinel.vsid,
                                 mock.sentinel.network_name,
                                 mock.sentinel.port_id)

        self.assertFalse(self.ops._hyperv_utils.set_vswitch_port_vsid.called)

    @mock.patch.object(nvgre_ops.HyperVNvgreOps, 'refresh_nvgre_records')
    @mock.patch.object(nvgre_ops.HyperVNvgreOps, '_create_customer_routes')
    def test_bind_nvgre_network(self, mock_create_routes,
                                mock_refresh_records):
        fake_ip = '10.10.10.10'
        self.config(provider_tunnel_ip=fake_ip, group='NVGRE')
        self.ops._n_client.get_network_subnets.return_value = [
            mock.sentinel.subnet, mock.sentinel.subnet2]

        get_cidr = self.ops._n_client.get_network_subnet_cidr_and_gateway
        get_cidr.return_value = (self.FAKE_CIDR, mock.sentinel.gateway)

        self.ops.bind_nvgre_network(
            mock.sentinel.vsid, mock.sentinel.net_uuid,
            self.FAKE_VSWITCH_NAME)

        self.assertEqual(mock.sentinel.vsid,
                         self.ops._network_vsids[mock.sentinel.net_uuid])
        self.ops._n_client.get_network_subnets.assert_called_once_with(
            mock.sentinel.net_uuid)
        get_cidr.assert_called_once_with(mock.sentinel.subnet)
        mock_create_routes.assert_called_once_with(
            mock.sentinel.vsid, self.FAKE_CIDR,
            mock.sentinel.gateway, mock.ANY)
        mock_refresh_records.assert_called_once_with(
            network_id=mock.sentinel.net_uuid)
        self.ops._notifier.tunnel_update.assert_called_once_with(
            self.context, fake_ip, mock.sentinel.vsid)

    def _check_create_customer_routes(self, gateway=None):
        self.ops._create_customer_routes(
            mock.sentinel.vsid, mock.sentinel.cidr,
            gateway, mock.sentinel.rdid)

        self.ops._nvgre_utils.clear_customer_routes.assert_called_once_with(
            mock.sentinel.vsid)
        self.ops._nvgre_utils.create_customer_route.assert_called_once_with(
            mock.sentinel.vsid, mock.sentinel.cidr, constants.IPV4_DEFAULT,
            mock.sentinel.rdid)

    def test_create_customer_routes_no_gw(self):
        self._check_create_customer_routes()

    def test_create_customer_routes_bad_gw(self):
        gateway = '10.0.0.1'
        self._check_create_customer_routes(gateway=gateway)

    def test_create_customer_routes(self):
        gateway = '10.0.0.2'
        self.ops._create_customer_routes(
            mock.sentinel.vsid, mock.sentinel.cidr,
            gateway, mock.sentinel.rdid)

        metadata_addr = '%s/32' % CONF.AGENT.neutron_metadata_address
        self.ops._nvgre_utils.create_customer_route.assert_has_calls([
            mock.call(mock.sentinel.vsid, mock.sentinel.cidr,
                      constants.IPV4_DEFAULT, mock.sentinel.rdid),
            mock.call(mock.sentinel.vsid, '%s/0' % constants.IPV4_DEFAULT,
                      gateway, mock.ANY),
            mock.call(mock.sentinel.vsid, metadata_addr,
                      gateway, mock.ANY)], any_order=True)

    @mock.patch.object(nvgre_ops.HyperVNvgreOps, '_register_lookup_record')
    def test_refresh_nvgre_records(self, mock_register_record):
        self.ops._nvgre_ports.append(mock.sentinel.processed_port_id)
        self.ops._tunneling_agents[mock.sentinel.host_id] = (
            mock.sentinel.agent_ip)
        self.ops._network_vsids[mock.sentinel.net_id] = (
            mock.sentinel.vsid)

        processed_port = {'id': mock.sentinel.processed_port_id}
        no_host_port = {'id': mock.sentinel.port_no_host_id,
                        'binding:host_id': mock.sentinel.odd_host_id}
        other_net_id_port = {'id': mock.sentinel.port_other_net_id,
                             'binding:host_id': mock.sentinel.host_id,
                             'network_id': mock.sentinel.odd_net_id}
        port = {'id': mock.sentinel.port_id,
                'binding:host_id': mock.sentinel.host_id,
                'network_id': mock.sentinel.net_id,
                'mac_address': self.FAKE_MAC_ADDR,
                'fixed_ips': [{'ip_address': mock.sentinel.customer_addr}]
                }

        self.ops._n_client.get_network_ports.return_value = [
            processed_port, no_host_port, other_net_id_port, port]

        self.ops.refresh_nvgre_records()

        expected_mac = self.FAKE_MAC_ADDR.replace(':', '')
        mock_register_record.assert_has_calls([
            mock.call(mock.sentinel.agent_ip, mock.sentinel.customer_addr,
                      expected_mac, mock.sentinel.vsid),
            # mock.call(mock.sentinel.agent_ip, constants.METADATA_ADDR,
            #          expected_mac, mock.sentinel.vsid)
        ])
        self.assertIn(mock.sentinel.port_id, self.ops._nvgre_ports)

    @mock.patch.object(nvgre_ops.HyperVNvgreOps, '_register_lookup_record')
    def test_refresh_nvgre_records_exception(self, mock_register_record):
        self.ops._tunneling_agents[mock.sentinel.host_id] = (
            mock.sentinel.agent_ip)
        self.ops._network_vsids[mock.sentinel.net_id] = (mock.sentinel.vsid)
        port = mock.MagicMock()
        self.ops._n_client.get_network_ports.return_value = [port]
        mock_register_record.side_effect = TypeError

        self.ops.refresh_nvgre_records()

        self.assertNotIn(mock.sentinel.port_id, self.ops._nvgre_ports)
