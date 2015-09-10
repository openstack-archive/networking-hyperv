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

from hyperv.neutron import constants
from hyperv.neutron import nvgre_ops
from hyperv.neutron import utilsfactory
from hyperv.tests import base


class TestHyperVNvgreOps(base.BaseTestCase):

    FAKE_MAC_ADDR = 'fa:ke:ma:ca:dd:re:ss'

    def setUp(self):
        super(TestHyperVNvgreOps, self).setUp()

        utilsfactory._get_windows_version = mock.MagicMock(
            return_value='6.2.0')

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
    def test_bind_nvgre_network(self, mock_refresh_records):
        self.config(provider_tunnel_ip=mock.sentinel.ip_addr, group='NVGRE')
        self.ops._n_client.get_network_subnets.return_value = [
            mock.sentinel.subnet, mock.sentinel.subnet2]

        get_cidr = self.ops._n_client.get_network_subnet_cidr_and_gateway
        get_cidr.return_value = (mock.sentinel.cidr, mock.sentinel.gateway)

        self.ops.bind_nvgre_network(
            mock.sentinel.vsid, mock.sentinel.net_uuid,
            mock.sentinel.vswitch_name)

        self.assertEqual(mock.sentinel.vsid,
                         self.ops._network_vsids[mock.sentinel.net_uuid])
        self.ops._n_client.get_network_subnets.assert_called_once_with(
            mock.sentinel.net_uuid)
        get_cidr.assert_called_once_with(mock.sentinel.subnet)
        self.ops._nvgre_utils.create_customer_routes.assert_called_once_with(
            mock.sentinel.vsid, mock.sentinel.vswitch_name,
            mock.sentinel.cidr, mock.sentinel.gateway)
        mock_refresh_records.assert_called_once_with(
            network_id=mock.sentinel.net_uuid)
        self.ops._notifier.tunnel_update.assert_called_once_with(
            self.context, mock.sentinel.ip_addr, mock.sentinel.vsid)

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
