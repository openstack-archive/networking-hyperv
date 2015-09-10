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
Unit tests for the Hyper-V NVGRE support.
"""

import mock
from oslo_config import cfg

from hyperv.neutron import constants
from hyperv.neutron import utils_nvgre
from hyperv.tests import base

CONF = cfg.CONF


class TestHyperVNvgreUtils(base.BaseTestCase):

    _FAKE_RDID = 'fake_rdid'
    _FAKE_NETWORK_NAME = 'fake_network_name'
    _FAKE_VSID = 9001
    _FAKE_DEST_PREFIX = 'fake_dest_prefix'
    _FAKE_GW_BAD = '10.0.0.1'
    _FAKE_GW = '10.0.0.2'

    def setUp(self):
        super(TestHyperVNvgreUtils, self).setUp()
        self.utils = utils_nvgre.NvgreUtils()
        self.utils._utils = mock.MagicMock()
        self.utils._scimv2 = mock.MagicMock()

    def _create_mock_binding(self):
        binding = mock.MagicMock()
        binding.BindName = self.utils._WNV_BIND_NAME
        binding.Name = mock.sentinel.fake_network

        net_binds = self.utils._scimv2.MSFT_NetAdapterBindingSettingData
        net_binds.return_value = [binding]
        return binding

    @mock.patch.object(utils_nvgre.NvgreUtils, 'get_network_iface_ip')
    @mock.patch.object(utils_nvgre.NvgreUtils, '_get_network_iface_index')
    def test_create_provider_address(self, mock_get_iface_index,
                                     mock_get_iface_ip):
        mock_get_iface_index.return_value = mock.sentinel.iface_index
        mock_get_iface_ip.return_value = (mock.sentinel.iface_ip,
                                          mock.sentinel.prefix_len)

        provider_addr = mock.MagicMock()
        scimv2 = self.utils._scimv2
        obj_class = scimv2.MSFT_NetVirtualizationProviderAddressSettingData
        obj_class.return_value = [provider_addr]

        self.utils.create_provider_address(mock.sentinel.fake_network,
                                           mock.sentinel.fake_vlan_id)

        self.assertTrue(provider_addr.Delete_.called)
        obj_class.new.assert_called_once_with(
            ProviderAddress=mock.sentinel.iface_ip,
            VlanID=mock.sentinel.fake_vlan_id,
            InterfaceIndex=mock.sentinel.iface_index,
            PrefixLength=mock.sentinel.prefix_len)

    @mock.patch.object(utils_nvgre.NvgreUtils, 'get_network_iface_ip')
    @mock.patch.object(utils_nvgre.NvgreUtils, '_get_network_iface_index')
    def test_create_provider_address_none(self, mock_get_iface_index,
                                          mock_get_iface_ip):
        mock_get_iface_ip.return_value = (None, None)

        self.utils.create_provider_address(mock.sentinel.fake_network,
                                           mock.sentinel.fake_vlan_id)
        scimv2 = self.utils._scimv2
        self.assertFalse(
            scimv2.MSFT_NetVirtualizationProviderAddressSettingData.new.called)

    @mock.patch.object(utils_nvgre.NvgreUtils, 'get_network_iface_ip')
    @mock.patch.object(utils_nvgre.NvgreUtils, '_get_network_iface_index')
    def test_create_provider_address_exists(self, mock_get_iface_index,
                                            mock_get_iface_ip):
        mock_get_iface_index.return_value = mock.sentinel.iface_index
        mock_get_iface_ip.return_value = (mock.sentinel.iface_ip,
                                          mock.sentinel.prefix_len)

        provider_addr = mock.MagicMock(
            VlanID=mock.sentinel.fake_vlan_id,
            InterfaceIndex=mock.sentinel.iface_index)
        scimv2 = self.utils._scimv2
        obj_class = scimv2.MSFT_NetVirtualizationProviderAddressSettingData
        obj_class.return_value = [provider_addr]

        self.utils.create_provider_address(mock.sentinel.fake_network,
                                           mock.sentinel.fake_vlan_id)

        self.assertFalse(obj_class.new.called)

    @mock.patch.object(utils_nvgre.NvgreUtils, '_get_network_iface_index')
    def test_create_provider_route(self, mock_get_iface_index):
        mock_get_iface_index.return_value = mock.sentinel.iface_index
        self.utils._scimv2.MSFT_NetVirtualizationProviderRouteSettingData = (
            mock.MagicMock(return_value=[]))

        self.utils.create_provider_route(mock.sentinel.fake_network)

        scimv2 = self.utils._scimv2
        obj_class = scimv2.MSFT_NetVirtualizationProviderRouteSettingData
        obj_class.new.assert_called_once_with(
            InterfaceIndex=mock.sentinel.iface_index,
            DestinationPrefix='%s/0' % constants.IPV4_DEFAULT,
            NextHop=constants.IPV4_DEFAULT)

    @mock.patch.object(utils_nvgre.NvgreUtils, '_get_network_iface_index')
    def test_create_provider_route_none(self, mock_get_iface_index):
        mock_get_iface_index.return_value = None

        self.utils.create_provider_route(mock.sentinel.fake_network)
        scimv2 = self.utils._scimv2
        self.assertFalse(
            scimv2.MSFT_NetVirtualizationProviderRouteSettingData.new.called)

    @mock.patch.object(utils_nvgre.NvgreUtils, '_get_network_iface_index')
    def test_create_provider_route_exists(self, mock_get_iface_index):
        mock_get_iface_index.return_value = mock.sentinel.iface_index
        self.utils._scimv2.MSFT_NetVirtualizationProviderRouteSettingData = (
            mock.MagicMock(return_value=[mock.MagicMock()]))

        self.utils.create_provider_route(mock.sentinel.fake_network)

        scimv2 = self.utils._scimv2
        self.assertFalse(
            scimv2.MSFT_NetVirtualizationProviderRouteSettingData.new.called)

    @mock.patch.object(utils_nvgre.NvgreUtils, '_create_cust_route')
    def _check_create_customer_routes(self, mock_create_route, gateway=None):
        customer_route = mock.MagicMock()
        scimv2 = self.utils._scimv2
        obj_class = scimv2.MSFT_NetVirtualizationCustomerRouteSettingData
        obj_class.return_value = [customer_route]

        self.utils.create_customer_routes(
            self._FAKE_VSID, self._FAKE_NETWORK_NAME, self._FAKE_DEST_PREFIX,
            gateway)

        routes = [(self._FAKE_DEST_PREFIX, constants.IPV4_DEFAULT)]
        if gateway and gateway[-1] != '1':
            routes.append(('%s/0' % constants.IPV4_DEFAULT, gateway))
            routes.append(('%s/32' % CONF.AGENT.neutron_metadata_address,
                           gateway))
        expected_calls = [
            mock.call(self._FAKE_VSID, dest_prefix, next_hop, mock.ANY)
            for dest_prefix, next_hop in routes]

        self.assertTrue(customer_route.Delete_.called)
        mock_create_route.assert_has_calls(expected_calls)

    def test_create_customer_route(self):
        self._check_create_customer_routes(gateway=self._FAKE_GW)

    def test_create_customer_route_no_gateway(self):
        self._check_create_customer_routes()

    def test_create_customer_route_bad_gateway(self):
        self._check_create_customer_routes(gateway=self._FAKE_GW_BAD)

    def test_create_cust_route(self):
        self.utils._create_cust_route(
            mock.sentinel.fake_vsid, mock.sentinel.dest_prefix,
            mock.sentinel.next_hop, self._FAKE_RDID)

        scimv2 = self.utils._scimv2
        obj_class = scimv2.MSFT_NetVirtualizationCustomerRouteSettingData
        obj_class.new.assert_called_once_with(
            VirtualSubnetID=mock.sentinel.fake_vsid,
            DestinationPrefix=mock.sentinel.dest_prefix,
            NextHop=mock.sentinel.next_hop,
            Metric=255,
            RoutingDomainID='{%s}' % self._FAKE_RDID)

    def _check_create_lookup_record(self, customer_addr, expected_type):
        lookup = mock.MagicMock()
        scimv2 = self.utils._scimv2
        obj_class = scimv2.MSFT_NetVirtualizationLookupRecordSettingData
        obj_class.return_value = [lookup]

        self.utils.create_lookup_record(mock.sentinel.provider_addr,
                                        customer_addr,
                                        mock.sentinel.mac_addr,
                                        mock.sentinel.fake_vsid)

        self.assertTrue(lookup.Delete_.called)
        obj_class.new.assert_called_once_with(
            VirtualSubnetID=mock.sentinel.fake_vsid,
            Rule=self.utils._TRANSLATE_ENCAP,
            Type=expected_type,
            MACAddress=mock.sentinel.mac_addr,
            CustomerAddress=customer_addr,
            ProviderAddress=mock.sentinel.provider_addr)

    def test_create_lookup_record_l2_only(self):
        self._check_create_lookup_record(
            constants.IPV4_DEFAULT,
            self.utils._LOOKUP_RECORD_TYPE_L2_ONLY)

    def test_create_lookup_record_static(self):
        self._check_create_lookup_record(
            mock.sentinel.customer_addr,
            self.utils._LOOKUP_RECORD_TYPE_STATIC)

    def test_create_lookup_record_exists(self):
        lookup = mock.MagicMock(VirtualSubnetID=mock.sentinel.fake_vsid,
                                ProviderAddress=mock.sentinel.provider_addr,
                                CustomerAddress=mock.sentinel.customer_addr,
                                MACAddress=mock.sentinel.mac_addr)
        scimv2 = self.utils._scimv2
        obj_class = scimv2.MSFT_NetVirtualizationLookupRecordSettingData
        obj_class.return_value = [lookup]

        self.utils.create_lookup_record(mock.sentinel.provider_addr,
                                        mock.sentinel.customer_addr,
                                        mock.sentinel.mac_addr,
                                        mock.sentinel.fake_vsid)
        self.assertFalse(obj_class.new.called)

    def test_get_network_iface_index(self):
        fake_network = mock.MagicMock(InterfaceIndex=mock.sentinel.iface_index)
        self.utils._scimv2.MSFT_NetAdapter.return_value = [fake_network]
        description = (
            self.utils._utils.get_vswitch_external_network_name.return_value)

        index = self.utils._get_network_iface_index(mock.sentinel.fake_network)

        self.assertEqual(mock.sentinel.iface_index, index)
        self.assertIn(mock.sentinel.fake_network, self.utils._net_if_indexes)
        self.utils._scimv2.MSFT_NetAdapter.assert_called_once_with(
            InterfaceDescription=description)

    def test_get_network_iface_index_cached(self):
        self.utils._net_if_indexes[mock.sentinel.fake_network] = (
            mock.sentinel.iface_index)

        index = self.utils._get_network_iface_index(mock.sentinel.fake_network)

        self.assertEqual(mock.sentinel.iface_index, index)
        self.assertFalse(self.utils._scimv2.MSFT_NetAdapter.called)

    @mock.patch.object(utils_nvgre.NvgreUtils, '_get_network_ifaces_by_name')
    def test_get_network_iface_ip(self, mock_get_net_ifaces):
        fake_network = mock.MagicMock(
            InterfaceIndex=mock.sentinel.iface_index,
            DriverDescription=self.utils._HYPERV_VIRT_ADAPTER)
        mock_get_net_ifaces.return_value = [fake_network]

        fake_netip = mock.MagicMock(IPAddress=mock.sentinel.provider_addr,
                                    PrefixLength=mock.sentinel.prefix_len)
        self.utils._scimv2.MSFT_NetIPAddress.return_value = [fake_netip]

        pair = self.utils.get_network_iface_ip(mock.sentinel.fake_network)

        self.assertEqual(
            (mock.sentinel.provider_addr, mock.sentinel.prefix_len), pair)

    @mock.patch.object(utils_nvgre.NvgreUtils, '_get_network_ifaces_by_name')
    def test_get_network_iface_ip_none(self, mock_get_net_ifaces):
        mock_get_net_ifaces.return_value = []
        pair = self.utils.get_network_iface_ip(mock.sentinel.fake_network)
        self.assertEqual((None, None), pair)
