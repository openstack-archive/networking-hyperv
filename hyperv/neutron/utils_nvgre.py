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

import sys
import uuid

from oslo_config import cfg
from oslo_log import log as logging

from hyperv.common.i18n import _, _LI, _LW, _LE  # noqa
from hyperv.neutron import constants
from hyperv.neutron import utilsv2

# Check needed for unit testing on Unix
if sys.platform == 'win32':
    import wmi

agent_opts = [
    cfg.StrOpt('neutron_metadata_address',
               default='169.254.169.254',
               help=_('Specifies the address which will serve the metadata for'
                      ' the instance.')),
]

CONF = cfg.CONF
CONF.register_opts(agent_opts, "AGENT")

LOG = logging.getLogger(__name__)


class NvgreUtils(object):
    _HYPERV_VIRT_ADAPTER = 'Hyper-V Virtual Ethernet Adapter'
    _IPV4_ADDRESS_FAMILY = 2

    _WNV_BIND_NAME = 'Wnv'
    _TRANSLATE_NAT = 0
    _TRANSLATE_ENCAP = 1

    _LOOKUP_RECORD_TYPE_STATIC = 0
    _LOOKUP_RECORD_TYPE_L2_ONLY = 3

    _STDCIMV2_NAMESPACE = '//./root/StandardCimv2'

    def __init__(self):
        super(NvgreUtils, self).__init__()
        self._utils = utilsv2.HyperVUtilsV2()
        self._net_if_indexes = {}
        if sys.platform == 'win32':
            self._scimv2 = wmi.WMI(moniker=self._STDCIMV2_NAMESPACE)

    def create_provider_address(self, network_name, provider_vlan_id):
        iface_index = self._get_network_iface_index(network_name)
        (provider_addr, prefix_len) = self.get_network_iface_ip(network_name)

        if iface_index is None or provider_addr is None:
            return None

        provider = (
            self._scimv2.MSFT_NetVirtualizationProviderAddressSettingData(
                ProviderAddress=provider_addr))

        if provider:
            if (provider[0].VlanID == provider_vlan_id and
                    provider[0].InterfaceIndex == iface_index):
                # ProviderAddress already exists.
                return
            # ProviderAddress exists, but with different VlanID or iface index.
            provider[0].Delete_()

        self._create_new_object(
            self._scimv2.MSFT_NetVirtualizationProviderAddressSettingData,
            ProviderAddress=provider_addr,
            VlanID=provider_vlan_id,
            InterfaceIndex=iface_index,
            PrefixLength=prefix_len)

    def create_provider_route(self, network_name):
        iface_index = self._get_network_iface_index(network_name)

        if iface_index is None:
            return

        routes = self._scimv2.MSFT_NetVirtualizationProviderRouteSettingData(
            InterfaceIndex=iface_index, NextHop=constants.IPV4_DEFAULT)

        if not routes:
            self._create_new_object(
                self._scimv2.MSFT_NetVirtualizationProviderRouteSettingData,
                InterfaceIndex=iface_index,
                DestinationPrefix='%s/0' % constants.IPV4_DEFAULT,
                NextHop=constants.IPV4_DEFAULT)

    def create_customer_routes(self, vsid, network_name, dest_prefix, gateway):
        cust_route_string = network_name + dest_prefix + str(vsid)
        rdid_uuid = uuid.uuid5(uuid.NAMESPACE_X500, cust_route_string)
        rdid_uuid = str(rdid_uuid)

        routes = self._scimv2.MSFT_NetVirtualizationCustomerRouteSettingData(
            VirtualSubnetID=vsid)

        for route in routes:
            route.Delete_()

        # TODO(claudiub): the logic should be moved to nvgre_ops. This should
        # create only one router per call.

        self._create_cust_route(
            vsid, dest_prefix, constants.IPV4_DEFAULT, rdid_uuid)

        if not gateway:
            LOG.info(_LI('Subnet does not have gateway configured. Skipping.'))
            return

        if gateway.split('.')[-1] == '1':
            LOG.error(_LE('Subnet has unsupported gateway IP ending in 1: %s. '
                          'Any other gateway IP is supported.'), gateway)
            return

        # TODO(claudiub): what if there is no gateway?
        self._create_cust_route(
            vsid, '%s/0' % constants.IPV4_DEFAULT, gateway, rdid_uuid)

        # customer route for metadata is also necessary.
        self._create_cust_route(
            vsid, '%s/32' % CONF.AGENT.neutron_metadata_address, gateway,
            rdid_uuid)

    def _create_cust_route(self, vsid, dest_prefix, next_hop, rdid_uuid):
        self._create_new_object(
            self._scimv2.MSFT_NetVirtualizationCustomerRouteSettingData,
            VirtualSubnetID=vsid,
            DestinationPrefix=dest_prefix,
            NextHop=next_hop,
            Metric=255,
            RoutingDomainID='{%s}' % rdid_uuid)

    def create_lookup_record(self, provider_addr, customer_addr, mac, vsid):
        # check for existing entry.
        lrec = self._scimv2.MSFT_NetVirtualizationLookupRecordSettingData(
            CustomerAddress=customer_addr, VirtualSubnetID=vsid)
        if (lrec and lrec[0].VirtualSubnetID == vsid and
                lrec[0].ProviderAddress == provider_addr and
                lrec[0].MACAddress == mac):
            # lookup record already exists, nothing to do.
            return

        # create new lookup record.
        if lrec:
            lrec[0].Delete_()

        if constants.IPV4_DEFAULT == customer_addr:
            # customer address used for DHCP requests.
            record_type = self._LOOKUP_RECORD_TYPE_L2_ONLY
        else:
            record_type = self._LOOKUP_RECORD_TYPE_STATIC

        self._create_new_object(
            self._scimv2.MSFT_NetVirtualizationLookupRecordSettingData,
            VirtualSubnetID=vsid,
            Rule=self._TRANSLATE_ENCAP,
            Type=record_type,
            MACAddress=mac,
            CustomerAddress=customer_addr,
            ProviderAddress=provider_addr)

    def _create_new_object(self, object_class, **args):
        new_obj = object_class.new(**args)
        new_obj.Put_()
        return new_obj

    def _get_network_ifaces_by_name(self, network_name):
        return [n for n in self._scimv2.MSFT_NetAdapter() if
                n.Name.find(network_name) >= 0]

    def _get_network_iface_index(self, network_name):
        if self._net_if_indexes.get(network_name):
            return self._net_if_indexes[network_name]

        description = (
            self._utils.get_vswitch_external_network_name(network_name))

        # physical NIC and vswitch must have the same MAC address.
        networks = self._scimv2.MSFT_NetAdapter(
            InterfaceDescription=description)

        if networks:
            self._net_if_indexes[network_name] = networks[0].InterfaceIndex
            return networks[0].InterfaceIndex

    def get_network_iface_ip(self, network_name):
        networks = [n for n in self._get_network_ifaces_by_name(network_name)
                    if n.DriverDescription == self._HYPERV_VIRT_ADAPTER]

        if networks:
            ip_addr = self._scimv2.MSFT_NetIPAddress(
                InterfaceIndex=networks[0].InterfaceIndex,
                AddressFamily=self._IPV4_ADDRESS_FAMILY)

            if ip_addr:
                return (ip_addr[0].IPAddress, ip_addr[0].PrefixLength)
            else:
                LOG.error(_LE('No IP Address could be found for network: %s'),
                          network_name)
        else:
            LOG.error(_LE('No vswitch was found with name: %s'), network_name)

        return (None, None)
