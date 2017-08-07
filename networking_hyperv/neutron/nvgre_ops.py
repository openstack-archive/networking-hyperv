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

from os_win import utilsfactory
from oslo_log import log as logging
import six
import uuid

from networking_hyperv.common.i18n import _LI, _LW, _LE  # noqa
from networking_hyperv.neutron import config
from networking_hyperv.neutron import constants
from networking_hyperv.neutron import hyperv_agent_notifier
from networking_hyperv.neutron import neutron_client

CONF = config.CONF
LOG = logging.getLogger(__name__)


class HyperVNvgreOps(object):

    def __init__(self, physical_networks):
        self.topic = constants.AGENT_TOPIC
        self._vswitch_ips = {}
        self._tunneling_agents = {}
        self._nvgre_ports = []
        self._network_vsids = {}

        self._hyperv_utils = utilsfactory.get_networkutils()
        self._nvgre_utils = utilsfactory.get_nvgreutils()
        self._n_client = neutron_client.NeutronAPIClient()

        self._init_nvgre(physical_networks)

    def init_notifier(self, context, rpc_client):
        self.context = context
        self._notifier = hyperv_agent_notifier.AgentNotifierApi(
            self.topic, rpc_client)

    def _init_nvgre(self, physical_networks):
        for network in physical_networks:
            LOG.info("Adding provider route and address for network: %s",
                     network)
            self._nvgre_utils.create_provider_route(network)
            self._nvgre_utils.create_provider_address(
                network, CONF.NVGRE.provider_vlan_id)
            ip_addr, length = self._nvgre_utils.get_network_iface_ip(network)
            self._vswitch_ips[network] = ip_addr

    def _refresh_tunneling_agents(self):
        self._tunneling_agents.update(self._n_client.get_tunneling_agents())

    def lookup_update(self, kwargs):
        lookup_ip = kwargs.get('lookup_ip')
        lookup_details = kwargs.get('lookup_details')

        LOG.info("Lookup Received: %(lookup_ip)s, %(lookup_details)s",
                 {'lookup_ip': lookup_ip, 'lookup_details': lookup_details})
        if not lookup_ip or not lookup_details:
            return

        self._register_lookup_record(lookup_ip,
                                     lookup_details['customer_addr'],
                                     lookup_details['mac_addr'],
                                     lookup_details['customer_vsid'])

    def tunnel_update(self, context, tunnel_ip, tunnel_type):
        if tunnel_type != constants.TYPE_NVGRE:
            return
        self._notifier.tunnel_update(context, CONF.NVGRE.provider_tunnel_ip,
                                     tunnel_type)

    def _register_lookup_record(self, prov_addr, cust_addr, mac_addr, vsid):
        LOG.info('Creating LookupRecord: VSID: %(vsid)s MAC: %(mac_addr)s '
                 'Customer IP: %(cust_addr)s Provider IP: %(prov_addr)s',
                 dict(vsid=vsid,
                      mac_addr=mac_addr,
                      cust_addr=cust_addr,
                      prov_addr=prov_addr))

        self._nvgre_utils.create_lookup_record(
            prov_addr, cust_addr, mac_addr, vsid)

    def bind_nvgre_port(self, segmentation_id, network_name, port_id):
        mac_addr = self._hyperv_utils.get_vnic_mac_address(port_id)
        provider_addr = self._nvgre_utils.get_network_iface_ip(network_name)[0]
        customer_addr = self._n_client.get_port_ip_address(port_id)

        if not provider_addr or not customer_addr:
            LOG.warning('Cannot bind NVGRE port. Could not determine '
                        'provider address (%(prov_addr)s) or customer '
                        'address (%(cust_addr)s).',
                        {'prov_addr': provider_addr,
                         'cust_addr': customer_addr})
            return

        LOG.info('Binding VirtualSubnetID %(segmentation_id)s '
                 'to switch port %(port_id)s',
                 dict(segmentation_id=segmentation_id, port_id=port_id))
        self._hyperv_utils.set_vswitch_port_vsid(segmentation_id, port_id)

        # normal lookup record.
        self._register_lookup_record(
            provider_addr, customer_addr, mac_addr, segmentation_id)

        # lookup record for dhcp requests.
        self._register_lookup_record(
            self._vswitch_ips[network_name], constants.IPV4_DEFAULT,
            mac_addr, segmentation_id)

        LOG.info('Fanning out LookupRecord...')
        self._notifier.lookup_update(self.context,
                                     provider_addr,
                                     {'customer_addr': customer_addr,
                                      'mac_addr': mac_addr,
                                      'customer_vsid': segmentation_id})

    def bind_nvgre_network(self, segmentation_id, net_uuid, vswitch_name):
        subnets = self._n_client.get_network_subnets(net_uuid)
        if len(subnets) > 1:
            LOG.warning("Multiple subnets in the same network is not "
                        "supported.")
        subnet = subnets[0]
        try:
            cidr, gw = self._n_client.get_network_subnet_cidr_and_gateway(
                subnet)

            cust_route_string = vswitch_name + cidr + str(segmentation_id)
            rdid_uuid = str(uuid.uuid5(uuid.NAMESPACE_X500, cust_route_string))
            self._create_customer_routes(segmentation_id, cidr, gw, rdid_uuid)

        except Exception as ex:
            LOG.error("Exception caught: %s", ex)

        self._network_vsids[net_uuid] = segmentation_id
        self.refresh_nvgre_records(network_id=net_uuid)
        self._notifier.tunnel_update(
            self.context, CONF.NVGRE.provider_tunnel_ip, segmentation_id)

    def _create_customer_routes(self, segmentation_id, cidr, gw, rdid_uuid):
        self._nvgre_utils.clear_customer_routes(segmentation_id)

        # create cidr -> 0.0.0.0/0 customer route
        self._nvgre_utils.create_customer_route(
            segmentation_id, cidr, constants.IPV4_DEFAULT, rdid_uuid)

        if not gw:
            LOG.info('Subnet does not have gateway configured. Skipping.')
        elif gw.split('.')[-1] == '1':
            LOG.error('Subnet has unsupported gateway IP ending in 1: '
                      '%s. Any other gateway IP is supported.', gw)
        else:
            # create 0.0.0.0/0 -> gateway customer route
            self._nvgre_utils.create_customer_route(
                segmentation_id, '%s/0' % constants.IPV4_DEFAULT, gw,
                rdid_uuid)

            # create metadata address -> gateway customer route
            metadata_addr = '%s/32' % CONF.AGENT.neutron_metadata_address
            self._nvgre_utils.create_customer_route(
                segmentation_id, metadata_addr, gw, rdid_uuid)

    def refresh_nvgre_records(self, **kwargs):
        self._refresh_tunneling_agents()
        ports = self._n_client.get_network_ports(**kwargs)

        # process ports that were not processed yet.
        # process ports that are bound to tunneling_agents.
        ports = [p for p in ports if p['id'] not in self._nvgre_ports and
                 p['binding:host_id'] in self._tunneling_agents and
                 p['network_id'] in six.iterkeys(self._network_vsids)]

        for port in ports:
            tunneling_ip = self._tunneling_agents[port['binding:host_id']]
            customer_addr = port['fixed_ips'][0]['ip_address']
            mac_addr = port['mac_address'].replace(':', '')
            segmentation_id = self._network_vsids[port['network_id']]
            try:
                self._register_lookup_record(
                    tunneling_ip, customer_addr, mac_addr, segmentation_id)

                self._nvgre_ports.append(port['id'])
            except Exception as ex:
                LOG.error("Exception while adding lookup_record: %(ex)s. "
                          "VSID: %(vsid)s MAC: %(mac_address)s Customer "
                          "IP:%(cust_addr)s Provider IP: %(prov_addr)s",
                          dict(ex=ex,
                               vsid=segmentation_id,
                               mac_address=mac_addr,
                               cust_addr=customer_addr,
                               prov_addr=tunneling_ip))
