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

from keystoneauth1 import loading as ks_loading
from neutronclient.v2_0 import client as clientv20
from oslo_log import log as logging

from networking_hyperv.common.i18n import _LW, _LE  # noqa
from networking_hyperv.neutron import config
from networking_hyperv.neutron import constants

CONF = config.CONF
LOG = logging.getLogger(__name__)


class NeutronAPIClient(object):

    def __init__(self):
        self._init_client()

    def _init_client(self):
        session = ks_loading.load_session_from_conf_options(
            CONF, config.NEUTRON_GROUP)
        auth_plugin = ks_loading.load_auth_from_conf_options(
            CONF, config.NEUTRON_GROUP)

        self._client = clientv20.Client(
            session=session,
            auth=auth_plugin)

    def get_network_subnets(self, network_id):
        try:
            net = self._client.show_network(network_id)
            return net['network']['subnets']
        except Exception as ex:
            LOG.error("Could not retrieve network %(network_id)s . Error: "
                      "%(ex)s", {'network_id': network_id, 'ex': ex})

        return []

    def get_network_subnet_cidr_and_gateway(self, subnet_id):
        try:
            subnet = self._client.show_subnet(subnet_id)['subnet']
            return (str(subnet['cidr']), str(subnet['gateway_ip']))
        except Exception as ex:
            LOG.error("Could not retrieve subnet %(subnet_id)s . Error: "
                      "%(ex)s: ", {'subnet_id': subnet_id, 'ex': ex})

        return None, None

    def get_port_ip_address(self, port_id):
        try:
            port = self._client.show_port(port_id)
            fixed_ips = port['port']['fixed_ips'][0]
            return fixed_ips['ip_address']
        except Exception as ex:
            LOG.error("Could not retrieve port %(port_id)s . Error: "
                      "%(ex)s", {'port_id': port_id, 'ex': ex})

        return None

    def get_tunneling_agents(self):
        try:
            agents = self._client.list_agents()
            tunneling_agents = [
                a for a in agents['agents'] if constants.TYPE_NVGRE in
                a.get('configurations', {}).get('tunnel_types', [])]

            tunneling_ip_agents = [
                a for a in tunneling_agents if
                a.get('configurations', {}).get('tunneling_ip')]

            if len(tunneling_ip_agents) < len(tunneling_agents):
                LOG.warning('Some agents have NVGRE tunneling enabled, but'
                            ' do not provide tunneling_ip. Ignoring those '
                            'agents.')

            return dict([(a['host'], a['configurations']['tunneling_ip'])
                         for a in tunneling_ip_agents])
        except Exception as ex:
            LOG.error("Could not get tunneling agents. Error: %s", ex)
            return {}

    def get_network_ports(self, **kwargs):
        try:
            return self._client.list_ports(**kwargs)['ports']
        except Exception as ex:
            LOG.error("Exception caught: %s", ex)
        return []

    def get_port_profile_id(self, port_id):
        try:
            port = self._client.show_port(port_id)
            return "{%s}" % (port["port"]["binding:vif_details"]
                             ["port_profile_id"])
        except Exception:
            LOG.exception("Failed to retrieve profile id for port %s.",
                          port_id)
        return {}
