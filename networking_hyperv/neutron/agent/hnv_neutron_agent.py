# Copyright 2017 Cloudbase Solutions SRL
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

"""This module contains the L2 Agent needed for HNV."""

import platform
import sys

from neutron.common import config as common_config
from neutron.conf.agent import common as neutron_config
from oslo_log import log as logging

from networking_hyperv.common.i18n import _LI    # noqa
from networking_hyperv.neutron import _common_utils as c_util
from networking_hyperv.neutron.agent import layer2 as hyperv_base
from networking_hyperv.neutron import config
from networking_hyperv.neutron import constants as h_const
from networking_hyperv.neutron import neutron_client

LOG = logging.getLogger(__name__)
CONF = config.CONF

_port_synchronized = c_util.get_port_synchronized_decorator('n-hv-agent-')


class HNVAgent(hyperv_base.Layer2Agent):

    _AGENT_BINARY = "neutron-hnv-agent"
    _AGENT_TYPE = h_const.AGENT_TYPE_HNV

    def __init__(self):
        super(HNVAgent, self).__init__()
        # Handle updates from service
        self._agent_id = 'hnv_%s' % platform.node()
        self._neutron_client = neutron_client.NeutronAPIClient()

    def _get_agent_configurations(self):
        return {
            'logical_network': CONF.HNV.logical_network,
            'vswitch_mappings': self._physical_network_mappings,
            'devices': 1,
            'l2_population': False,
            'tunnel_types': [],
            'bridge_mappings': {},
            'enable_distributed_routing': False,
        }

    def _provision_network(self, port_id, net_uuid, network_type,
                           physical_network, segmentation_id):
        """Provision the network with the received information."""
        LOG.info("Provisioning network %s", net_uuid)

        vswitch_name = self._get_vswitch_name(network_type, physical_network)
        vswitch_map = {
            'network_type': network_type,
            'vswitch_name': vswitch_name,
            'ports': [],
            'vlan_id': segmentation_id}
        self._network_vswitch_map[net_uuid] = vswitch_map

    def _port_bound(self, port_id, network_id, network_type, physical_network,
                    segmentation_id):
        """Bind the port to the recived network."""
        super(HNVAgent, self)._port_bound(port_id, network_id, network_type,
                                          physical_network, segmentation_id)
        LOG.debug("Getting the profile id for the current port.")
        profile_id = self._neutron_client.get_port_profile_id(port_id)

        LOG.debug("Trying to set port profile id %r for the current port %r.",
                  profile_id, port_id)
        self._utils.set_vswitch_port_profile_id(
            switch_port_name=port_id,
            profile_id=profile_id,
            profile_data=h_const.PROFILE_DATA,
            profile_name=h_const.PROFILE_NAME,
            net_cfg_instance_id=h_const.NET_CFG_INSTANCE_ID,
            cdn_label_id=h_const.CDN_LABEL_ID,
            cdn_label_string=h_const.CDN_LABEL_STRING,
            vendor_id=h_const.VENDOR_ID,
            vendor_name=h_const.VENDOR_NAME)

    @_port_synchronized
    def _treat_vif_port(self, port_id, network_id, network_type,
                        physical_network, segmentation_id,
                        admin_state_up):
        if admin_state_up:
            self._port_bound(port_id, network_id, network_type,
                             physical_network, segmentation_id)
        else:
            self._port_unbound(port_id)


def main():
    """The entry point for the HNV Agent."""
    neutron_config.register_agent_state_opts_helper(CONF)
    common_config.init(sys.argv[1:])
    neutron_config.setup_logging()

    hnv_agent = HNVAgent()

    # Start everything.
    LOG.info("Agent initialized successfully, now running... ")
    hnv_agent.daemon_loop()
