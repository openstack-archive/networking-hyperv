# Copyright (c) 2015 Cloudbase Solutions Srl
# Copyright (c) 2013 OpenStack Foundation
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

import re

from neutron.plugins.ml2.drivers import mech_agent
from neutron_lib.api.definitions import portbindings

from networking_hyperv.neutron import constants


class HypervMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using Hyper-V L2 Agent.

    The HypervMechanismDriver integrates the Ml2 Plugin with the
    Hyperv L2 Agent. Port binding with this driver requires the Hyper-V
    agent to be running on the port's host, and that agent to have
    connectivity to at least one segment of the port's network.
    """

    def __init__(self):
        super(HypervMechanismDriver, self).__init__(
            constants.AGENT_TYPE_HYPERV,
            constants.VIF_TYPE_HYPERV,
            {portbindings.CAP_PORT_FILTER: False},
            supported_vnic_types=[portbindings.VNIC_NORMAL,
                                  portbindings.VNIC_DIRECT])

    def get_allowed_network_types(self, agent=None):
        network_types = [constants.TYPE_LOCAL, constants.TYPE_FLAT,
                         constants.TYPE_VLAN]
        if agent is not None:
            tunnel_types = agent.get('configurations', {}).get('tunnel_types')
            if tunnel_types:
                network_types.extend(tunnel_types)
        return network_types

    def get_mappings(self, agent):
        return agent['configurations'].get('vswitch_mappings', {})

    def physnet_in_mappings(self, physnet, mappings):
        return any(re.match(pattern, physnet) for pattern in mappings)
