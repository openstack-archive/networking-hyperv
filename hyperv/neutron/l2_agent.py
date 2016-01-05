# Copyright 2015 Cloudbase Solutions Srl
#
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

import platform
import sys

from neutron.agent.common import config
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall

from hyperv.common.i18n import _, _LE, _LI  # noqa
from hyperv.neutron import constants as h_const
from hyperv.neutron import hyperv_neutron_agent

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class HyperVSecurityAgent(sg_rpc.SecurityGroupAgentRpc):

    def __init__(self, context, plugin_rpc):
        super(HyperVSecurityAgent, self).__init__(context, plugin_rpc)
        if sg_rpc.is_firewall_enabled():
            self._setup_rpc()

    @property
    def use_enhanced_rpc(self):
        return True

    def _setup_rpc(self):
        self.topic = topics.AGENT
        self.endpoints = [HyperVSecurityCallbackMixin(self)]
        consumers = [[topics.SECURITY_GROUP, topics.UPDATE]]

        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)


class HyperVSecurityCallbackMixin(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    target = oslo_messaging.Target(version='1.3')

    def __init__(self, sg_agent):
        super(HyperVSecurityCallbackMixin, self).__init__()
        self.sg_agent = sg_agent


class HyperVNeutronAgent(hyperv_neutron_agent.HyperVNeutronAgentMixin):
    # Set RPC API version to 1.1 by default.
    target = oslo_messaging.Target(version='1.1')

    def __init__(self):
        self._setup_rpc()
        super(HyperVNeutronAgent, self).__init__(cfg.CONF)
        self._set_agent_state()

    def _set_agent_state(self):
        configurations = self._get_agent_configurations()
        self.agent_state = {
            'binary': 'neutron-hyperv-agent',
            'host': CONF.host,
            'configurations': configurations,
            'agent_type': h_const.AGENT_TYPE_HYPERV,
            'topic': n_const.L2_AGENT_TOPIC,
            'start_flag': True}

    def _get_agent_configurations(self):
        configurations = {'vswitch_mappings': self._physical_network_mappings}
        if CONF.NVGRE.enable_support:
            configurations['arp_responder_enabled'] = False
            configurations['tunneling_ip'] = CONF.NVGRE.provider_tunnel_ip
            configurations['devices'] = 1
            configurations['l2_population'] = False
            configurations['tunnel_types'] = [h_const.TYPE_NVGRE]
            configurations['enable_distributed_routing'] = False
            configurations['bridge_mappings'] = {}
        return configurations

    def _report_state(self):
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def _setup_rpc(self):
        self.agent_id = 'hyperv_%s' % platform.node()
        self.topic = topics.AGENT
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        self.sec_groups_agent = HyperVSecurityAgent(self.context,
                                                    self.sg_plugin_rpc)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # Handle updates from service
        self.endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.PORT, topics.DELETE]]
        if CONF.NVGRE.enable_support:
            consumers.append([h_const.TUNNEL, topics.UPDATE])
            consumers.append([h_const.LOOKUP, h_const.UPDATE])

        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)

        self.client = n_rpc.get_client(self.target)
        report_interval = CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)


def main():
    config.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()

    hyperv_agent = HyperVNeutronAgent()

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    hyperv_agent.daemon_loop()
