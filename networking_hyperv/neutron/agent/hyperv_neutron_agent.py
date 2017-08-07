# Copyright 2013 Cloudbase Solutions SRL
# Copyright 2013 Pedro Navarro Perez
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

from neutron.agent.l2.extensions import qos as qos_extension
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import topics
from neutron.conf.agent import common as neutron_config
from os_win import exceptions
from os_win import utilsfactory
from oslo_log import log as logging
import oslo_messaging

from networking_hyperv.common.i18n import _, _LI, _LW, _LE    # noqa
from networking_hyperv.neutron import _common_utils as c_util
from networking_hyperv.neutron.agent import layer2 as hyperv_base
from networking_hyperv.neutron import config
from networking_hyperv.neutron import constants as h_constant
from networking_hyperv.neutron import exception
from networking_hyperv.neutron import nvgre_ops
from networking_hyperv.neutron import trunk_driver

CONF = config.CONF
LOG = logging.getLogger(__name__)

_port_synchronized = c_util.get_port_synchronized_decorator('n-hv-agent-')


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


class HyperVNeutronAgent(hyperv_base.Layer2Agent):

    _AGENT_BINARY = "neutron-hyperv-agent"
    _AGENT_TYPE = h_constant.AGENT_TYPE_HYPERV

    def __init__(self):
        super(HyperVNeutronAgent, self).__init__()
        self._agent_id = 'hyperv_%s' % platform.node()

        self._qos_ext = None
        self._nvgre_enabled = False

        self._metricsutils = utilsfactory.get_metricsutils()
        self._port_metric_retries = {}

        agent_conf = CONF.get('AGENT', {})
        security_conf = CONF.get('SECURITYGROUP', {})
        self._enable_metrics_collection = agent_conf.get(
            'enable_metrics_collection', False)
        self._metrics_max_retries = agent_conf.get('metrics_max_retries', 100)
        self._enable_security_groups = security_conf.get(
            'enable_security_group', False)

        self._init_nvgre()

    def _get_agent_configurations(self):
        configurations = {'vswitch_mappings': self._physical_network_mappings}
        if CONF.NVGRE.enable_support:
            configurations['arp_responder_enabled'] = False
            configurations['tunneling_ip'] = CONF.NVGRE.provider_tunnel_ip
            configurations['devices'] = 1
            configurations['l2_population'] = False
            configurations['tunnel_types'] = [h_constant.TYPE_NVGRE]
            configurations['enable_distributed_routing'] = False
            configurations['bridge_mappings'] = {}
        return configurations

    def _setup(self):
        """Setup the layer two agent."""
        super(HyperVNeutronAgent, self)._setup()

        self._sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self._sec_groups_agent = HyperVSecurityAgent(self._context,
                                                     self._sg_plugin_rpc)
        self._vlan_driver = trunk_driver.HyperVTrunkDriver(self._context)
        if CONF.NVGRE.enable_support:
            self._consumers.append([h_constant.TUNNEL, topics.UPDATE])
            self._consumers.append([h_constant.LOOKUP, h_constant.UPDATE])

    def _setup_qos_extension(self):
        """Setup the QOS extension if it is required."""
        if not CONF.AGENT.enable_qos_extension:
            return
        self._qos_ext = qos_extension.QosAgentExtension()
        self._qos_ext.consume_api(self)
        self._qos_ext.initialize(self._connection, 'hyperv')

    def _init_nvgre(self):
        # if NVGRE is enabled, self._nvgre_ops is required in order to properly
        # set the agent state (see get_agent_configrations method).
        if not CONF.NVGRE.enable_support:
            return

        if not CONF.NVGRE.provider_tunnel_ip:
            err_msg = _('enable_nvgre_support is set to True, but '
                        'provider tunnel IP is not configured. '
                        'Check neutron.conf config file.')
            LOG.error(err_msg)
            raise exception.NetworkingHyperVException(err_msg)

        self._nvgre_enabled = True
        self._nvgre_ops = nvgre_ops.HyperVNvgreOps(
            list(self._physical_network_mappings.values()))

        self._nvgre_ops.init_notifier(self._context, self._client)
        self._nvgre_ops.tunnel_update(self._context,
                                      CONF.NVGRE.provider_tunnel_ip,
                                      h_constant.TYPE_NVGRE)

    def _provision_network(self, port_id, net_uuid, network_type,
                           physical_network, segmentation_id):
        """Provision the network with the received information."""
        LOG.info("Provisioning network %s", net_uuid)

        vswitch_name = self._get_vswitch_name(network_type, physical_network)
        if network_type == h_constant.TYPE_VLAN:
            # Nothing to do
            pass
        elif network_type == h_constant.TYPE_FLAT:
            # Nothing to do
            pass
        elif network_type == h_constant.TYPE_LOCAL:
            # TODO(alexpilotti): Check that the switch type is private
            # or create it if not existing.
            pass
        elif network_type == h_constant.TYPE_NVGRE and self._nvgre_enabled:
            self._nvgre_ops.bind_nvgre_network(segmentation_id, net_uuid,
                                               vswitch_name)
        else:
            raise exception.NetworkingHyperVException(
                (_("Cannot provision unknown network type "
                   "%(network_type)s for network %(net_uuid)s") %
                 dict(network_type=network_type, net_uuid=net_uuid)))

        vswitch_map = {
            'network_type': network_type,
            'vswitch_name': vswitch_name,
            'ports': [],
            'vlan_id': segmentation_id}
        self._network_vswitch_map[net_uuid] = vswitch_map

    def _port_bound(self, port_id, network_id, network_type, physical_network,
                    segmentation_id):
        """Bind the port to the recived network."""
        super(HyperVNeutronAgent, self)._port_bound(
            port_id, network_id, network_type, physical_network,
            segmentation_id
        )
        vswitch_map = self._network_vswitch_map[network_id]

        if network_type == h_constant.TYPE_VLAN:
            self._vlan_driver.bind_vlan_port(port_id, segmentation_id)
        elif network_type == h_constant.TYPE_NVGRE and self._nvgre_enabled:
            self._nvgre_ops.bind_nvgre_port(
                segmentation_id, vswitch_map['vswitch_name'], port_id)
        elif network_type == h_constant.TYPE_FLAT:
            pass    # Nothing to do
        elif network_type == h_constant.TYPE_LOCAL:
            pass    # Nothing to do
        else:
            LOG.error('Unsupported network type %s', network_type)

        if self._enable_metrics_collection:
            self._utils.add_metrics_collection_acls(port_id)
            self._port_metric_retries[port_id] = self._metrics_max_retries

    def _port_enable_control_metrics(self):
        if not self._enable_metrics_collection:
            return

        for port_id in list(self._port_metric_retries.keys()):
            try:
                if self._utils.is_metrics_collection_allowed(port_id):
                    self._metricsutils.enable_port_metrics_collection(port_id)
                    LOG.info('Port metrics enabled for port: %s', port_id)
                    del self._port_metric_retries[port_id]
                elif self._port_metric_retries[port_id] < 1:
                    self._metricsutils.enable_port_metrics_collection(port_id)
                    LOG.error('Port metrics raw enabling for port: %s',
                              port_id)
                    del self._port_metric_retries[port_id]
                else:
                    self._port_metric_retries[port_id] -= 1
            except exceptions.NotFound:
                # the vNIC no longer exists. it might have been removed or
                # the VM it was attached to was destroyed.
                LOG.warning("Port %s no longer exists. Cannot enable "
                            "metrics.", port_id)
                del self._port_metric_retries[port_id]

    @_port_synchronized
    def _treat_vif_port(self, port_id, network_id, network_type,
                        physical_network, segmentation_id,
                        admin_state_up):
        if admin_state_up:
            self._port_bound(port_id, network_id, network_type,
                             physical_network, segmentation_id)
            # check if security groups is enabled.
            # if not, teardown the security group rules
            if self._enable_security_groups:
                self._sec_groups_agent.refresh_firewall([port_id])
            else:
                self._utils.remove_all_security_rules(port_id)
        else:
            self._port_unbound(port_id)
            self._sec_groups_agent.remove_devices_filter([port_id])

    def _process_added_port(self, device_details):
        super(HyperVNeutronAgent, self)._process_added_port(
            device_details)

        if CONF.AGENT.enable_qos_extension:
            self._qos_ext.handle_port(self._context, device_details)

    def _process_removed_port(self, device):
        super(HyperVNeutronAgent, self)._process_removed_port(device)
        try:
            self._sec_groups_agent.remove_devices_filter([device])
        except Exception:
            LOG.exception("Exception encountered while processing"
                          " port %s.", device)
            # Readd the port as "removed", so it can be reprocessed.
            self._removed_ports.add(device)
            raise

    def _work(self):
        """Process the information regarding the available ports."""
        super(HyperVNeutronAgent, self)._work()
        if self._nvgre_enabled:
            self._nvgre_ops.refresh_nvgre_records()
        self._port_enable_control_metrics()

    def tunnel_update(self, context, **kwargs):
        LOG.info('tunnel_update received: kwargs: %s', kwargs)
        tunnel_ip = kwargs.get('tunnel_ip')
        if tunnel_ip == CONF.NVGRE.provider_tunnel_ip:
            # the notification should be ignored if it originates from this
            # node.
            return

        tunnel_type = kwargs.get('tunnel_type')
        self._nvgre_ops.tunnel_update(context, tunnel_ip, tunnel_type)

    def lookup_update(self, context, **kwargs):
        self._nvgre_ops.lookup_update(kwargs)


def main():
    """The entry point for the Hyper-V Neutron Agent."""
    neutron_config.register_agent_state_opts_helper(CONF)
    common_config.init(sys.argv[1:])
    neutron_config.setup_logging()

    hyperv_agent = HyperVNeutronAgent()

    # Start everything.
    LOG.info("Agent initialized successfully, now running... ")
    hyperv_agent.daemon_loop()
