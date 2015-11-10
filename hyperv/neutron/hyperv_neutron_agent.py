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

import collections
import re
import time

from oslo_config import cfg
from oslo_log import log as logging
import six

from hyperv.common.i18n import _, _LE, _LI  # noqa
from hyperv.neutron import constants
from hyperv.neutron import hyperv_agent_notifier
from hyperv.neutron import nvgre_ops
from hyperv.neutron import utils
from hyperv.neutron import utilsfactory

nvgre_opts = [
    cfg.BoolOpt('enable_support',
                default=False,
                help=_('Enables Hyper-V NVGRE. '
                       'Requires Windows Server 2012 or above.')),
    cfg.IntOpt('provider_vlan_id',
               default=0,
               help=_('Specifies the VLAN ID of the physical network, required'
                      ' for setting the NVGRE Provider Address.')),
    cfg.StrOpt('provider_tunnel_ip',
               default=None,
               help=_('Specifies the tunnel IP which will be used and '
                      'reported by this host for NVGRE networks.')),
]

CONF = cfg.CONF
CONF.register_opts(nvgre_opts, "NVGRE")

LOG = logging.getLogger(__name__)


class HyperVNeutronAgentMixin(object):

    def __init__(self, conf=None):
        """Initializes local configuration of the Hyper-V Neutron Agent.

        :param conf: dict or dict-like object containing the configuration
                     details used by this Agent. If None is specified, default
                     values are used instead. conf format is as follows:
        {
            'host': string,
            'AGENT': {'polling_interval': int,
                       'local_network_vswitch': string,
                       'physical_network_vswitch_mappings': array,
                       'enable_metrics_collection': boolean,
                       'metrics_max_retries': int},
            'SECURITYGROUP': {'enable_security_group': boolean}
        }

        For more information on the arguments, their meaning and their default
        values, visit: http://docs.openstack.org/juno/config-reference/content/
networking-plugin-hyperv_agent.html
        """

        super(HyperVNeutronAgentMixin, self).__init__()
        self._utils = utilsfactory.get_hypervutils()
        self._utils.init_caches()
        self._network_vswitch_map = {}
        self._port_metric_retries = {}

        self.plugin_rpc = None
        self.context = None
        self.client = None
        self.connection = None
        self.endpoints = None
        self.topic = constants.AGENT_TOPIC

        self._nvgre_enabled = False

        conf = conf or {}
        agent_conf = conf.get('AGENT', {})
        security_conf = conf.get('SECURITYGROUP', {})

        self._host = conf.get('host', None)

        self._polling_interval = agent_conf.get('polling_interval', 2)
        self._local_network_vswitch = agent_conf.get('local_network_vswitch',
                                                     'private')
        self._phys_net_map = agent_conf.get(
            'physical_network_vswitch_mappings', [])
        self.enable_metrics_collection = agent_conf.get(
            'enable_metrics_collection', False)
        self._metrics_max_retries = agent_conf.get('metrics_max_retries', 100)

        self.enable_security_groups = security_conf.get(
            'enable_security_group', False)

        self._load_physical_network_mappings(self._phys_net_map)

    def _load_physical_network_mappings(self, phys_net_vswitch_mappings):
        self._physical_network_mappings = collections.OrderedDict()
        for mapping in phys_net_vswitch_mappings:
            parts = mapping.split(':')
            if len(parts) != 2:
                LOG.debug('Invalid physical network mapping: %s', mapping)
            else:
                pattern = re.escape(parts[0].strip()).replace('\\*', '.*')
                vswitch = parts[1].strip()
                self._physical_network_mappings[pattern] = vswitch

    def _init_nvgre(self):
        # if NVGRE is enabled, self._nvgre_ops is required in order to properly
        # set the agent state (see get_agent_configrations method).

        if not CONF.NVGRE.enable_support:
            return

        if not CONF.NVGRE.provider_tunnel_ip:
            err_msg = _('enable_nvgre_support is set to True, but provider '
                        'tunnel IP is not configured. Check neutron.conf '
                        'config file.')
            LOG.error(err_msg)
            raise utils.HyperVException(msg=err_msg)

        self._nvgre_enabled = True
        self._nvgre_ops = nvgre_ops.HyperVNvgreOps(
            list(self._physical_network_mappings.values()))

        self._nvgre_ops.init_notifier(self.context, self.client)
        self._nvgre_ops.tunnel_update(self.context,
                                      CONF.NVGRE.provider_tunnel_ip,
                                      constants.TYPE_NVGRE)

        # setup Hyper-V Agent Lookup Record update consumer
        topic = hyperv_agent_notifier.get_topic_name(
            self.topic, constants.LOOKUP, constants.UPDATE)
        self.connection.create_consumer(topic, self.endpoints, fanout=True)

        # the created consumer is the last connection server.
        # need to start it in order for it to consume.
        self.connection.servers[-1].start()

    def get_agent_configurations(self):
        configurations = {'vswitch_mappings': self._physical_network_mappings}
        if CONF.NVGRE.enable_support:
            configurations['arp_responder_enabled'] = False
            configurations['tunneling_ip'] = CONF.NVGRE.provider_tunnel_ip
            configurations['devices'] = 1
            configurations['l2_population'] = False
            configurations['tunnel_types'] = [constants.TYPE_NVGRE]
            configurations['enable_distributed_routing'] = False
            configurations['bridge_mappings'] = {}
        return configurations

    def _get_vswitch_for_physical_network(self, phys_network_name):
        for pattern in self._physical_network_mappings:
            if phys_network_name is None:
                phys_network_name = ''
            if re.match(pattern, phys_network_name):
                return self._physical_network_mappings[pattern]
        # Not found in the mappings, the vswitch has the same name
        return phys_network_name

    def _get_network_vswitch_map_by_port_id(self, port_id):
        for network_id, map in six.iteritems(self._network_vswitch_map):
            if port_id in map['ports']:
                return (network_id, map)

        # if the port was not found, just return (None, None)
        return (None, None)

    def network_delete(self, context, network_id=None):
        LOG.debug("network_delete received. "
                  "Deleting network %s", network_id)
        # The network may not be defined on this agent
        if network_id in self._network_vswitch_map:
            self._reclaim_local_network(network_id)
        else:
            LOG.debug("Network %s not defined on agent.", network_id)

    def port_delete(self, context, port_id=None):
        LOG.debug("port_delete received")
        self._port_unbound(port_id)

    def port_update(self, context, port=None, network_type=None,
                    segmentation_id=None, physical_network=None):
        LOG.debug("port_update received")
        if self.enable_security_groups:
            if 'security_groups' in port:
                self.sec_groups_agent.refresh_firewall()

        self._treat_vif_port(
            port['id'], port['network_id'],
            network_type, physical_network,
            segmentation_id, port['admin_state_up'])

    def tunnel_update(self, context, **kwargs):
        LOG.info(_LI('tunnel_update received: kwargs: %s'), kwargs)
        tunnel_ip = kwargs.get('tunnel_ip')
        if tunnel_ip == CONF.NVGRE.provider_tunnel_ip:
            # the notification should be ignored if it originates from this
            # node.
            return

        tunnel_type = kwargs.get('tunnel_type')
        self._nvgre_ops.tunnel_update(context, tunnel_ip, tunnel_type)

    def lookup_update(self, context, **kwargs):
        self._nvgre_ops.lookup_update(kwargs)

    def _get_vswitch_name(self, network_type, physical_network):
        if network_type != constants.TYPE_LOCAL:
            vswitch_name = self._get_vswitch_for_physical_network(
                physical_network)
        else:
            vswitch_name = self._local_network_vswitch
        return vswitch_name

    def _provision_network(self, port_id,
                           net_uuid, network_type,
                           physical_network,
                           segmentation_id):
        LOG.info(_LI("Provisioning network %s"), net_uuid)

        vswitch_name = self._get_vswitch_name(network_type, physical_network)
        if network_type == constants.TYPE_VLAN:
            self._utils.set_switch_external_port_trunk_vlan(
                vswitch_name, segmentation_id, constants.TRUNK_ENDPOINT_MODE)
        elif network_type == constants.TYPE_NVGRE and self._nvgre_enabled:
            self._nvgre_ops.bind_nvgre_network(
                segmentation_id, net_uuid, vswitch_name)
        elif network_type == constants.TYPE_FLAT:
            # Nothing to do
            pass
        elif network_type == constants.TYPE_LOCAL:
            # TODO(alexpilotti): Check that the switch type is private
            # or create it if not existing
            pass
        else:
            raise utils.HyperVException(
                msg=(_("Cannot provision unknown network type %(network_type)s"
                       " for network %(net_uuid)s") %
                     dict(network_type=network_type, net_uuid=net_uuid)))

        map = {
            'network_type': network_type,
            'vswitch_name': vswitch_name,
            'ports': [],
            'vlan_id': segmentation_id}
        self._network_vswitch_map[net_uuid] = map

    def _reclaim_local_network(self, net_uuid):
        LOG.info(_LI("Reclaiming local network %s"), net_uuid)
        del self._network_vswitch_map[net_uuid]

    def _port_bound(self, port_id,
                    net_uuid,
                    network_type,
                    physical_network,
                    segmentation_id):
        LOG.debug("Binding port %s", port_id)

        if net_uuid not in self._network_vswitch_map:
            self._provision_network(
                port_id, net_uuid, network_type,
                physical_network, segmentation_id)

        map = self._network_vswitch_map[net_uuid]
        map['ports'].append(port_id)

        self._utils.connect_vnic_to_vswitch(map['vswitch_name'], port_id)

        if network_type == constants.TYPE_VLAN:
            LOG.info(_LI('Binding VLAN ID %(segmentation_id)s '
                         'to switch port %(port_id)s'),
                     dict(segmentation_id=segmentation_id, port_id=port_id))
            self._utils.set_vswitch_port_vlan_id(
                segmentation_id,
                port_id)
        elif network_type == constants.TYPE_NVGRE and self._nvgre_enabled:
            self._nvgre_ops.bind_nvgre_port(
                segmentation_id, map['vswitch_name'], port_id)
        elif network_type == constants.TYPE_FLAT:
            # Nothing to do
            pass
        elif network_type == constants.TYPE_LOCAL:
            # Nothing to do
            pass
        else:
            LOG.error(_LE('Unsupported network type %s'), network_type)

        if self.enable_metrics_collection:
            self._utils.enable_port_metrics_collection(port_id)
            self._port_metric_retries[port_id] = self._metrics_max_retries

    def _port_unbound(self, port_id, vnic_deleted=False):
        (net_uuid, map) = self._get_network_vswitch_map_by_port_id(port_id)

        if not net_uuid:
            LOG.debug('Port %s was not found on this agent.', port_id)
            return

        LOG.debug("Unbinding port %s", port_id)
        self._utils.disconnect_switch_port(port_id, vnic_deleted, True)
        map['ports'].remove(port_id)

        if not map['ports']:
            self._reclaim_local_network(net_uuid)

    def _port_enable_control_metrics(self):
        if not self.enable_metrics_collection:
            return

        for port_id in list(self._port_metric_retries.keys()):
            if self._utils.can_enable_control_metrics(port_id):
                self._utils.enable_control_metrics(port_id)
                LOG.info(_LI('Port metrics enabled for port: %s'), port_id)
                del self._port_metric_retries[port_id]
            elif self._port_metric_retries[port_id] < 1:
                self._utils.enable_control_metrics(port_id)
                LOG.error(_LE('Port metrics raw enabling for port: %s'),
                          port_id)
                del self._port_metric_retries[port_id]
            else:
                self._port_metric_retries[port_id] -= 1

    def _update_ports(self, registered_ports):
        ports = self._utils.get_vnic_ids()
        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

    def _treat_vif_port(self, port_id, network_id, network_type,
                        physical_network, segmentation_id,
                        admin_state_up):
        if self._utils.vnic_port_exists(port_id):
            if admin_state_up:
                self._port_bound(port_id, network_id, network_type,
                                 physical_network, segmentation_id)
            else:
                self._port_unbound(port_id)
        else:
            LOG.debug("No port %s defined on agent.", port_id)

    def _treat_devices_added(self, devices):
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                devices,
                self.agent_id)
        except Exception as e:
            LOG.debug("Unable to get ports details for "
                      "devices %(devices)s: %(e)s",
                      {'devices': devices, 'e': e})
            # resync is needed
            return True

        for device_details in devices_details_list:
            device = device_details['device']
            LOG.info(_LI("Adding port %s"), device)
            if 'port_id' in device_details:
                LOG.info(_LI("Port %(device)s updated. Details: "
                             "%(device_details)s"),
                         {'device': device, 'device_details': device_details})
                self._treat_vif_port(
                    device_details['port_id'],
                    device_details['network_id'],
                    device_details['network_type'],
                    device_details['physical_network'],
                    device_details['segmentation_id'],
                    device_details['admin_state_up'])

                # check if security groups is enabled.
                # if not, teardown the security group rules
                if self.enable_security_groups:
                    self.sec_groups_agent.prepare_devices_filter([device])
                else:
                    self._utils.remove_all_security_rules(
                        device_details['port_id'])
                self.plugin_rpc.update_device_up(self.context,
                                                 device,
                                                 self.agent_id,
                                                 self._host)
        return False

    def _treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_LI("Removing port %s"), device)
            try:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   self._host)
            except Exception as e:
                LOG.debug("Removing port failed for device %(device)s: %(e)s",
                          dict(device=device, e=e))
                resync = True
                continue
            self._port_unbound(device, vnic_deleted=True)
        return resync

    def _process_network_ports(self, port_info):
        resync_a = False
        resync_b = False
        if 'added' in port_info:
            resync_a = self._treat_devices_added(port_info['added'])
        if 'removed' in port_info:
            resync_b = self._treat_devices_removed(port_info['removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def daemon_loop(self):
        # init NVGRE after the RPC connection and context is created.
        self._init_nvgre()

        sync = True
        ports = set()

        while True:
            try:
                start = time.time()
                if sync:
                    LOG.info(_LI("Agent out of sync with plugin!"))
                    ports.clear()
                    sync = False

                port_info = self._update_ports(ports)

                # notify plugin about port deltas
                if port_info:
                    LOG.debug("Agent loop has new devices!")
                    # If treat devices fails - must resync with plugin
                    sync = self._process_network_ports(port_info)
                    ports = port_info['current']

                if self._nvgre_enabled:
                    self._nvgre_ops.refresh_nvgre_records()
                self._port_enable_control_metrics()
            except Exception:
                LOG.exception(_LE("Error in agent event loop"))

                # inconsistent cache might cause exceptions. for example, if a
                # port has been removed, it will be known in the next loop.
                # using the old switch port can cause exceptions.
                self._utils.update_cache()

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self._polling_interval):
                time.sleep(self._polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval "
                          "(%(polling_interval)s vs. %(elapsed)s)",
                          {'polling_interval': self._polling_interval,
                           'elapsed': elapsed})
