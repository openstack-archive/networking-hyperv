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
from concurrent import futures
import re
import threading
import time

from os_win import exceptions
from os_win import utilsfactory
from oslo_config import cfg
from oslo_log import log as logging
import six

from hyperv.common.i18n import _, _LE, _LW, _LI  # noqa
from hyperv.neutron import _common_utils as c_util
from hyperv.neutron import constants
from hyperv.neutron import exception
from hyperv.neutron import nvgre_ops

CONF = cfg.CONF
CONF.import_group('NVGRE', 'hyperv.neutron.config')
LOG = logging.getLogger(__name__)

_port_synchronized = c_util.get_port_synchronized_decorator('n-hv-agent-')


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
        self._metricsutils = utilsfactory.get_metricsutils()
        self._utils = utilsfactory.get_networkutils()
        self._utils.init_caches()
        self._network_vswitch_map = {}
        self._port_metric_retries = {}

        self._nvgre_enabled = False

        conf = conf or {}
        agent_conf = conf.get('AGENT', {})
        security_conf = conf.get('SECURITYGROUP', {})

        self._host = conf.get('host', None)

        self._polling_interval = agent_conf.get('polling_interval', 2)
        self._local_network_vswitch = agent_conf.get('local_network_vswitch',
                                                     'private')
        self._worker_count = agent_conf.get('worker_count')
        self._phys_net_map = agent_conf.get(
            'physical_network_vswitch_mappings', [])
        self.enable_metrics_collection = agent_conf.get(
            'enable_metrics_collection', False)
        self._metrics_max_retries = agent_conf.get('metrics_max_retries', 100)

        self.enable_security_groups = security_conf.get(
            'enable_security_group', False)

        self._load_physical_network_mappings(self._phys_net_map)
        self._init_nvgre()
        self._workers = futures.ThreadPoolExecutor(self._worker_count)

    def _load_physical_network_mappings(self, phys_net_vswitch_mappings):
        self._physical_network_mappings = collections.OrderedDict()
        for mapping in phys_net_vswitch_mappings:
            parts = mapping.split(':')
            if len(parts) != 2:
                LOG.debug('Invalid physical network mapping: %s', mapping)
            else:
                pattern = re.escape(parts[0].strip()).replace('\\*', '.*')
                pattern = pattern + '$'
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
            raise exception.NetworkingHyperVException(err_msg)

        self._nvgre_enabled = True
        self._nvgre_ops = nvgre_ops.HyperVNvgreOps(
            list(self._physical_network_mappings.values()))

        self._nvgre_ops.init_notifier(self.context, self.client)
        self._nvgre_ops.tunnel_update(self.context,
                                      CONF.NVGRE.provider_tunnel_ip,
                                      constants.TYPE_NVGRE)

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
        pass

    def port_update(self, context, port=None, network_type=None,
                    segmentation_id=None, physical_network=None):
        LOG.debug("port_update received: %s", port['id'])

        if self._utils.vnic_port_exists(port['id']):
            self._treat_vif_port(
                port['id'], port['network_id'],
                network_type, physical_network,
                segmentation_id, port['admin_state_up'])
        else:
            LOG.debug("No port %s defined on agent.", port['id'])

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
            # Nothing to do
            pass
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
            raise exception.NetworkingHyperVException(
                (_("Cannot provision unknown network type %(network_type)s"
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
            self._utils.add_metrics_collection_acls(port_id)
            self._port_metric_retries[port_id] = self._metrics_max_retries

    def _port_unbound(self, port_id, vnic_deleted=False):
        (net_uuid, map) = self._get_network_vswitch_map_by_port_id(port_id)

        if not net_uuid:
            LOG.debug('Port %s was not found on this agent.', port_id)
            return

        LOG.debug("Unbinding port %s", port_id)
        self._utils.remove_switch_port(port_id, vnic_deleted)
        map['ports'].remove(port_id)

        if not map['ports']:
            self._reclaim_local_network(net_uuid)

    def _port_enable_control_metrics(self):
        if not self.enable_metrics_collection:
            return

        for port_id in list(self._port_metric_retries.keys()):
            try:
                if self._utils.is_metrics_collection_allowed(port_id):
                    self._metricsutils.enable_port_metrics_collection(port_id)
                    LOG.info(_LI('Port metrics enabled for port: %s'), port_id)
                    del self._port_metric_retries[port_id]
                elif self._port_metric_retries[port_id] < 1:
                    self._metricsutils.enable_port_metrics_collection(port_id)
                    LOG.error(_LE('Port metrics raw enabling for port: %s'),
                              port_id)
                    del self._port_metric_retries[port_id]
                else:
                    self._port_metric_retries[port_id] -= 1
            except exceptions.NotFound:
                # the vNIC no longer exists. it might have been removed or
                # the VM it was attached to was destroyed.
                LOG.warning(_LW("Port %s no longer exists. Cannot enable "
                                "metrics."), port_id)
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
            if self.enable_security_groups:
                self.sec_groups_agent.refresh_firewall([port_id])
            else:
                self._utils.remove_all_security_rules(port_id)
        else:
            self._port_unbound(port_id)
            self.sec_groups_agent.remove_devices_filter([port_id])

    def _process_added_port(self, device_details):
        device = device_details['device']
        port_id = device_details['port_id']

        try:
            self._treat_vif_port(port_id,
                                 device_details['network_id'],
                                 device_details['network_type'],
                                 device_details['physical_network'],
                                 device_details['segmentation_id'],
                                 device_details['admin_state_up'])

            LOG.debug("Updating port %s status as UP.", port_id)
            self.plugin_rpc.update_device_up(self.context,
                                             device,
                                             self.agent_id,
                                             self._host)
            LOG.info("Port %s processed.", port_id)
        except Exception:
            LOG.exception(_LE("Exception encountered while processing port "
                              "%s."), port_id)

            # readd the port as "added", so it can be reprocessed.
            self._added_ports.add(device)

    def _treat_devices_added(self):
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                self._added_ports,
                self.agent_id)
        except Exception as e:
            LOG.debug("Unable to get ports details for "
                      "devices %(devices)s: %(e)s",
                      {'devices': self._added_ports, 'e': e})
            return

        for device_details in devices_details_list:
            device = device_details['device']
            LOG.info(_LI("Adding port %s"), device)
            if 'port_id' in device_details:
                LOG.info(_LI("Port %(device)s updated. Details: "
                             "%(device_details)s"),
                         {'device': device, 'device_details': device_details})

                self._workers.submit(self._process_added_port, device_details)

            # remove the port from added ports set, so it doesn't get
            # reprocessed.
            self._added_ports.discard(device)

    def _treat_devices_removed(self):
        for device in list(self._removed_ports):
            LOG.info(_LI("Removing port %s"), device)
            try:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   self._host)
            except Exception as e:
                LOG.debug("Removing port failed for device %(device)s: %(e)s",
                          dict(device=device, e=e))
                continue

            self._port_unbound(device, vnic_deleted=True)
            self.sec_groups_agent.remove_devices_filter([device])

            # if the port unbind was successful, remove the port from removed
            # set, so it won't be reprocessed.
            self._removed_ports.discard(device)

    def _process_added_port_event(self, port_name):
        LOG.info(_LI("Hyper-V VM vNIC added: %s"), port_name)
        self._added_ports.add(port_name)

    def _process_removed_port_event(self, port_name):
        LOG.info(_LI("Hyper-V VM vNIC removed: %s"), port_name)
        self._removed_ports.add(port_name)

    def _create_event_listeners(self):
        event_callback_pairs = [
            (self._utils.EVENT_TYPE_CREATE, self._process_added_port_event),
            (self._utils.EVENT_TYPE_DELETE, self._process_removed_port_event)]

        for event_type, callback in event_callback_pairs:
            listener = self._utils.get_vnic_event_listener(event_type)
            thread = threading.Thread(target=listener, args=(callback,))
            thread.start()

    def daemon_loop(self):
        self._added_ports = self._utils.get_vnic_ids()
        self._removed_ports = set()

        self._create_event_listeners()

        while True:
            try:
                start = time.time()

                # notify plugin about port deltas
                if self._added_ports:
                    LOG.debug("Agent loop has new devices!")
                    self._treat_devices_added()

                if self._removed_ports:
                    LOG.debug("Agent loop has lost devices...")
                    self._treat_devices_removed()

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
