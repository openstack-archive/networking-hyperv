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

"""This module contains all the available contract classes."""

import abc
import collections
import re

import eventlet
from eventlet import tpool
from neutron.agent import rpc as agent_rpc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron_lib import constants as n_const
from os_win import exceptions as os_win_exc
from oslo_concurrency import lockutils
from oslo_log import log as logging
from oslo_service import loopingcall
import six

from networking_hyperv.common.i18n import _, _LI, _LE    # noqa
from networking_hyperv.neutron.agent import base as base_agent
from networking_hyperv.neutron import config
from networking_hyperv.neutron import constants

LOG = logging.getLogger(__name__)
CONF = config.CONF

_synchronized = lockutils.synchronized_with_prefix('n-hv-agent-')


class Layer2Agent(base_agent.BaseAgent):

    """Contract class for all the layer two agents."""

    _AGENT_TOPIC = n_const.L2_AGENT_TOPIC

    def __init__(self):
        super(Layer2Agent, self).__init__()
        self._network_vswitch_map = {}

        # The following sets contain ports that are to be processed.
        self._added_ports = set()
        self._removed_ports = set()

        # The following sets contain ports that have been processed.
        self._bound_ports = set()
        self._unbound_ports = set()

        self._physical_network_mappings = collections.OrderedDict()
        self._consumers = []
        self._event_callback_pairs = []

        # Setup the current agent.
        self._setup()
        self._set_agent_state()
        self._setup_rpc()

    def _setup(self):
        """Setup the layer two agent."""
        agent_config = CONF.get("AGENT", {})
        self._worker_count = agent_config.get('worker_count')
        self._phys_net_map = agent_config.get(
            'physical_network_vswitch_mappings', [])
        self._local_network_vswitch = agent_config.get(
            'local_network_vswitch', 'private')
        self._load_physical_network_mappings(self._phys_net_map)

        self._endpoints.append(self)
        self._event_callback_pairs.extend([
            (self._utils.EVENT_TYPE_CREATE, self._process_added_port_event),
            (self._utils.EVENT_TYPE_DELETE, self._process_removed_port_event)
        ])

        tpool.set_num_threads(self._worker_count)

    def _setup_qos_extension(self):
        """Setup the QOS extension if it is required."""
        pass

    def _setup_rpc(self):
        """Setup the RPC client for the current agent."""
        self._plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self._state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self._client = n_rpc.get_client(self.target)

        self._consumers.extend([
            [topics.PORT, topics.UPDATE], [topics.NETWORK, topics.DELETE],
            [topics.PORT, topics.DELETE]
        ])

        self.connection = agent_rpc.create_consumers(
            self._endpoints, self._topic, self._consumers,
            start_listening=False
        )
        self._setup_qos_extension()
        self.connection.consume_in_threads()

        report_interval = CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def _process_added_port_event(self, port_name):
        """Callback for added ports."""
        LOG.info("Hyper-V VM vNIC added: %s", port_name)
        self._added_ports.add(port_name)

    def _process_removed_port_event(self, port_name):
        LOG.info("Hyper-V VM vNIC removed: %s", port_name)
        self._removed_ports.add(port_name)

    def _load_physical_network_mappings(self, phys_net_vswitch_mappings):
        """Load all the information regarding the physical network."""
        for mapping in phys_net_vswitch_mappings:
            parts = mapping.split(':')
            if len(parts) != 2:
                LOG.debug('Invalid physical network mapping: %s', mapping)
            else:
                pattern = re.escape(parts[0].strip()).replace('\\*', '.*')
                pattern = pattern + '$'
                vswitch = parts[1].strip()
                self._physical_network_mappings[pattern] = vswitch

    def _get_vswitch_name(self, network_type, physical_network):
        """Get the vswitch name for the received network information."""
        if network_type != constants.TYPE_LOCAL:
            vswitch_name = self._get_vswitch_for_physical_network(
                physical_network)
        else:
            vswitch_name = self._local_network_vswitch
        return vswitch_name

    def _get_vswitch_for_physical_network(self, phys_network_name):
        """Get the vswitch name for the received network name."""
        for pattern in self._physical_network_mappings:
            if phys_network_name is None:
                phys_network_name = ''
            if re.match(pattern, phys_network_name):
                return self._physical_network_mappings[pattern]
        # Not found in the mappings, the vswitch has the same name
        return phys_network_name

    def _get_network_vswitch_map_by_port_id(self, port_id):
        """Get the vswitch name for the received port id."""
        for network_id, vswitch in six.iteritems(self._network_vswitch_map):
            if port_id in vswitch['ports']:
                return (network_id, vswitch)

        # If the port was not found, just return (None, None)
        return (None, None)

    def _update_port_status_cache(self, device, device_bound=True):
        """Update the ports status cache."""
        with self._cache_lock:
            if device_bound:
                self._bound_ports.add(device)
                self._unbound_ports.discard(device)
            else:
                self._bound_ports.discard(device)
                self._unbound_ports.add(device)

    def _create_event_listeners(self):
        """Create and bind the event listeners."""
        LOG.debug("Create the event listeners.")
        for event_type, callback in self._event_callback_pairs:
            LOG.debug("Create listener for %r event", event_type)
            listener = self._utils.get_vnic_event_listener(event_type)
            eventlet.spawn_n(listener, callback)

    def _prologue(self):
        """Executed once before the daemon loop."""
        self._added_ports = self._utils.get_vnic_ids()
        self._create_event_listeners()

    def _reclaim_local_network(self, net_uuid):
        LOG.info("Reclaiming local network %s", net_uuid)
        del self._network_vswitch_map[net_uuid]

    def _port_bound(self, port_id, network_id, network_type, physical_network,
                    segmentation_id):
        """Bind the port to the recived network."""
        LOG.debug("Binding port %s", port_id)

        if network_id not in self._network_vswitch_map:
            self._provision_network(
                port_id, network_id, network_type,
                physical_network, segmentation_id)

        vswitch_map = self._network_vswitch_map[network_id]
        vswitch_map['ports'].append(port_id)

        LOG.debug("Trying to connect the current port to vswitch %r.",
                  vswitch_map['vswitch_name'])
        self._utils.connect_vnic_to_vswitch(
            vswitch_name=vswitch_map['vswitch_name'],
            switch_port_name=port_id,
        )

    def _port_unbound(self, port_id, vnic_deleted=False):
        LOG.debug("Trying to unbind the port %r", port_id)

        vswitch = self._get_network_vswitch_map_by_port_id(port_id)
        net_uuid, vswitch_map = vswitch

        if not net_uuid:
            LOG.debug('Port %s was not found on this agent.', port_id)
            return

        LOG.debug("Unbinding port %s", port_id)
        self._utils.remove_switch_port(port_id, vnic_deleted)
        vswitch_map['ports'].remove(port_id)

        if not vswitch_map['ports']:
            self._reclaim_local_network(net_uuid)

    def _process_added_port(self, device_details):
        self._treat_vif_port(
            port_id=device_details['port_id'],
            network_id=device_details['network_id'],
            network_type=device_details['network_type'],
            physical_network=device_details['physical_network'],
            segmentation_id=device_details['segmentation_id'],
            admin_state_up=device_details['admin_state_up'])

    def process_added_port(self, device_details):
        """Process the new ports.

        Wraps _process_added_port, and treats the sucessful and exception
        cases.
        """
        device = device_details['device']
        port_id = device_details['port_id']
        reprocess = True
        try:
            self._process_added_port(device_details)

            LOG.debug("Updating cached port %s status as UP.", port_id)
            self._update_port_status_cache(device, device_bound=True)
            LOG.info("Port %s processed.", port_id)
        except os_win_exc.HyperVvNicNotFound:
            LOG.debug('vNIC %s not found. This can happen if the VM was '
                      'destroyed.', port_id)
            reprocess = False
        except os_win_exc.HyperVPortNotFoundException:
            LOG.debug('vSwitch port %s not found. This can happen if the VM '
                      'was destroyed.', port_id)
            # NOTE(claudiub): just to be on the safe side, in case Hyper-V said
            # that the port was added, but it hasn't really, we're leaving
            # reprocess = True. If the VM / vNIC was removed, on the next
            # reprocess, a HyperVvNicNotFound will be raised.
        except Exception as ex:
            # NOTE(claudiub): in case of a non-transient error, the port will
            # be processed over and over again, and will not be reported as
            # bound (e.g.: InvalidParameterValue when setting QoS), until the
            # port is deleted. These issues have to be investigated and solved
            LOG.exception("Exception encountered while processing "
                          "port %(port_id)s. Exception: %(ex)s",
                          dict(port_id=port_id, ex=ex))
        else:
            # no exception encountered, no need to reprocess.
            reprocess = False

        if reprocess:
            # Readd the port as "added", so it can be reprocessed.
            self._added_ports.add(device)

            # Force cache refresh.
            self._refresh_cache = True
            return False

        return True

    def _treat_devices_added(self):
        """Process the new devices."""
        try:
            devices_details_list = self._plugin_rpc.get_devices_details_list(
                self._context, self._added_ports, self._agent_id)
        except Exception as exc:
            LOG.debug("Unable to get ports details for "
                      "devices %(devices)s: %(exc)s",
                      {'devices': self._added_ports, 'exc': exc})
            return

        for device_details in devices_details_list:
            device = device_details['device']
            LOG.info("Adding port %s", device)
            if 'port_id' in device_details:
                LOG.info("Port %(device)s updated. "
                         "Details: %(device_details)s",
                         {'device': device, 'device_details': device_details})
                eventlet.spawn_n(self.process_added_port, device_details)
            else:
                LOG.debug("Missing port_id from device details: "
                          "%(device)s. Details: %(device_details)s",
                          {'device': device, 'device_details': device_details})

            LOG.debug("Remove the port from added ports set, so it "
                      "doesn't get reprocessed.")
            self._added_ports.discard(device)

    def _process_removed_port(self, device):
        """Process the removed ports."""
        LOG.debug("Trying to remove the port %r", device)
        self._update_port_status_cache(device, device_bound=False)
        self._port_unbound(device, vnic_deleted=True)

        LOG.debug("The port was successfully removed.")
        self._removed_ports.discard(device)

    def _treat_devices_removed(self):
        """Process the removed devices."""
        for device in self._removed_ports.copy():
            eventlet.spawn_n(self._process_removed_port, device)

    @_synchronized('n-plugin-notifier')
    def _notify_plugin_on_port_updates(self):
        if not (self._bound_ports or self._unbound_ports):
            return

        with self._cache_lock:
            bound_ports = self._bound_ports.copy()
            unbound_ports = self._unbound_ports.copy()

        self._plugin_rpc.update_device_list(
            self._context, list(bound_ports), list(unbound_ports),
            self._agent_id, self._host)

        with self._cache_lock:
            self._bound_ports = self._bound_ports.difference(bound_ports)
            self._unbound_ports = self._unbound_ports.difference(
                unbound_ports)

    def _work(self):
        """Process the information regarding the available ports."""
        if self._refresh_cache:
            # Inconsistent cache might cause exceptions. For example,
            # if a port has been removed, it will be known in the next
            # loop. Using the old switch port can cause exceptions.
            LOG.debug("Refreshing os_win caches...")
            self._utils.update_cache()
            self._refresh_cache = False

        eventlet.spawn_n(self._notify_plugin_on_port_updates)

        # notify plugin about port deltas
        if self._added_ports:
            LOG.debug("Agent loop has new devices!")
            self._treat_devices_added()

        if self._removed_ports:
            LOG.debug("Agent loop has lost devices...")
            self._treat_devices_removed()

    def port_update(self, context, port=None, network_type=None,
                    segmentation_id=None, physical_network=None):
        LOG.debug("port_update received: %s", port['id'])

        if self._utils.vnic_port_exists(port['id']):
            self._treat_vif_port(
                port_id=port['id'],
                network_id=port['network_id'],
                network_type=network_type,
                physical_network=physical_network,
                segmentation_id=segmentation_id,
                admin_state_up=port['admin_state_up'],
            )
        else:
            LOG.debug("No port %s defined on agent.", port['id'])

    def port_delete(self, context, port_id=None):
        """Delete the received port."""
        LOG.debug("port_delete event received for %r", port_id)

    def network_delete(self, context, network_id=None):
        LOG.debug("network_delete received. "
                  "Deleting network %s", network_id)

        # The network may not be defined on this agent
        if network_id in self._network_vswitch_map:
            self._reclaim_local_network(network_id)
        else:
            LOG.debug("Network %s not defined on agent.", network_id)

    @abc.abstractmethod
    def _provision_network(self, port_id, net_uuid, network_type,
                           physical_network, segmentation_id):
        """Provision the network with the received information."""
        pass

    @abc.abstractmethod
    def _treat_vif_port(self, port_id, network_id, network_type,
                        physical_network, segmentation_id,
                        admin_state_up):
        pass
