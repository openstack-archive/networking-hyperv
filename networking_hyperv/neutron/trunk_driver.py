# Copyright 2017 Cloudbase Solutions Srl
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

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.handlers import resources_rpc
from neutron.services.trunk import constants as t_const
from neutron.services.trunk.rpc import agent as trunk_rpc
from os_win import constants as os_win_const
from os_win import utilsfactory
from oslo_log import log as logging
import oslo_messaging

from networking_hyperv.common.i18n import _LI, _LE  # noqa

LOG = logging.getLogger(__name__)


class HyperVTrunkDriver(trunk_rpc.TrunkSkeleton):
    """Driver responsible for handling trunk/subport/port events.

    Receives data model events from the neutron server and uses them to setup
    VLAN trunks for Hyper-V vSwitch ports.
    """

    def __init__(self, context):
        super(HyperVTrunkDriver, self).__init__()
        self._context = context
        self._utils = utilsfactory.get_networkutils()
        self._trunk_rpc = trunk_rpc.TrunkStub()

        # Map between trunk.id and trunk.
        self._trunks = {}

    def handle_trunks(self, trunks, event_type):
        """Trunk data model change from the server."""

        LOG.debug("Trunks event received: %(event_type)s. Trunks: %(trunks)s",
                  {'event_type': event_type, 'trunks': trunks})

        if event_type == events.DELETED:
            # The port trunks have been deleted. Remove them from cache.
            for trunk in trunks:
                self._trunks.pop(trunk.id, None)
        else:
            for trunk in trunks:
                self._trunks[trunk.id] = trunk
                self._setup_trunk(trunk)

    def handle_subports(self, subports, event_type):
        """Subport data model change from the server."""

        LOG.debug("Subports event received: %(event_type)s. "
                  "Subports: %(subports)s",
                  {'event_type': event_type, 'subports': subports})

        # update the cache.
        if event_type == events.CREATED:
            for subport in subports:
                trunk = self._trunks.get(subport['trunk_id'])
                if trunk:
                    trunk.sub_ports.append(subport)
        elif event_type == events.DELETED:
            for subport in subports:
                trunk = self._trunks.get(subport['trunk_id'])
                if trunk and subport in trunk.sub_ports:
                    trunk.sub_ports.remove(subport)

        # update the bound trunks.
        affected_trunk_ids = set([s['trunk_id'] for s in subports])
        for trunk_id in affected_trunk_ids:
            trunk = self._trunks.get(trunk_id)
            if trunk:
                self._setup_trunk(trunk)

    def bind_vlan_port(self, port_id, segmentation_id):
        trunk = self._fetch_trunk(port_id)
        if not trunk:
            # No trunk found. No VLAN IDs to set in trunk mode.
            self._set_port_vlan(port_id, segmentation_id)
            return

        self._setup_trunk(trunk, segmentation_id)

    def _fetch_trunk(self, port_id, context=None):
        context = context or self._context
        try:
            trunk = self._trunk_rpc.get_trunk_details(context, port_id)
            LOG.debug("Found trunk for port_id %(port_id)s: %(trunk)s",
                      {'port_id': port_id, 'trunk': trunk})

            # cache it.
            self._trunks[trunk.id] = trunk
            return trunk
        except resources_rpc.ResourceNotFound:
            return None
        except oslo_messaging.RemoteError as ex:
            if 'CallbackNotFound' not in str(ex):
                raise
            LOG.debug("Trunk plugin disabled on server. Assuming port %s is "
                      "not a trunk.", port_id)
            return None

    def _setup_trunk(self, trunk, vlan_id=None):
        """Sets up VLAN trunk and updates the trunk status."""

        LOG.info('Binding trunk port: %s.', trunk)
        try:
            # bind sub_ports to host.
            self._trunk_rpc.update_subport_bindings(self._context,
                                                    trunk.sub_ports)

            vlan_trunk = [s.segmentation_id for s in trunk.sub_ports]
            self._set_port_vlan(trunk.port_id, vlan_id, vlan_trunk)

            self._trunk_rpc.update_trunk_status(self._context, trunk.id,
                                                t_const.ACTIVE_STATUS)
        except Exception:
            # something broke
            LOG.exception("Failure setting up subports for %s", trunk.port_id)
            self._trunk_rpc.update_trunk_status(self._context, trunk.id,
                                                t_const.DEGRADED_STATUS)

    def _set_port_vlan(self, port_id, vlan_id, vlan_trunk=None):
        LOG.info('Binding VLAN ID: %(vlan_id)s, VLAN trunk: '
                 '%(vlan_trunk)s to switch port %(port_id)s',
                 dict(vlan_id=vlan_id, vlan_trunk=vlan_trunk, port_id=port_id))

        op_mode = (os_win_const.VLAN_MODE_TRUNK if vlan_trunk else
                   os_win_const.VLAN_MODE_ACCESS)
        self._utils.set_vswitch_port_vlan_id(
            vlan_id,
            port_id,
            operation_mode=op_mode,
            vlan_trunk=vlan_trunk)
