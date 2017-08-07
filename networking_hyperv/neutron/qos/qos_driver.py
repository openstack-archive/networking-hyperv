# Copyright 2017 Cloudbase Solutions Srl
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

from neutron.agent.l2.extensions import qos
from neutron.services.qos import qos_consts
from os_win.utils.network import networkutils
from oslo_log import log as logging

from networking_hyperv.common.i18n import _LI, _LW  # noqa

LOG = logging.getLogger(__name__)


class QosHyperVAgentDriver(qos.QosAgentDriver):

    _SUPPORTED_QOS_RULES = [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                            qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH]

    def initialize(self):
        self._utils = networkutils.NetworkUtils()

    def create(self, port, qos_policy):
        """Apply QoS rules on port for the first time.

        :param port: port object.
        :param qos_policy: the QoS policy to be applied on port.
        """
        LOG.info("Setting QoS policy %(qos_policy)s on port %(port)s",
                 dict(qos_policy=qos_policy, port=port))

        policy_data = self._get_policy_values(qos_policy)
        self._utils.set_port_qos_rule(port["port_id"], policy_data)

    def update(self, port, qos_policy):
        """Apply QoS rules on port.

        :param port: port object.
        :param qos_policy: the QoS policy to be applied on port.
        """
        LOG.info("Updating QoS policy %(qos_policy)s on port %(port)s",
                 dict(qos_policy=qos_policy, port=port))

        policy_data = self._get_policy_values(qos_policy)
        self._utils.set_port_qos_rule(port["port_id"], policy_data)

    def delete(self, port, qos_policy=None):
        """Remove QoS rules from port.

        :param port: port object.
        :param qos_policy: the QoS policy to be removed from port.
        """
        LOG.info("Deleting QoS policy %(qos_policy)s on port %(port)s",
                 dict(qos_policy=qos_policy, port=port))

        self._utils.remove_port_qos_rule(port["port_id"])

    def _get_policy_values(self, qos_policy):
        result = {}
        for qos_rule in qos_policy.rules:
            if qos_rule.rule_type not in self._SUPPORTED_QOS_RULES:
                LOG.warning("Unsupported QoS rule: %(qos_rule)s",
                            dict(qos_rule=qos_rule))
                continue
            result['min_kbps'] = getattr(qos_rule, 'min_kbps',
                                         result.get('min_kbps'))
            result['max_kbps'] = getattr(qos_rule, 'max_kbps',
                                         result.get('max_kbps'))
            result['max_burst_kbps'] = getattr(qos_rule, 'max_burst_kbps',
                                               result.get('max_burst_kbps'))

        return result
