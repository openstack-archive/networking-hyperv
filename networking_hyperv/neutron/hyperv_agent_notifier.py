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

from networking_hyperv.neutron import constants


def get_topic_name(prefix, table, operation):
    """Create a topic name.

    The topic name needs to be synced between the agents.
    The agent will send a fanout message to all of the listening agents
    so that the agents in turn can perform their updates accordingly.

    :param prefix: Common prefix for the agent message queues.
    :param table: The table in question (TUNNEL, LOOKUP).
    :param operation: The operation that invokes notification (UPDATE)
    :returns: The topic name.
    """
    return '%s-%s-%s' % (prefix, table, operation)


class AgentNotifierApi(object):
    """Agent side of the OpenVSwitch rpc API."""

    def __init__(self, topic, client):
        self._client = client
        self.topic_tunnel_update = get_topic_name(topic,
                                                  constants.TUNNEL,
                                                  constants.UPDATE)
        self.topic_lookup_update = get_topic_name(topic,
                                                  constants.LOOKUP,
                                                  constants.UPDATE)

    def _fanout_cast(self, context, topic, method, **info):
        cctxt = self._client.prepare(topic=topic, fanout=True)
        cctxt.cast(context, method, **info)

    def tunnel_update(self, context, tunnel_ip, tunnel_type):
        self._fanout_cast(context,
                          self.topic_tunnel_update,
                          'tunnel_update',
                          tunnel_ip=tunnel_ip,
                          tunnel_type=tunnel_type)

    def lookup_update(self, context, lookup_ip, lookup_details):
        self._fanout_cast(context,
                          self.topic_lookup_update,
                          'lookup_update',
                          lookup_ip=lookup_ip,
                          lookup_details=lookup_details)
