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

"""This module contains the contract class for each agent."""

import abc
import threading
import time

from neutron.common import topics
from neutron_lib import context as neutron_context
from os_win import utilsfactory
from oslo_log import log as logging
import oslo_messaging
import six

from networking_hyperv.common.i18n import _LE    # noqa
from networking_hyperv.neutron import config


LOG = logging.getLogger(__name__)
CONF = config.CONF


@six.add_metaclass(abc.ABCMeta)
class BaseAgent(object):

    """Contact class for all the neutron agents."""

    _AGENT_BINARY = None
    _AGENT_TYPE = None
    _AGENT_TOPIC = None

    target = oslo_messaging.Target(version='1.3')

    def __init__(self):
        """Initializes local configuration of the current agent.

        :param conf: dict or dict-like object containing the configuration
                     details used by this Agent. If None is specified, default
                     values are used instead.
        """
        self._agent_id = None
        self._topic = topics.AGENT
        self._cache_lock = threading.Lock()
        self._refresh_cache = False
        self._host = CONF.get("host")

        self._agent_state = {}
        self._context = neutron_context.get_admin_context_without_session()

        self._utils = utilsfactory.get_networkutils()
        self._utils.init_caches()

        # The following attributes will be initialized by the
        # `_setup_rpc` method.
        self._client = None
        self._connection = None
        self._endpoints = []
        self._plugin_rpc = None
        self._sg_plugin_rpc = None
        self._state_rpc = None

        agent_config = CONF.get("AGENT", {})
        self._polling_interval = agent_config.get('polling_interval', 2)

    @abc.abstractmethod
    def _get_agent_configurations(self):
        """Get configurations for the current agent."""
        pass

    def _set_agent_state(self):
        """Set the state for the agent."""
        self._agent_state = {
            'agent_type': self._AGENT_TYPE,
            'binary': self._AGENT_BINARY,
            'configurations': self._get_agent_configurations(),
            'host': self._host,
            'start_flag': True,
            'topic': self._AGENT_TOPIC,
        }

    @abc.abstractmethod
    def _setup_rpc(self):
        """Setup the RPC client for the current agent."""
        pass

    @abc.abstractmethod
    def _work(self):
        """Override this with your desired procedures."""
        pass

    def _prologue(self):
        """Executed once before the daemon loop."""
        pass

    def daemon_loop(self):
        """Process all the available ports."""
        self._prologue()
        while True:
            start = time.time()
            try:
                self._work()
            except Exception:
                LOG.exception("Error in agent event loop")

            # Sleep until the end of polling interval
            elapsed = (time.time() - start)
            if elapsed < self._polling_interval:
                time.sleep(self._polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval "
                          "(%(polling_interval)s vs. %(elapsed)s)",
                          {'polling_interval': self._polling_interval,
                           'elapsed': elapsed})

    def _report_state(self):
        try:
            self._state_rpc.report_state(self._context,
                                         self._agent_state)
            self._agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception("Failed reporting state!")
