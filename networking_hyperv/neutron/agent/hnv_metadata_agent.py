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

import hashlib
import hmac
import sys

import httplib2
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import topics
from neutron.conf.agent import common as neutron_config
from neutron.conf.agent.metadata import config as meta_config
from neutron import wsgi
from neutron_lib import constants
from neutron_lib import context
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import encodeutils
from oslo_utils import uuidutils
import six
import six.moves.urllib.parse as urlparse
import webob

from networking_hyperv.common.i18n import _, _LW, _LE   # noqa
from networking_hyperv.neutron.agent import base as base_agent
from networking_hyperv.neutron import config
from networking_hyperv.neutron import neutron_client

CONF = config.CONF
LOG = logging.getLogger(__name__)


class _MetadataProxyHandler(object):

    def __init__(self):
        self._context = context.get_admin_context_without_session()
        self._neutron_client = neutron_client.NeutronAPIClient()

    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        try:
            return self._proxy_request(req)
        except Exception:
            LOG.exception("Unexpected error.")
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)

    def _get_port_profile_id(self, request):
        """Get the port profile ID from the request path."""

        # Note(alexcoman): The port profile ID can be found as suffix
        # in request path.
        port_profile_id = request.path.split("/")[-1].strip()
        if uuidutils.is_uuid_like(port_profile_id):
            LOG.debug("The instance id was found in request path.")
            return port_profile_id

        LOG.debug("Failed to get the instance id from the request.")
        return None

    def _get_instance_id(self, port_profile_id):
        tenant_id = None
        instance_id = None
        ports = self._neutron_client.get_network_ports()
        for port in ports:
            vif_details = port.get("binding:vif_details", {})
            profile_id = vif_details.get("port_profile_id")
            if profile_id and profile_id == port_profile_id:
                tenant_id = port["tenant_id"]
                # Note(alexcoman): The port["device_id"] is actually the
                # Nova instance_id.
                instance_id = port["device_id"]
                break
        else:
            LOG.debug("Failed to get the port information.")

        return tenant_id, instance_id

    def _sign_instance_id(self, instance_id):
        secret = CONF.metadata_proxy_shared_secret
        secret = encodeutils.to_utf8(secret)
        instance_id = encodeutils.to_utf8(instance_id)
        return hmac.new(secret, instance_id, hashlib.sha256).hexdigest()

    def _get_headers(self, port_profile_id):
        tenant_id, instance_id = self._get_instance_id(port_profile_id)
        if not (tenant_id and instance_id):
            return None

        headers = {
            'X-Instance-ID': instance_id,
            'X-Tenant-ID': tenant_id,
            'X-Instance-ID-Signature': self._sign_instance_id(instance_id),
        }
        return headers

    def _proxy_request(self, request):
        LOG.debug("Request: %s", request)
        port_profile_id = self._get_port_profile_id(request)
        if not port_profile_id:
            return webob.exc.HTTPNotFound()

        headers = self._get_headers(port_profile_id)
        if not headers:
            return webob.exc.HTTPNotFound()

        LOG.debug("Trying to proxy the request.")
        nova_url = '%s:%s' % (CONF.nova_metadata_host,
                              CONF.nova_metadata_port)
        allow_insecure = CONF.nova_metadata_insecure

        http_request = httplib2.Http(
            ca_certs=CONF.auth_ca_cert,
            disable_ssl_certificate_validation=allow_insecure
        )
        if CONF.nova_client_cert and CONF.nova_client_priv_key:
            http_request.add_certificate(
                key=CONF.nova_client_priv_key,
                cert=CONF.nova_client_cert,
                domain=nova_url)

        url = urlparse.urlunsplit((
            CONF.nova_metadata_protocol, nova_url,
            request.path_info, request.query_string, ''))

        response, content = http_request.request(
            url.replace(port_profile_id, ""),
            method=request.method, headers=headers,
            body=request.body)

        LOG.debug("Response [%s]: %s", response.status, content)
        if response.status == 200:
            request.response.content_type = response['content-type']
            request.response.body = content
            return request.response
        elif response.status == 403:
            LOG.warning('The remote metadata server responded with Forbidden. '
                        'This response usually occurs when shared secrets do '
                        'not match.')
            return webob.exc.HTTPForbidden()
        elif response.status == 400:
            return webob.exc.HTTPBadRequest()
        elif response.status == 404:
            return webob.exc.HTTPNotFound()
        elif response.status == 409:
            return webob.exc.HTTPConflict()
        elif response.status == 500:
            message = _(
                "Remote metadata server experienced an internal server error."
            )
            LOG.warning(message)
            return webob.exc.HTTPInternalServerError(explanation=message)
        else:
            message = _("The HNV Metadata proxy experienced an internal"
                        " server error.")
            LOG.warning('Unexpected response code: %s', response.status)
            return webob.exc.HTTPInternalServerError(explanation=message)


class MetadataProxy(base_agent.BaseAgent):

    _AGENT_BINARY = 'neutron-hnv-metadata-proxy'
    _AGENT_TYPE = constants.AGENT_TYPE_METADATA
    _AGENT_TOPIC = 'N/A'

    def __init__(self):
        super(MetadataProxy, self).__init__()
        self._set_agent_state()
        self._setup_rpc()

    def _setup_rpc(self):
        """Setup the RPC client for the current agent."""
        self._state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        report_interval = CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def _get_agent_configurations(self):
        return {
            'nova_metadata_ip': CONF.nova_metadata_host,
            'nova_metadata_port': CONF.nova_metadata_port,
            'log_agent_heartbeats': CONF.AGENT.log_agent_heartbeats,
        }

    def _work(self):
        """Start the neutron-hnv-metadata-proxy agent."""
        server = wsgi.Server(
            name=self._AGENT_BINARY,
            num_threads=CONF.AGENT.worker_count)
        server.start(
            application=_MetadataProxyHandler(),
            port=CONF.bind_port,
            host=CONF.bind_host)
        server.wait()

    def run(self):
        self._prologue()
        try:
            self._work()
        except Exception:
            LOG.exception("Error in agent.")


def register_config_opts():
    neutron_config.register_agent_state_opts_helper(CONF)
    meta_config.register_meta_conf_opts(
        meta_config.METADATA_PROXY_HANDLER_OPTS)


def main():
    """The entry point for neutron-hnv-metadata-proxy."""
    register_config_opts()
    common_config.init(sys.argv[1:])
    neutron_config.setup_logging()
    proxy = MetadataProxy()
    proxy.run()
