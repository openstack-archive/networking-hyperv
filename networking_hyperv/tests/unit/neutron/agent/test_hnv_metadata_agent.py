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
import sys

import mock
from neutron.agent import rpc as agent_rpc
from neutron.common import topics
from neutron import wsgi
from oslo_config import cfg
import webob

from networking_hyperv.neutron.agent import base as base_agent
from networking_hyperv.neutron.agent import hnv_metadata_agent
from networking_hyperv.tests import base as test_base

CONF = cfg.CONF


class TestMetadataProxyHandler(test_base.BaseTestCase):

    @mock.patch("networking_hyperv.neutron.neutron_client.NeutronAPIClient")
    @mock.patch("neutron_lib.context.get_admin_context_without_session")
    def _get_proxy(self, mock_get_context, mock_neutron_client):
        return hnv_metadata_agent._MetadataProxyHandler()

    def setUp(self):
        super(TestMetadataProxyHandler, self).setUp()
        hnv_metadata_agent.register_config_opts()
        self._proxy = self._get_proxy()
        self._neutron_client = self._proxy._neutron_client

    @mock.patch.object(hnv_metadata_agent._MetadataProxyHandler,
                       "_proxy_request")
    def test_call(self, mock_proxy_request):
        mock_proxy_request.side_effect = [mock.sentinel.response,
                                          ValueError("_proxy_request_error")]

        self.assertEqual(mock.sentinel.response,
                         self._proxy(mock.sentinel.request))
        mock_proxy_request.assert_called_once_with(mock.sentinel.request)

        self.assertIsInstance(self._proxy(mock.sentinel.request),
                              webob.exc.HTTPInternalServerError)

    def test_get_port_profile_id(self):
        url = "http://169.254.169.254/"
        port_profile_id = "9d0bab3e-1abf-11e7-a7ef-5cc5d4a321db"
        request = mock.Mock(path=url + port_profile_id)
        request_invalid = mock.Mock(path=url)

        self.assertEqual(port_profile_id,
                         self._proxy._get_port_profile_id(request))
        self.assertIsNone(self._proxy._get_port_profile_id(request_invalid))

    def test_get_instance_id(self):
        self._neutron_client.get_network_ports.return_value = [
            {},
            {"binding:vif_details": {"port_profile_id": None}},
            {"binding:vif_details": {
                "port_profile_id": mock.sentinel.port_profile_id},
             "tenant_id": mock.sentinel.tenant_id,
             "device_id": mock.sentinel.instance_id},
        ]
        self.assertEqual(
            (mock.sentinel.tenant_id, mock.sentinel.instance_id),
            self._proxy._get_instance_id(mock.sentinel.port_profile_id))

        self._neutron_client.get_network_ports.return_value = []
        self.assertEqual(
            (None, None),
            self._proxy._get_instance_id(mock.sentinel.port_profile_id))

    def test_sign_instance_id(self):
        self.config(metadata_proxy_shared_secret="secret")
        self.assertEqual(
            "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914",
            self._proxy._sign_instance_id("test")
        )

    @mock.patch.object(hnv_metadata_agent._MetadataProxyHandler,
                       "_sign_instance_id")
    @mock.patch.object(hnv_metadata_agent._MetadataProxyHandler,
                       "_get_instance_id")
    def test_get_headers(self, mock_get_instance_id, mock_sign_instance_id):
        mock_get_instance_id.side_effect = [
            (mock.sentinel.tenant_id, mock.sentinel.instance_id),
            (None, None),
        ]
        expected_headers = {
            'X-Instance-ID': mock.sentinel.instance_id,
            'X-Tenant-ID': mock.sentinel.tenant_id,
            'X-Instance-ID-Signature': mock_sign_instance_id.return_value,
        }

        self.assertEqual(
            expected_headers,
            self._proxy._get_headers(mock.sentinel.port))
        mock_get_instance_id.assert_called_once_with(mock.sentinel.port)
        self.assertIsNone(self._proxy._get_headers(mock.sentinel.port))

    @mock.patch("httplib2.Http")
    @mock.patch.object(hnv_metadata_agent._MetadataProxyHandler,
                       "_get_headers")
    def _test_proxy_request(self, mock_get_headers, mock_http,
                            valid_path=True, valid_profile_id=True,
                            response_code=200, method='GET'):
        nova_url = '%s:%s' % (CONF.nova_metadata_ip,
                              CONF.nova_metadata_port)
        path = "/9d0bab3e-1abf-11e7-a7ef-5cc5d4a321db" if valid_path else "/"
        headers = {"X-Not-Empty": True} if valid_profile_id else {}
        mock_get_headers.return_value = headers

        http_response = mock.MagicMock(status=response_code)
        http_response.__getitem__.return_value = "text/plain"
        http_request = mock_http.return_value
        http_request.request.return_value = (http_response,
                                             mock.sentinel.content)

        mock_resonse = mock.Mock(content_type=None, body=None)
        mock_request = mock.Mock(path=path, path_info=path, query_string='',
                                 headers={}, method=method,
                                 body=mock.sentinel.body)
        mock_request.response = mock_resonse

        response = self._proxy._proxy_request(mock_request)

        if not (valid_path and valid_profile_id):
            http_request.add_certificate.assert_not_called()
            http_request.request.assert_not_called()
            return response

        if CONF.nova_client_cert and CONF.nova_client_priv_key:
            http_request.add_certificate.assert_called_once_with(
                key=CONF.nova_client_priv_key,
                cert=CONF.nova_client_cert,
                domain=nova_url)

        http_request.request.assert_called_once_with(
            "http://127.0.0.1:8775/", method=method, headers=headers,
            body=mock.sentinel.body)

        return response

    def test_proxy_request_200(self):
        self.config(nova_client_cert=mock.sentinel.nova_client_cert,
                    nova_client_priv_key=mock.sentinel.priv_key)
        response = self._test_proxy_request()
        self.assertEqual("text/plain", response.content_type)
        self.assertEqual(mock.sentinel.content, response.body)

    def test_proxy_request_400(self):
        self.assertIsInstance(
            self._test_proxy_request(response_code=400),
            webob.exc.HTTPBadRequest)

    def test_proxy_request_403(self):
        self.assertIsInstance(
            self._test_proxy_request(response_code=403),
            webob.exc.HTTPForbidden)

    def test_proxy_request_409(self):
        self.assertIsInstance(
            self._test_proxy_request(response_code=409),
            webob.exc.HTTPConflict)

    def test_proxy_request_404(self):
        self.assertIsInstance(
            self._test_proxy_request(valid_path=False),
            webob.exc.HTTPNotFound)
        self.assertIsInstance(
            self._test_proxy_request(valid_profile_id=False),
            webob.exc.HTTPNotFound)
        self.assertIsInstance(
            self._test_proxy_request(response_code=404),
            webob.exc.HTTPNotFound)

    def test_proxy_request_500(self):
        self.assertIsInstance(
            self._test_proxy_request(response_code=500),
            webob.exc.HTTPInternalServerError)

    def test_proxy_request_other_code(self):
        self.assertIsInstance(
            self._test_proxy_request(response_code=527),
            webob.exc.HTTPInternalServerError)

    def test_proxy_request_post(self):
        response = self._test_proxy_request(method='POST')
        self.assertEqual("text/plain", response.content_type)
        self.assertEqual(mock.sentinel.content, response.body)


class TestMetadataProxy(test_base.HyperVBaseTestCase):

    @mock.patch.object(hnv_metadata_agent.MetadataProxy, "_setup_rpc")
    @mock.patch.object(base_agent.BaseAgent, "_set_agent_state")
    def _get_agent(self, mock_set_agent_state, mock_setup_rpc):
        return hnv_metadata_agent.MetadataProxy()

    def setUp(self):
        super(TestMetadataProxy, self).setUp()
        hnv_metadata_agent.register_config_opts()
        self._agent = self._get_agent()

    @mock.patch('oslo_service.loopingcall.FixedIntervalLoopingCall')
    @mock.patch.object(agent_rpc, 'PluginReportStateAPI')
    def test_setup_rpc(self, mock_plugin_report_state_api,
                       mock_looping_call):
        report_interval = 10
        self.config(report_interval=report_interval, group="AGENT")

        self._agent._setup_rpc()

        mock_plugin_report_state_api.assert_called_once_with(topics.REPORTS)
        mock_looping_call.assert_called_once_with(self._agent._report_state)
        mock_heartbeat = mock_looping_call.return_value
        mock_heartbeat.start.assert_called_once_with(interval=report_interval)

    def test_get_agent_configurations(self):
        fake_ip = '10.10.10.10'
        fake_port = 9999
        self.config(nova_metadata_ip=fake_ip,
                    nova_metadata_port=fake_port)

        configuration = self._agent._get_agent_configurations()

        self.assertEqual(fake_ip, configuration["nova_metadata_ip"])
        self.assertEqual(fake_port, configuration["nova_metadata_port"])
        self.assertEqual(CONF.AGENT.log_agent_heartbeats,
                         configuration["log_agent_heartbeats"])

    @mock.patch.object(hnv_metadata_agent, "_MetadataProxyHandler")
    @mock.patch.object(wsgi, "Server")
    def test_work(self, mock_server, mock_proxy_handler):
        self._agent._work()

        mock_server.assert_called_once_with(
            name=self._agent._AGENT_BINARY,
            num_threads=CONF.AGENT.worker_count)
        server = mock_server.return_value
        server.start.assert_called_once_with(
            application=mock_proxy_handler.return_value,
            port=CONF.bind_port,
            host=CONF.bind_host)
        server.wait.assert_called_once_with()

    @mock.patch.object(hnv_metadata_agent.MetadataProxy, "_work")
    @mock.patch.object(hnv_metadata_agent.MetadataProxy, "_prologue")
    def test_run(self, mock_prologue, mock_work):
        mock_work.side_effect = ValueError
        self._agent.run()

        mock_prologue.assert_called_once_with()
        mock_work.assert_called_once_with()


class TestMain(test_base.BaseTestCase):

    @mock.patch.object(hnv_metadata_agent, 'MetadataProxy')
    @mock.patch.object(hnv_metadata_agent, 'common_config')
    @mock.patch.object(hnv_metadata_agent, 'meta_config')
    @mock.patch.object(hnv_metadata_agent, 'neutron_config')
    def test_main(self, mock_config, mock_meta_config, mock_common_config,
                  mock_proxy):
        hnv_metadata_agent.main()

        mock_config.register_agent_state_opts_helper.assert_called_once_with(
            CONF)
        mock_meta_config.register_meta_conf_opts.assert_called_once_with(
            hnv_metadata_agent.meta_config.METADATA_PROXY_HANDLER_OPTS)
        mock_common_config.init.assert_called_once_with(sys.argv[1:])
        mock_config.setup_logging.assert_called_once_with()
        mock_proxy.assert_called_once_with()
        mock_proxy.return_value.run.assert_called_once_with()
