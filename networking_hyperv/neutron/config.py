# Copyright 2015 Cloudbase Solutions Srl
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

from keystoneauth1 import loading as ks_loading
from oslo_config import cfg

from networking_hyperv.common.i18n import _

CONF = cfg.CONF


HYPERV_AGENT_GROUP_NAME = 'AGENT'

HYPERV_AGENT_GROUP = cfg.OptGroup(
    HYPERV_AGENT_GROUP_NAME,
    title='Hyper-V Neutron Agent Options',
    help=('Configuration options for the neutron-hyperv-agent (L2 agent).')
)

HYPERV_AGENT_OPTS = [
    cfg.ListOpt(
        'physical_network_vswitch_mappings',
        default=[],
        help=_('List of <physical_network>:<vswitch> '
               'where the physical networks can be expressed with '
               'wildcards, e.g.: ."*:external"')),
    cfg.StrOpt(
        'local_network_vswitch',
        default='private',
        help=_('Private vswitch name used for local networks')),
    cfg.IntOpt('polling_interval', default=2, min=1,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.IntOpt('worker_count', default=10, min=1,
               help=_("The number of worker threads allowed to run in "
                      "parallel to process port binding.")),
    cfg.IntOpt('worker_retry', default=3, min=0,
               help=_("The number of times worker process will retry "
                      "port binding.")),
    cfg.BoolOpt('enable_metrics_collection',
                default=False,
                help=_('Enables metrics collections for switch ports by using '
                       'Hyper-V\'s metric APIs. Collected data can by '
                       'retrieved by other apps and services, e.g.: '
                       'Ceilometer. Requires Hyper-V / Windows Server 2012 '
                       'and above')),
    cfg.IntOpt('metrics_max_retries',
               default=100, min=0,
               help=_('Specifies the maximum number of retries to enable '
                      'Hyper-V\'s port metrics collection. The agent will try '
                      'to enable the feature once every polling_interval '
                      'period for at most metrics_max_retries or until it '
                      'succeedes.')),
    cfg.IPOpt('neutron_metadata_address',
              default='169.254.169.254',
              help=_('Specifies the address which will serve the metadata for'
                      ' the instance.')),
    cfg.BoolOpt('enable_qos_extension',
                default=False,
                help=_('Enables the QoS extension.')),
]


NVGRE_GROUP_NAME = 'NVGRE'

NVGRE_GROUP = cfg.OptGroup(
    NVGRE_GROUP_NAME,
    title='Hyper-V NVGRE Options',
    help=('Configuration options for NVGRE.')
)

NVGRE_OPTS = [
    cfg.BoolOpt('enable_support',
                default=False,
                help=_('Enables Hyper-V NVGRE. '
                       'Requires Windows Server 2012 or above.')),
    cfg.IntOpt('provider_vlan_id',
               default=0, min=0, max=4096,
               help=_('Specifies the VLAN ID of the physical network, required'
                      ' for setting the NVGRE Provider Address.')),
    cfg.IPOpt('provider_tunnel_ip',
              default=None,
              help=_('Specifies the tunnel IP which will be used and '
                     'reported by this host for NVGRE networks.')),
]


NEUTRON_GROUP_NAME = 'neutron'

NEUTRON_GROUP = cfg.OptGroup(
    NEUTRON_GROUP_NAME,
    title='Neutron Options',
    help=('Configuration options for neutron (network connectivity as a '
          'service).')
)

NEUTRON_OPTS = [
    cfg.StrOpt('url',
               default='http://127.0.0.1:9696',
               help='URL for connecting to neutron'),
    cfg.IntOpt('url_timeout',
               default=30, min=1,
               help='timeout value for connecting to neutron in seconds'),
    cfg.StrOpt('admin_username',
               help='username for connecting to neutron in admin context'),
    cfg.StrOpt('admin_password',
               help='password for connecting to neutron in admin context',
               secret=True),
    cfg.StrOpt('admin_tenant_name',
               help='tenant name for connecting to neutron in admin context'),
    cfg.StrOpt('admin_auth_url',
               default='http://localhost:5000/v2.0',
               help='auth url for connecting to neutron in admin context'),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               help='auth strategy for connecting to neutron in admin context')
]


HNV_GROUP_NAME = 'HNV'

HNV_GROUP = cfg.OptGroup(
    HNV_GROUP_NAME,
    title='HNV Options',
    help='Configuration options for the Windows Network Controller.'
)

HNV_OPTS = [
    cfg.StrOpt(
        "logical_network", default=None,
        help=("Logical network to use as a medium for tenant network "
              "traffic.")),
]


def register_opts():
    CONF.register_group(HYPERV_AGENT_GROUP)
    CONF.register_opts(HYPERV_AGENT_OPTS, group=HYPERV_AGENT_GROUP_NAME)

    CONF.register_group(NVGRE_GROUP)
    CONF.register_opts(NVGRE_OPTS, group=NVGRE_GROUP_NAME)

    CONF.register_group(NEUTRON_GROUP)
    CONF.register_opts(NEUTRON_OPTS, group=NEUTRON_GROUP_NAME)
    ks_loading.register_session_conf_options(CONF, NEUTRON_GROUP)
    ks_loading.register_auth_conf_options(CONF, NEUTRON_GROUP)

    CONF.register_group(HNV_GROUP)
    CONF.register_opts(HNV_OPTS, group=HNV_GROUP_NAME)


register_opts()
