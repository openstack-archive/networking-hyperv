# Copyright 2013 Cloudbase Solutions SRL
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

# Topic for tunnel notifications between the plugin and agent
AGENT_TOPIC = 'q-agent-notifier'
AGENT_TYPE_HYPERV = 'HyperV agent'
AGENT_TYPE_HNV = "HNV agent"
VIF_TYPE_HYPERV = 'hyperv'

TUNNEL = 'tunnel'
LOOKUP = 'lookup'

UPDATE = 'update'

# Special vlan_id value in ovs_vlan_allocations table indicating flat network
FLAT_VLAN_ID = -1

TYPE_FLAT = 'flat'
TYPE_LOCAL = 'local'
TYPE_VLAN = 'vlan'
TYPE_NVGRE = 'gre'

IPV4_DEFAULT = '0.0.0.0'

# Windows Server 2016 Network Controller related constants.
# NOTE(claudiub): These constants HAVE to be defined exactly like this,
# otherwise networking using the Windows Server 2016 Network Controller won't
# work.
# https://docs.microsoft.com/en-us/windows-server/networking/sdn/manage/create-a-tenant-vm  # noqa
NET_CFG_INSTANCE_ID = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
CDN_LABEL_STRING = "OpenStackCdn"
CDN_LABEL_ID = 1111
PROFILE_NAME = "OpenStackProfile"
VENDOR_ID = "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"
VENDOR_NAME = "NetworkController"
PROFILE_DATA = 1
