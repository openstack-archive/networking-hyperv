# Copyright 2014 Cloudbase Solutions SRL
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

import threading

import netaddr
from neutron.agent import firewall
from os_win import exceptions
from os_win.utils.network import networkutils
from os_win import utilsfactory
from oslo_log import log as logging
import six

from networking_hyperv.common.i18n import _LE, _LI  # noqa
from networking_hyperv.neutron import _common_utils as c_utils

LOG = logging.getLogger(__name__)

INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
DIRECTION_IP_PREFIX = {'ingress': 'source_ip_prefix',
                       'egress': 'dest_ip_prefix'}

ACL_PROP_MAP = {
    'direction': {'ingress': networkutils.NetworkUtils._ACL_DIR_IN,
                  'egress': networkutils.NetworkUtils._ACL_DIR_OUT},
    'ethertype': {'IPv4': networkutils.NetworkUtils._ACL_TYPE_IPV4,
                  'IPv6': networkutils.NetworkUtils._ACL_TYPE_IPV6},
    'protocol': {'tcp': networkutils.NetworkUtils._TCP_PROTOCOL,
                 'udp': networkutils.NetworkUtils._UDP_PROTOCOL,
                 'icmp': networkutils.NetworkUtils._ICMP_PROTOCOL,
                 'ipv6-icmp': networkutils.NetworkUtils._ICMPV6_PROTOCOL,
                 'icmpv6': networkutils.NetworkUtils._ICMPV6_PROTOCOL},
    'action': {'allow': networkutils.NetworkUtils._ACL_ACTION_ALLOW,
               'deny': networkutils.NetworkUtils._ACL_ACTION_DENY},
    'default': "ANY",
    'address_default': {'IPv4': '0.0.0.0/0', 'IPv6': '::/0'}
}


_ports_synchronized = c_utils.get_port_synchronized_decorator('n-hv-driver-')


class HyperVSecurityGroupsDriverMixin(object):
    """Security Groups Driver.

    Security Groups implementation for Hyper-V VMs.
    """

    def __init__(self):
        self._utils = utilsfactory.get_networkutils()
        self._sg_gen = SecurityGroupRuleGeneratorR2()
        self._sec_group_rules = {}
        self._security_ports = {}
        self._sg_members = {}
        self._sg_rule_templates = {}
        self.cache_lock = threading.Lock()

        # TODO(claudiub): remove this on the next os-win release.
        clear_cache = lambda port_id: self._utils._sg_acl_sds.pop(port_id,
                                                                  None)
        self._utils.clear_port_sg_acls_cache = clear_cache

    def _select_sg_rules_for_port(self, port, direction):
        sg_ids = port.get('security_groups', [])
        port_rules = []
        fixed_ips = port.get('fixed_ips', [])
        for sg_id in sg_ids:
            for rule in self._sg_rule_templates.get(sg_id, []):
                if rule['direction'] != direction:
                    continue
                remote_group_id = rule.get('remote_group_id')
                if not remote_group_id:
                    grp_rule = rule.copy()
                    grp_rule.pop('security_group_id', None)
                    port_rules.append(grp_rule)
                    continue
                ethertype = rule['ethertype']
                for ip in self._sg_members[remote_group_id][ethertype]:
                    if ip in fixed_ips:
                        continue
                    ip_rule = rule.copy()
                    direction_ip_prefix = DIRECTION_IP_PREFIX[direction]
                    ip_rule[direction_ip_prefix] = str(
                        netaddr.IPNetwork(ip).cidr)
                    # NOTE(claudiub): avoid returning fields that are not
                    # directly used in setting the security group rules
                    # properly (remote_group_id, security_group_id), as they
                    # only make testing for rule's identity harder.
                    ip_rule.pop('security_group_id', None)
                    ip_rule.pop('remote_group_id', None)
                    port_rules.append(ip_rule)
        return port_rules

    def filter_defer_apply_on(self):
        """Defer application of filtering rule."""
        pass

    def filter_defer_apply_off(self):
        """Turn off deferral of rules and apply the rules now."""
        pass

    def update_security_group_rules(self, sg_id, sg_rules):
        LOG.debug("Update rules of security group (%s)", sg_id)
        with self.cache_lock:
            self._sg_rule_templates[sg_id] = sg_rules

    def update_security_group_members(self, sg_id, sg_members):
        LOG.debug("Update members of security group (%s)", sg_id)
        with self.cache_lock:
            self._sg_members[sg_id] = sg_members

    def _generate_rules(self, ports):
        newports = {}
        for port in ports:
            _rules = []
            _rules.extend(self._select_sg_rules_for_port(port,
                                                         INGRESS_DIRECTION))
            _rules.extend(self._select_sg_rules_for_port(port,
                                                         EGRESS_DIRECTION))
            newports[port['id']] = _rules
        return newports

    def prepare_port_filter(self, port):
        if not port.get('port_security_enabled'):
            LOG.info('Port %s does not have security enabled. '
                     'Skipping rules creation.', port['id'])
            return
        LOG.debug('Creating port %s rules', len(port['security_group_rules']))

        # newly created port, add default rules.
        if port['device'] not in self._security_ports:
            LOG.debug('Creating default reject rules.')
            self._sec_group_rules[port['id']] = []

            def_sg_rules = self._sg_gen.create_default_sg_rules()
            self._add_sg_port_rules(port, def_sg_rules)
            # Add provider rules
            provider_rules = port['security_group_rules']
            self._create_port_rules(port, provider_rules)

        newrules = self._generate_rules([port])
        self._create_port_rules(port, newrules[port['id']])

        self._security_ports[port['device']] = port
        self._sec_group_rules[port['id']] = newrules[port['id']]

    @_ports_synchronized
    def _create_port_rules(self, port, rules):
        sg_rules = self._sg_gen.create_security_group_rules(rules)
        old_sg_rules = self._sec_group_rules[port['id']]
        add, rm = self._sg_gen.compute_new_rules_add(old_sg_rules, sg_rules)

        self._add_sg_port_rules(port, list(set(add)))
        self._remove_sg_port_rules(port, list(set(rm)))

    @_ports_synchronized
    def _remove_port_rules(self, port, rules):
        sg_rules = self._sg_gen.create_security_group_rules(rules)
        self._remove_sg_port_rules(port, list(set(sg_rules)))

    def _add_sg_port_rules(self, port, sg_rules):
        if not sg_rules:
            return
        old_sg_rules = self._sec_group_rules[port['id']]
        try:
            self._utils.create_security_rules(port['id'], sg_rules)
            old_sg_rules.extend(sg_rules)
        except exceptions.NotFound:
            # port no longer exists.
            # NOTE(claudiub): In the case of a rebuild / shelve, the
            # neutron port is not deleted, and it can still be in the cache.
            # We need to make sure the port's caches are cleared since it is
            # not valid anymore. The port will be reprocessed in the next
            # loop iteration.
            self._sec_group_rules.pop(port['id'], None)
            self._security_ports.pop(port.get('device'), None)
            raise
        except Exception:
            LOG.exception('Exception encountered while adding rules for '
                          'port: %s', port['id'])
            raise

    def _remove_sg_port_rules(self, port, sg_rules):
        if not sg_rules:
            return
        old_sg_rules = self._sec_group_rules[port['id']]
        try:
            self._utils.remove_security_rules(port['id'], sg_rules)
            for rule in sg_rules:
                if rule in old_sg_rules:
                    old_sg_rules.remove(rule)
        except exceptions.NotFound:
            # port no longer exists.
            self._sec_group_rules.pop(port['id'], None)
            self._security_ports.pop(port.get('device'), None)
            raise
        except Exception:
            LOG.exception('Exception encountered while removing rules for '
                          'port: %s', port['id'])
            raise

    def apply_port_filter(self, port):
        LOG.info('Applying port filter.')

    def update_port_filter(self, port):
        if not port.get('port_security_enabled'):
            LOG.info('Port %s does not have security enabled. '
                     'Removing existing rules if any.', port['id'])
            self._security_ports.pop(port.get('device'), None)
            existing_rules = self._sec_group_rules.pop(port['id'], None)
            if existing_rules:
                self._utils.remove_all_security_rules(port['id'])
            return
        LOG.info('Updating port rules.')

        if port['device'] not in self._security_ports:
            LOG.info("Device %(port)s not yet added. Adding.",
                     {'port': port['id']})
            self.prepare_port_filter(port)
            return

        old_port = self._security_ports[port['device']]
        old_provider_rules = old_port['security_group_rules']
        added_provider_rules = port['security_group_rules']
        # Generate the rules
        added_rules = self._generate_rules([port])
        # Expand wildcard rules
        expanded_rules = self._sg_gen.expand_wildcard_rules(
            added_rules[port['id']])
        # Consider added provider rules (if any)
        new_rules = [r for r in added_provider_rules
                     if r not in old_provider_rules]
        # Build new rules to add
        new_rules.extend([r for r in added_rules[port['id']]
                          if r not in self._sec_group_rules[port['id']]])
        # Remove non provider rules
        remove_rules = [r for r in self._sec_group_rules[port['id']]
                        if r not in added_rules[port['id']]]
        # Remove for non provider rules
        remove_rules.extend([r for r in old_provider_rules
                             if r not in added_provider_rules])
        # Avoid removing or adding rules which are contained in wildcard rules
        new_rules = [r for r in new_rules if r not in expanded_rules]
        remove_rules = [r for r in remove_rules if r not in expanded_rules]

        LOG.info("Creating %(new)s new rules, removing %(old)s old rules.",
                 {'new': len(new_rules),
                  'old': len(remove_rules)})

        self._create_port_rules(port, new_rules)
        self._remove_port_rules(old_port, remove_rules)

        self._security_ports[port['device']] = port
        self._sec_group_rules[port['id']] = added_rules[port['id']]

    def remove_port_filter(self, port):
        LOG.info('Removing port filter')
        self._security_ports.pop(port['device'], None)
        self._sec_group_rules.pop(port['id'], None)
        self._utils.clear_port_sg_acls_cache(port['id'])

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        pass

    @property
    def ports(self):
        return self._security_ports


class SecurityGroupRuleGenerator(object):

    def create_security_group_rules(self, rules):
        security_group_rules = []
        for rule in rules:
            security_group_rules.extend(self.create_security_group_rule(rule))
        return security_group_rules

    def create_security_group_rule(self, rule):
        # TODO(claudiub): implement
        pass

    def _get_rule_remote_address(self, rule):
        if rule['direction'] == 'ingress':
            ip_prefix = 'source_ip_prefix'
        else:
            ip_prefix = 'dest_ip_prefix'

        if ip_prefix in rule:
            return rule[ip_prefix]
        return ACL_PROP_MAP['address_default'][rule['ethertype']]


class SecurityGroupRuleGeneratorR2(SecurityGroupRuleGenerator):

    def create_security_group_rule(self, rule):
        local_port = self._get_rule_port_range(rule)
        direction = ACL_PROP_MAP['direction'][rule['direction']]
        remote_address = self._get_rule_remote_address(rule)
        remote_address = remote_address.split('/128', 1)[0]
        protocol = self._get_rule_protocol(rule)
        if protocol == ACL_PROP_MAP['default']:
            # ANY protocols must be split up, to make stateful rules.
            protocols = list(set(ACL_PROP_MAP['protocol'].values()))
        else:
            protocols = [protocol]

        sg_rules = [SecurityGroupRuleR2(direction=direction,
                                        local_port=local_port,
                                        protocol=proto,
                                        remote_addr=remote_address)
                    for proto in protocols]

        return sg_rules

    def create_default_sg_rules(self):
        ip_type_pairs = [(ACL_PROP_MAP['ethertype'][ip],
                          ACL_PROP_MAP['address_default'][ip])
                         for ip in six.iterkeys(ACL_PROP_MAP['ethertype'])]

        action = ACL_PROP_MAP['action']['deny']
        port = ACL_PROP_MAP['default']
        sg_rules = []
        for direction in ACL_PROP_MAP['direction'].values():
            for protocol in set(ACL_PROP_MAP['protocol'].values()):
                for acl_type, address in ip_type_pairs:
                    sg_rules.append(SecurityGroupRuleR2(direction=direction,
                                                        local_port=port,
                                                        protocol=protocol,
                                                        remote_addr=address,
                                                        action=action))
        return sg_rules

    def compute_new_rules_add(self, old_rules, new_rules):
        add_rules = [r for r in new_rules if r not in old_rules]
        return add_rules, []

    def expand_wildcard_rules(self, rules):
        wildcard_rules = [
            r for r in rules
            if self._get_rule_protocol(r) == ACL_PROP_MAP['default']]
        rules = []
        for r in wildcard_rules:
            rule_copy = r.copy()
            if rule_copy['direction'] == 'ingress':
                ip_prefix = 'source_ip_prefix'
            else:
                ip_prefix = 'dest_ip_prefix'
            if ip_prefix not in rule_copy:
                rule_copy[ip_prefix] = (
                    ACL_PROP_MAP['address_default'][rule_copy['ethertype']])
            for proto in list(set(ACL_PROP_MAP['protocol'].keys())):
                rule_to_add = rule_copy.copy()
                rule_to_add['protocol'] = proto
                rules.extend([rule_to_add])
        return rules

    def _get_rule_port_range(self, rule):
        if 'port_range_min' in rule and 'port_range_max' in rule:
            return '%s-%s' % (rule['port_range_min'],
                              rule['port_range_max'])
        return ACL_PROP_MAP['default']

    def _get_rule_protocol(self, rule):
        protocol = self._get_rule_prop_or_default(rule, 'protocol')
        if protocol == 'icmp' and rule.get('ethertype') == 'IPv6':
            # If protocol is ICMP and ethertype is IPv6 the protocol has
            # to be ICMPv6.
            return ACL_PROP_MAP['protocol']['ipv6-icmp']
        if protocol in six.iterkeys(ACL_PROP_MAP['protocol']):
            return ACL_PROP_MAP['protocol'][protocol]

        return protocol

    def _get_rule_prop_or_default(self, rule, prop):
        if prop in rule:
            return rule[prop]
        return ACL_PROP_MAP['default']


class SecurityGroupRuleBase(object):

    _FIELDS = []

    def __eq__(self, obj):
        for f in self._FIELDS:
            if not hasattr(obj, f) or getattr(obj, f) != getattr(self, f):
                return False
        return True

    def __str__(self):
        return str(self.to_dict())

    def __repr__(self):
        return str(self)

    def to_dict(self):
        return dict((field, getattr(self, field)) for field in self._FIELDS)


class SecurityGroupRuleR2(SecurityGroupRuleBase):

    _FIELDS = ["Direction", "Action", "LocalPort", "Protocol",
               "RemoteIPAddress", "Stateful", "IdleSessionTimeout"]

    IdleSessionTimeout = 0
    Weight = 65500

    def __init__(self, direction, local_port, protocol, remote_addr,
                 action=ACL_PROP_MAP['action']['allow']):
        is_not_icmp = protocol not in [ACL_PROP_MAP['protocol']['icmp'],
                                       ACL_PROP_MAP['protocol']['ipv6-icmp']]

        self.Direction = direction
        self.Action = action
        self.LocalPort = str(local_port) if is_not_icmp else ''
        self.Protocol = protocol
        self.RemoteIPAddress = remote_addr
        self.Stateful = (is_not_icmp and
                         action is not ACL_PROP_MAP['action']['deny'])

        self._cached_hash = hash((direction, action, self.LocalPort,
                                  protocol, remote_addr))

    def __lt__(self, obj):
        return self.Protocol > obj.Protocol

    def __hash__(self):
        return self._cached_hash


class HyperVSecurityGroupsDriver(HyperVSecurityGroupsDriverMixin,
                                 firewall.FirewallDriver):
    pass
