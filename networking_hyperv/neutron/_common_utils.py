# Copyright 2013 Cloudbase Solutions SRL
# Copyright 2013 Pedro Navarro Perez
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

import inspect
from os_win import exceptions as os_win_exc
from oslo_concurrency import lockutils
from oslo_log import log as logging
from oslo_utils import reflection

LOG = logging.getLogger(__name__)


def get_port_synchronized_decorator(lock_prefix):
    synchronized = lockutils.synchronized_with_prefix(lock_prefix)

    def _port_synchronized(f):
        # This decorator synchronizes operations targeting the same port.
        # The decorated method is expected to accept the port_id argument.
        def wrapper(*args, **kwargs):
            call_args = inspect.getcallargs(f, *args, **kwargs)
            port_id = (call_args.get('port_id') or
                       call_args.get('port', {}).get('id'))
            lock_name = lock_prefix + ('port-lock-%s' % port_id)

            @synchronized(lock_name)
            def inner():
                return f(*args, **kwargs)
            return inner()
        return wrapper
    return _port_synchronized


def ignore_missing_ports(f):
    def wrapper(*args, **kwargs):
        # The decorated method is expected to accept a port as argument.
        call_args = inspect.getcallargs(f, *args, **kwargs)
        port_id = (call_args.get('port_id') or
                   call_args.get('port', {}).get('id'))

        try:
            return f(*args, **kwargs)
        except os_win_exc.NotFound:
            func_name = reflection.get_callable_name(f)
            LOG.warning("Could not find port '%(port_id)s' while executing "
                        "'%(func_name)s'. It may have been removed.",
                        dict(port_id=port_id,
                             func_name=func_name))
    return wrapper
