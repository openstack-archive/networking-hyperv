# Copyright (c) 2015 Cloudbase Solutions Srl
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import eventlet

# eventlet monkey patching the os modules causes  subprocess.Popen to fail
# on Windows when using pipes due to missing non-blocking IO support.
#
# bug report on eventlet:
# https://bitbucket.org/eventlet/eventlet/issue/132/
#       eventletmonkey_patch-breaks
eventlet.monkey_patch(os=False)
# Monkey patch the original current_thread to use the up-to-date _active
# global variable. See https://bugs.launchpad.net/bugs/1863021 and
# https://github.com/eventlet/eventlet/issues/592
import __original_module_threading as orig_threading  # noqa
import threading  # noqa
orig_threading.current_thread.__globals__['_active'] = threading._active
