#!/usr/bin/python

# (C) Copyright 2016 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
SwiftHLM middleware is useful for running OpenStack Swift on top of high
latency media (HLM) storage, such as tape or optical disk archive based
backends, allowing to store cheaply and access efficiently large amounts of
infrequently used object data.

SwiftHLM extends Swift's interface and thus allows to explicitly control and
query the state (on disk or on HLM) of Swift object data, including efficient
prefetch of bulk of objects from HLM to disk when those objects need to be
accessed.

SwiftHLM provides the following basic HLM functions on the external Swift
interface:
- MIGRATE (container or an object from disk to HLM)
- RECALL (i.e. prefetch a container or an object from HLM to disk)
- STATUS (get status for an object or a container).

For each of these functions, SwiftHLM invokes an external backend that is
responsible for managing the HLM resources and moving the data from disk to HLM
and vice versa.

-------
MIGRATE
-------

Trigger a migration from disk to HLM of a single object or all objects within a
container.
Request must be POST with the query parameter ``?MIGRATE``

For example::

    /v1/AUTH_Account/Container/Object?MIGRATE
    /v1/AUTH_Account/Container?MIGRATE

------
RECALL
------

Trigger a recall from HLM to disk for a single object or all objects within a
container.
Request must be POST with the query parameter ``?RECALL``

For example::

    /v1/AUTH_Account/Container/Object?RECALL
    /v1/AUTH_Account/Container?RECALL

------
STATUS
------

Return free-form status (on HLM or on disk) for a given object or all objects
within a container with the response body.
Request must be GET with the query parameter
``?STATUS``

For example::

    /v1/AUTH_Account/Container/Object?STATUS
    /v1/AUTH_Account/Container?STATUS

When ``format=json`` is added to the query parameter, the response body will be
formatted in json format.

For example::

    /v1/AUTH_Account/Container/Object?STATUS&format=json
    /v1/AUTH_Account/Container?STATUS&format=json


Authors:
Slavisa Sarafijanovic (sla@zurich.ibm.com)
Harald Seipp (seipp@de.ibm.com)
"""

import errno
import subprocess
import random
import string
import os
import sys

from swift.common.swob import Request, Response
from swift.common.http import HTTP_OK

# If POST is migration or recall request, or GET is status request, process by this middleware 
class HlmMiddleware(object):

    def __init__(self, app, conf):
        # app is the final application
        self.app = app
        # Read settings from proxy-server.conf
        self.migrate_backend = conf.get('migrate_backend','/opt/ibm/swift-hlm-backend/migrate')
        self.recall_backend = conf.get('recall_backend','/opt/ibm/swift-hlm-backend/recall')
        self.status_backend = conf.get('status_backend','/opt/ibm/swift-hlm-backend/status')

    def __call__(self, env, start_response):
        # Process POST request to migrate/recall object(s)
        if env['REQUEST_METHOD'] == "POST":
            path = env['PATH_INFO']
            query = env.get('QUERY_STRING') or ''
            requestId = ''.join(random.choice(string.digits) for i in range(12))
            if query == 'MIGRATE':
                subprocess.call([self.migrate_backend, path[4:], requestId])
                return Response(status=HTTP_OK, body="Accepted migration request.\n", content_type="text/plain")(env, start_response)

            if query == 'RECALL':
                subprocess.call([self.recall_backend, path[4:], requestId])
                return Response(status=HTTP_OK, body="Accepted recall request.\n", content_type="text/plain")(env, start_response)
        # Process GET request to get object(s) status
        if env['REQUEST_METHOD'] == "GET":
            path = env['PATH_INFO']
            query = env.get('QUERY_STRING') or ''
            requestId = ''.join(random.choice(string.digits) for i in range(12)) # TBD: support requestId as input 
            if query == 'STATUS':
                try:
		    out = subprocess.check_output([self.status_backend, path[4:], requestId]) #py 2.7+
                except subprocess.CalledProcessError, e:
		    out = e.output
                return Response(status=HTTP_OK, body=out, content_type="text/plain")(env, start_response)

        return self.app(env, start_response)
              	
def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def hlm_filter(app):
        return HlmMiddleware(app, conf)
    return hlm_filter
