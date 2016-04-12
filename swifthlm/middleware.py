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

### Authors:
# Slavisa Sarafijanovic (sla@zurich.ibm.com)
# Harald Seipp (seipp@de.ibm.com)


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
