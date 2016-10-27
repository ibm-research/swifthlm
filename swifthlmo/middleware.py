# Copyright (c) 2010-2012 OpenStack Foundation
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

import os

#from swift.common.swob import Request, Response

#
import subprocess
import random
import string

from swift.common.swob import Request, Response
from swift.common.http import HTTP_OK, HTTP_INTERNAL_SERVER_ERROR, \
    HTTP_ACCEPTED, HTTP_PRECONDITION_FAILED
from swift.common.utils import register_swift_info

#
from swift.common.ring import Ring
from swift.common.utils import json, get_logger, split_path
from swift.common.swob import Request, Response
from swift.common.swob import HTTPBadRequest, HTTPMethodNotAllowed
from swift.common.storage_policy import POLICIES
from swift.proxy.controllers.base import get_container_info
#
import requests
from socket import gethostname, gethostbyname
import ConfigParser
from collections import OrderedDict
from ast import literal_eval
import netifaces

#

class HlmoMiddleware(object):
    """
    Hight latency media middleware on object server.

    TODO: add more description what/how it does 

    """

    def __init__(self, app, conf):
        # App is the final application
        self.app = app
        # This host ip address
        self.ip = gethostbyname(gethostname())

        self.ips = []
        for interface in netifaces.interfaces():
            if_addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in if_addresses:
                for link in if_addresses[netifaces.AF_INET]:
                    self.ips.append(link['addr'])

        # Read settings from proxy-server.conf
        self.migrate_backend = conf.get('migrate_backend',
                                        '/opt/ibm/swift-hlm-backend/migrate')
        self.recall_backend = conf.get('recall_backend',
                                       '/opt/ibm/swift-hlm-backend/recall')
        self.status_backend = conf.get('status_backend',
                                       '/opt/ibm/swift-hlm-backend/status')
        self.swift_dir = conf.get('swift_dir', '/etc/swift')
        # Logging
        self.logger = get_logger(conf, log_route='swifthlm')

    def __call__(self, env, start_response):
        req = Request(env)

        # Split request path to determine version, account, container, object
        try:
            (p1, p2, account, container, obj) = req.split_path(0, 5, True)
        except ValueError:
            return self.app(env, start_response)

        # If request is not HLM request and not object GET, it is not processed
        # by this middleware
        method = req.method
        query = req.query_string or ''
        if not (method == 'POST'
                and ('MIGRATE' in query
                     or 'RECALL' in query)
                or method == 'GET'):
            return self.app(env, start_response)

        # process by this middleware
        requestId = ''.join(random.choice(string.digits)
                    for i in range(12))

        ## process STATUS
        if 'STATUS' in query:
	        try:
	            a_path = '/' + account[5:] + '/' + container + '/' + obj
	            co = obj
	            out = subprocess.check_output([self.status_backend,
	                                           co,
	                                           requestId,
	                                           query])
	        except subprocess.CalledProcessError, e:
	            ip_addr = self.ip
	            out = OrderedDict([('object', a_path),
	                               ('replica_node', ip_addr),
	                               ('status', 'Unknown'),
	                               ('error', e.output)])
	            out = json.dumps(out);
	        return Response(status=HTTP_OK,
	                        body=out,
	                        content_type="text/plain")(env, start_response)
        ## process MIGRATE or RECALL
        elif 'MIGRATE' in query or 'RECALL' in query:
            if 'MIGRATE' in query:
                hlm_req = 'MIGRATE'
                hlm_backend = self.migrate_backend
            elif 'RECALL' in query:
                hlm_req = 'RECALL'
                hlm_backend = self.recall_backend
            self.logger.debug('hlm_req: %s', hlm_req)
            self.logger.debug('hlm_backend: %s', hlm_backend)
            try:
	            a_path = '/' + account[5:] + '/' + container + '/' + obj
	            co = obj
	            out = subprocess.check_output([hlm_backend,
	                                           co,
	                                           requestId])
            except subprocess.CalledProcessError, e:
                ip_addr = self.ip
                out = OrderedDict([('object', a_path),
                                   ('replica_node', ip_addr),
                                   ('request', hlm_req),
                                   ('error', e.output)])
                out = json.dumps(out);
                return Response(status=HTTP_OK,
                            body=out,
                            content_type="text/plain")(env, start_response)
                        
            return Response(status=HTTP_OK,
                            body="Accepted request",
                            content_type="text/plain")(env, start_response)

def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def hlmo_filter(app):
        return HlmoMiddleware(app, conf)
    return hlmo_filter
