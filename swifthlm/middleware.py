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

# MIGRATION/RECALL return codes
SUBMITTED_FORWARDED_REQUEST = 0
FAILED_SUBMITTING_REQUEST = 1
SUBMITTED_REQUESTS = 2
# STATUS return codes
REMOTE_STATUS = 0
STATUS = 1


class HlmMiddleware(object):

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

    # Get ring info needed for determining storage nodes
    def get_object_ring(self, storage_policy_index):
        return POLICIES.get_object_ring(storage_policy_index, self.swift_dir)

    def get_obj_storage_nodes(self, account, container, obj):
        container_info = get_container_info(
            {'PATH_INFO': '/v1/%s/%s' % (account, container)},
            self.app, swift_source='LE')
        storage_policy_index = container_info['storage_policy']
        obj_ring = self.get_object_ring(storage_policy_index)
        partition, nodes = obj_ring.get_nodes(account, container, obj)
        self.logger.debug('Storage nodes: %s' % str(nodes))
        ips = []
        for node in nodes:
            ips.append(node['ip'])
        return ips

    def get_authentication_token(self, req, ip_addr):
        # If Keystone authentication (need test)
        cur_token = req.headers['X-Storage-Token']
        if cur_token[0:3] == 'KEY' or cur_token[-2:] == '==':
            return cur_token
        # Tempauth
        remote_user = req.remote_user
        account_user_aux = remote_user.split(',')[1]
        account_user = account_user_aux.replace(':', '_')
        cfg = ConfigParser.RawConfigParser()
        configFile = r'/etc/swift/proxy-server.conf'
        cfg.read(configFile)
        remote_key = cfg.get('filter:tempauth', 'user_'
                             + account_user).split(' ')[0]
        # TODO: consider pros/cons of using admin account
        #account_user_aux = 'admin:admin'
        #remote_key = cfg.get('filter:tempauth',
        #                     'user_admin_admin').split(' ')[0]
        auth_url = 'http://%(ip)s:8080/auth/v1.0/'
        auth_req = auth_url % {'ip': ip_addr,
                               'url': req.path}
        headers = {'X-Auth-User': account_user_aux,
                   'X-Auth-Key': remote_key}
        response = requests.get(auth_req, headers=headers)
        token = response.headers.get('x-storage-token')
        return token

    def submit_object_replicas_migration_recall(self, req, account, container,
                                                obj, hlm_req, hlm_backend):
        self.logger.debug('HLM %s request\n', hlm_req)
        query = req.query_string
        ips = self.get_obj_storage_nodes(account, container, obj)
        for ip_addr in ips:
            if ip_addr in self.ips:
                # Replica on this node, pass hlm request to backend
                self.logger.debug('ip_addr = %s = self.ip', ip_addr)
                requestId = ''.join(random.choice(string.digits)
                                    for i in range(12))
                try:
                    subprocess.check_call([hlm_backend,
                                           req.path_info[4:],
                                           requestId])
                except subprocess.CalledProcessError, e:
                    status = FAILED_SUBMITTING_REQUEST
                    out = e.output
                    return status, out
                if 'FORWARDED' in query:
                    self.logger.debug('ip_addr = %s = self.ip (FWD)',
                                      ip_addr)
                    # Submitted forwarded request, return success
                    status = SUBMITTED_FORWARDED_REQUEST
                    out = ''
                    return status, out
            elif 'FORWARDED' not in query:
                # Replica on another node and hlm request not already
                # forwarded, forward hlm request
                self.logger.debug('ip_addr = %s != self.ip (NFWD)',
                                  ip_addr)
                # Get auth token
                token = self.get_authentication_token(req, ip_addr)
                # Forward hlm request
                hlm_url = 'http://%(ip)s:8080%(url)s?&FORWARDED&'\
                          + query
                hlm_fwd_req = hlm_url % {'ip': ip_addr,
                                         'url': req.path}
                headers = {'X-Storage-Token': token}
                response = requests.post(hlm_fwd_req, headers=headers)
                if response.status_code not in [HTTP_OK, HTTP_ACCEPTED]:
                    status = FAILED_SUBMITTING_REQUEST
                    out = response.content
                    return status, out
        status = SUBMITTED_REQUESTS
        out = ''
        return status, out

    def get_object_replicas_status(self, req, account, container, obj):
        query = req.query_string or 'STATUS'
        ips = self.get_obj_storage_nodes(account, container, obj)
        replicas_status = []
        for ip_addr in ips:
            if ip_addr in self.ips:
                # Replica on this node, pass hlm request to backend
                # TBD: support requestId as input
                requestId = ''.join(random.choice(string.digits)
                            for i in range(12))
                try:
                    out = subprocess.check_output([self.status_backend,
                                                   req.path_info[4:],
                                                   requestId,
                                                   query])
                except subprocess.CalledProcessError, e:
                    out = OrderedDict([('object', req.path),
                                       ('replica_node', ip_addr),
                                       ('status', 'Unknown'),
                                       ('error', e.output)])
                self.logger.debug('Subprocess return: %s', str(out))
                if 'FORWARDED' in query:
                    # Request was forwarded, return success response
                    rc = REMOTE_STATUS
                    return rc, out, replicas_status
                else:
                    replicas_status.append(out)
            elif 'FORWARDED' not in query:
            # Replica on another node, request status remotely
                # Get auth token
                token = self.get_authentication_token(req, ip_addr)
                # Forward hlm request
                hlm_url = 'http://%(ip)s:8080%(url)s?FORWARDED&'\
                          + query
                hlm_fwd_req = hlm_url % {'ip': ip_addr,
                                         'url': req.path}
                headers = {'X-Storage-Token': token}
                response = requests.get(hlm_fwd_req, headers=headers)
                if response.status_code not in [HTTP_OK, HTTP_ACCEPTED]:
                    out = OrderedDict([('object', req.path),
                                       ('status', 'Unknown')])
                    replicas_status.append(out)
                else:
                    replicas_status.append(response.content)
        rc = STATUS
        out = ''
        return rc, out, replicas_status

    # Prepare/format object status info for reporting (json is default format)
    def format_object_status_info_for_reporting(self, req, replicas_status):
        query = req.query_string
        out = ''
        # Custom formats are not summarized and are reported one line per
        # replica. Custom headers line is reported only once if provided by
        # backend
        if ('format=' in query and 'format=json' not in query):
            # get per replica status info
            for replica_status in replicas_status:
                #remove duplicate custom backend header
                if 'format=' in query and 'format=json' not in query:
                    header = replica_status.split('\n')[0]
                    if header in out:
                        replica_status = replica_status[len(header)+1:]
                # add replica info
                out += replica_status
        else:  # Default format
            # * By default, status is reported in JSON format, one line per
            # object. Status info reported by default: object url, status of
            # each replica.
            # * Query option '&summarized': one value is reported as
            # the object status; if not all replicas have the same
            # status value then 'undefined' status value is reported.
            # * Query option '&nodes': storage node is reported for
            # each replica; if '&summarized' option is not used nodes
            # are listed in same order as status of corresponding
            # replica
            # * Query option '&hlm': report hight latency media storage
            # information for migrated replicas (e.g. tape and/or tape
            # pool name); reported for each replica in the same order as
            # replica status
            # * Query option '&file': report replica file name as
            # stored by Swift; reported for each replica in the same
            # order as replica status
            # * Query option '&all': report all optional info
            # * Optional info, when queried, is reported in the
            # following order: nodes, hlm, file
            out = ''
            status = ''
            summarized_status = ''
            nodes = ''
            hlm_info = ''
            files = ''
            # Prepare status info
            for replica_status in replicas_status:
                if status != '':
                    status += '|'
                try:
                    status += literal_eval(replica_status)['status']
                    if summarized_status == '':
                        summarized_status = literal_eval(replica_status)['status']
                    elif literal_eval(replica_status)['status'] != status:
                        summarized_status = 'undefined'
                except ValueError:
                    summarized_status = 'undefined'
            if 'summarized' in query:
                out_dict = OrderedDict([('object', req.path),
                                        ('status', summarized_status)])
            else:
                out_dict = OrderedDict([('object', req.path),
                                        ('status', status)])
            # Append optional info
            if 'nodes' in query or 'all' in query:
                for replica_status in replicas_status:
                    if nodes != '':
                        nodes += '|'
                    nodes += literal_eval(replica_status)['node']
                out_dict.update({'nodes': nodes})
            if 'hlm' in query or 'all' in query:
                for replica_status in replicas_status:
                    if hlm_info != '':
                        hlm_info += '|'
                    hlm_info += literal_eval(replica_status)['hlm']
                out_dict.update({'hlm': hlm_info})
            if 'file' in query or 'all' in query:
                for replica_status in replicas_status:
                    if files != '':
                        files += '|'
                    files += literal_eval(replica_status)['file']
                out_dict.update({'file': files})

            # Prepare as a line string
            out = json.dumps(out_dict) + '\n'
        return out

    def __call__(self, env, start_response):
        req = Request(env)

        # Split request path to determine version, account, container, object
        try:
            (version, account, container, obj) = req.split_path(2, 4, True)
        except ValueError:
            self.logger.debug('split_path exception')
            return self.app(env, start_response)
        self.logger.debug(':%s:%s:%s:%s:', version, account, container, obj)

        # If request is not HLM request and not object GET, it is not processed
        # by this middleware
        method = req.method
        query = req.query_string or ''
        if not (method == 'POST'
                and ('MIGRATE' in query
                     or 'RECALL' in query)
                or method == 'GET'):
            return self.app(env, start_response)

        # Process GET object data request, if object is migrated return error
        # code 412 'Precondition Failed' (consider using 455 'Method Not Valid
        # in This State') - the error code is returned if any object replica is
        # migrated.
        # TODO: provide option to return error code only if all replicas are
        # migrated, and redirect get request to one of non-migrated replicas
        if req.method == "GET" and obj and 'STATUS' not in query:
            # check status and either let GET proceed or return error code
            rc, out, replicas_status = self.get_object_replicas_status(
                req, account, container, obj)
            if rc == REMOTE_STATUS:
                #send the replica status to requester node
                return Response(status=HTTP_OK,
                                body=out,
                                content_type="text/plain")(env,
                                                           start_response)
            self.logger.debug('replicas_status %s', str(replicas_status))
            ret_error = False
            for replica_status in replicas_status:
                status = literal_eval(replica_status)['status']
                if status not in ['resident', 'premigrated']:
                    ret_error = True
            if ret_error:
                return Response(status=HTTP_PRECONDITION_FAILED,
                                body="Object %s needs to be RECALL-ed before "
                                "it can be accessed.\n" %
                                literal_eval(replicas_status[0])['object'],
                                content_type="text/plain")(env, start_response)

            return self.app(env, start_response)

        # Process POST request to migrate/recall object
        elif method == 'POST' and obj:
            if 'MIGRATE' in query or 'RECALL' in query:
                if 'MIGRATE' in query:
                    hlm_req = 'MIGRATE'
                    hlm_backend = self.migrate_backend
                elif 'RECALL' in query:
                    hlm_req = 'RECALL'
                    hlm_backend = self.recall_backend
                # submit hlm request for object replicas
                status, out = self.submit_object_replicas_migration_recall(
                    req, account, container, obj, hlm_req, hlm_backend)
                self.logger.debug('submit_object_replicas_migration_recall()')
                if status == SUBMITTED_FORWARDED_REQUEST:
                    self.logger.debug('SUBMITTED_FORWARDED_REQUEST')
                    return Response(status=HTTP_OK,
                                    body='Accepted remote replica HLM request',
                                    content_type="text/plain")(env,
                                                               start_response)
                elif status == FAILED_SUBMITTING_REQUEST:
                    self.logger.debug('FAILED_SUBMITTING_REQUEST')
                    return Response(status=HTTP_INTERNAL_SERVER_ERROR,
                                    body=out,
                                    content_type="text/plain")(env,
                                                               start_response)
                elif status == SUBMITTED_REQUESTS:
                    self.logger.debug('SUBMITTED_REQUESTS')
                    return Response(status=HTTP_OK,
                                    body='Accepted %s request.\n' % hlm_req,
                                    content_type="text/plain")(env,
                                                               start_response)
                else:  # invalid case
                    self.logger.debug('INVALID_CASE')
                    return Response(status=HTTP_INTERNAL_SERVER_ERROR,
                                    body=out,
                                    content_type="text/plain")(env,
                                                               start_response)

        # Process GET object status request
        elif req.method == "GET" and obj:
            if 'STATUS' in query:
                # Get status of each replica
                rc, out, replicas_status = self.get_object_replicas_status(
                    req, account, container, obj)
                if rc == REMOTE_STATUS:
                    # send the replica status to requester node
                    return Response(status=HTTP_OK,
                                    body=out,
                                    content_type="text/plain")(env,
                                                               start_response)
                # Prepare/format object status info to report
                # (json is default format)
                out = self.format_object_status_info_for_reporting(
                    req, replicas_status)
                # Report object status
                return Response(status=HTTP_OK,
                                body=out,
                                content_type="text/plain")(env, start_response)

        # Process container request
        if (container and not obj and
           ((method == 'POST' and ('MIGRATE' in query or 'RECALL' in query))
                or method == 'GET' and 'STATUS' in query)):
            self.logger.debug('Process container request')
            # Get list of objects
            list_url = 'http://%(ip)s:8080%(url)s'
            list_req = list_url % {'ip': self.ip,
                                   'url': req.path}
            self.logger.debug('list_req: %s', list_req)
            self.logger.debug('req.headers: %s', str(req.headers))
            token = req.headers['X-Storage-Token']
            self.logger.debug('token: %s', token)
            headers = {'X-Storage-Token': token}
            response = requests.get(list_req, headers=headers)
            self.logger.debug('response.headers: %s', str(response.headers))
            self.logger.debug('list: %s', str(response.content))
            objects = response.content.strip().split('\n')
            # Submit migration or recall
            if method == 'POST':
                if 'MIGRATE' in query:
                    hlm_req = 'MIGRATE'
                    hlm_backend = self.migrate_backend
                elif 'RECALL' in query:
                    hlm_req = 'RECALL'
                    hlm_backend = self.recall_backend
                # submit hlm requests
                success = 0
                failure = 0
                for obj in objects:
                    self.logger.debug('obj: %s', obj)
                    status, out = self.submit_object_replicas_migration_recall(
                        req, account, container, obj, hlm_req, hlm_backend)
                    self.logger.debug('submit_object_replicas_migr.._recall()')
                    if status == SUBMITTED_FORWARDED_REQUEST:
                        self.logger.debug('SUBMITTED_FORWARDED_REQUEST')
                        return Response(status=HTTP_OK,
                                        body='Accepted remote replica'
                                        'HLM request',
                                        content_type="text/plain")(
                            env, start_response)
                    elif status == FAILED_SUBMITTING_REQUEST:
                        self.logger.debug('FAILED_SUBMITTING_REQUEST')
                        failure += 1
                    elif status == SUBMITTED_REQUESTS:
                        self.logger.debug('SUBMITTED_REQUESTS')
                        success += 1
                if failure == 0:
                    return Response(status=HTTP_OK,
                                    body='Submitted %s requests.\n' % hlm_req,
                                    content_type="text/plain")(env,
                                                               start_response)
                elif success == 0:
                    return Response(status=HTTP_INTERNAL_SERVER_ERROR,
                                    body='Failed to submit %s requests.\n' %
                                    hlm_req,
                                    content_type="text/plain")(env,
                                                               start_response)
                else:
                    return Response(status=HTTP_OK,
                                    body="Submitting %s requests"
                                    " is only partially"
                                    " successful.\n" % hlm_req,
                                    content_type="text/plain")(env,
                                                               start_response)

        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    register_swift_info('hlm')

    def hlm_filter(app):
        return HlmMiddleware(app, conf)
    return hlm_filter
