#!/usr/bin/python

# (C) Copyright 2016-2017 IBM Corp.
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

# Authors:
# Slavisa Sarafijanovic (sla@zurich.ibm.com)
# Harald Seipp (seipp@de.ibm.com)

# SwiftHLM is useful for running OpenStack Swift on top of high latency media
# (HLM) storage, such as tape or optical disk archive based backends, allowing
# to store cheaply and access efficiently large amounts of infrequently used
# object data.
#
# This file implements SwiftHLM Middleware component of SwiftHLM, which is the
# middleware added to Swift's proxy server.
#
# SwiftHLM middleware extends Swift's interface and thus allows to explicitly
# control and query the state (on disk or on HLM) of Swift object data,
# including efficient prefetch of bulk of objects from HLM to disk when those
# objects need to be accessed.
#
# SwiftHLM provides the following basic HLM functions on the external Swift
# interface:
# - MIGRATE (container or an object from disk to HLM)
# - RECALL (i.e. prefetch a container or an object from HLM to disk)
# - STATUS (get status for a container or an object)
# - REQUESTS (get status of migration and recall requests previously submitted
#   for a contaner or an object).
#
# MIGRATE and RECALL are asynchronous operations, meaning that the request from
# user is queued and user's call is responded immediately, then the request is
# processed as a background task. Requests are currently processed in a FIFO
# manner (scheduling optimizations are future work).
# REQUESTS and STATUS are synchronous operations that block the user's call
# until the queried information is collected and returned.
#
# For each of these functions, SwiftHLM Middleware invokes additional SwiftHLM
# components to perform the task, which includes calls to HLM storage backend.
#
# -------
# MIGRATE
# -------
#
# Trigger a migration from disk to HLM of a single object or all objects within
# a container.
# MIGRATE request is an HTTP POST request, with the following syntax:
#
#     POST http://<host>:<port>/hlm/v1/MIGRATE/<account>/<container>/<object>
#     POST http://<host>:<port>/hlm/v1/MIGRATE/<account>/<container>
#
#     Note: SwiftHLM request keywords are case-insensitive, MIGRATE or migrate
#     can be used, RECALL or recall, STATUS or status, REQUESTS or requests.
#
# ------
# RECALL
# ------
#
# Trigger a recall from HLM to disk for a single object or all objects within a
# container.
# RECALL request is an HTTP POST request, with the following syntax:
#
#     POST http://<host>:<port>/hlm/v1/RECALL/<account>/<container>/<object>
#     POST http://<host>:<port>/hlm/v1/RECALL/<account>/<container>
#
# ------
# STATUS
# ------
#
# Return, as the response body, a JSON encoded dictionary of objects and their
# status (on HLM or on disk) for a given object or all objects within a
# container.
# STATUS query request is an HTTP GET request, with the following syntax:
#
#     GET http://<host>:<port>/hlm/v1/STATUS/<account>/<container>/<object>
#     GET http://<host>:<port>/hlm/v1/STATUS/<account>/<container>
#
# ------
# REQUESTS
# ------
#
# Return, as the response body, a JSON encoded list of pending or failed
# migration and recall requests submitted for a contaner or an object.
# REQUESTS query request is an HTTP GET request, with the following syntax:
#
#     GET http://<host>:<port>/hlm/v1/REQUESTS/<account>/<container>/<object>
#     GET http://<host>:<port>/hlm/v1/REQUESTS/<account>/<container>

import subprocess
import random
import string
import select
import requests
import netifaces
import threading
import time
import datetime
import socket
import getpass

from collections import defaultdict
from paramiko import SSHClient, AutoAddPolicy
from errno import ENOENT

from swift.common.swob import Request, Response
from swift.common.http import (HTTP_OK, HTTP_INTERNAL_SERVER_ERROR,
                               HTTP_ACCEPTED, HTTP_PRECONDITION_FAILED)
from swift.common.utils import register_swift_info, cache_from_env
from swift.common.memcached import MemcacheConnectionError

from swift.common.ring import Ring
from swift.common.utils import json, get_logger, split_path
from swift.common.swob import Request, Response
from swift.common.swob import HTTPBadRequest, HTTPMethodNotAllowed
from swift.common.storage_policy import POLICIES
from swift.proxy.controllers.base import get_container_info

from socket import gethostname, gethostbyname
import ConfigParser
from collections import OrderedDict
from ast import literal_eval

from swift.common.internal_client import (delete_object, put_object,
                                          InternalClient, UnexpectedResponse)
from swift.common.exceptions import ClientException
from swift.common.utils import (
    audit_location_generator, clean_content_type, config_true_value,
    FileLikeIter, get_logger, hash_path, quote, urlparse, validate_sync_to,
    whataremyips, Timestamp)
from swift.common.wsgi import ConfigString
from eventlet import sleep, Timeout

from swift.common.direct_client import (ClientException, direct_head_container,
                                        direct_get_container,
                                        direct_put_container_object)
from swift.common.http import HTTP_NOT_FOUND
from eventlet import Timeout, GreenPool, GreenPile, sleep
from swift.common.utils import (split_path, config_true_value, whataremyips,
                                get_logger, Timestamp, list_from_csv,
                                last_modified_date_to_timestamp, quorum_size)
from swift.common.utils import readconf
import re

# SwiftHLM Queues: account and container names
SWIFTHLM_ACCOUNT = '.swifthlm'
SWIFTHLM_PENDING_REQUESTS_CONTAINER = 'pending-hlm-requests'
SWIFTHLM_FAILED_REQUESTS_CONTAINER = 'failed-hlm-requests'

# The default internal client config body is to support upgrades without
# requiring deployment of the new /etc/swift/internal-client.conf
ic_conf_body = """
[DEFAULT]
# swift_dir = /etc/swift
# user = swift
# You can specify default log routing here if you want:
# log_name = swift
# log_facility = LOG_LOCAL0
# log_level = INFO
# log_address = /dev/log
#
# comma separated list of functions to call to setup custom log handlers.
# functions get passed: conf, name, log_to_console, log_route, fmt, logger,
# adapted_logger
# log_custom_handlers =
#
# If set, log_udp_host will override log_address
# log_udp_host =
# log_udp_port = 514
#
# You can enable StatsD logging here:
# log_statsd_host = localhost
# log_statsd_port = 8125
# log_statsd_default_sample_rate = 1.0
# log_statsd_sample_rate_factor = 1.0
# log_statsd_metric_prefix =

[pipeline:main]
pipeline = catch_errors proxy-logging cache proxy-server

[app:proxy-server]
use = egg:swift#proxy
# See proxy-server.conf-sample for options
allow_account_management = false

[filter:cache]
use = egg:swift#memcache
# See proxy-server.conf-sample for options

[filter:proxy-logging]
use = egg:swift#proxy_logging

[filter:catch_errors]
use = egg:swift#catch_errors
# See proxy-server.conf-sample for options
""".lstrip()


class HlmMiddleware(object):

    def __init__(self, app, conf):
        # App is the final application
        self.app = app

        # Config
        self.conf = conf

        # This host ip address
        self.ip = gethostbyname(gethostname())

        # Swift directory
        self.swift_dir = conf.get('swift_dir', '/etc/swift')

        # Logging
        self.logger = get_logger(conf, name='hlm-middleware',
                                 log_route='swifthlm',
                                 fmt="%(server)s: %(msecs)03d "
                                 "[%(filename)s:%(funcName)20s():%(lineno)s] "
                                 "%(message)s")

        # Request
        self.req = ''
        # Per storage node request list
        self.per_node_request = defaultdict(list)
        # Responses received from storage nodes
        self.response_in = defaultdict(list)
        # Locks
        self.stdin_lock = threading.Lock()
        self.stout_lock = threading.Lock()
        # Internal swift client
        self.create_internal_swift_client()
        # Container ring
        self.container_ring = Ring(self.swift_dir, ring_name='container')

        # Memcache client
        self.mcache = None

        self.logger.info('info: Initialized SwiftHLM Middleware')
        self.logger.debug('dbg: Initialized SwiftHLM Middleware')

    # Get ring info needed for determining storage nodes
    def get_object_ring(self, storage_policy_index):
        return POLICIES.get_object_ring(storage_policy_index, self.swift_dir)

    # Determine storage policy index uses self.app inside proxy
    def get_storage_policy_index(self, account, container):
        container_info = get_container_info(
            {'PATH_INFO': '/v1/%s/%s' % (account, container)},
            self.app, swift_source='LE')
        storage_policy_index = container_info['storage_policy']
        return storage_policy_index

    # Determine storage nodes and other info for locating data file
    def get_obj_storage_nodes(self, account, container, obj, spi):
        obj_ring = self.get_object_ring(storage_policy_index=spi)
        swift_dir = self.swift_dir
        partition, nodes = obj_ring.get_nodes(account, container, obj)
        self.logger.debug('Storage nodes: %s' % str(nodes))
        ips = []
        devices = []
        for node in nodes:
            ips.append(node['ip'])
            devices.append(node['device'])
        return ips, devices, spi, swift_dir

    def __call__(self, env, start_response):
        self.logger.debug('env: %s', str(env))
        self.logger.debug('env[PATH_INFO]: %s', str(env['PATH_INFO']))
        # self.logger.debug('env[RAW_PATH_INFO]: %s',
        #                   str(env['RAW_PATH_INFO']))
        req = Request(env)
        self.req = req

        if self.mcache is None:
            self.mcache = cache_from_env(req.environ)
        if not self.mcache:
            self.logger.error('Memcache not found')
        else:
            self.logger.debug('Memcache registered')

        # Split request path to determine version, account, container, object
        try:
            (namespace, ver_ifhlm, cmd_ifhlm, acc_ifhlm, con_ifhlm, obj_ifhlm)\
                    = req.split_path(1, 6, True)
        except ValueError:
            self.logger.debug('split_path exception')
            return self.app(env, start_response)
        self.logger.debug(':%s:%s:%s:%s:%s:%s:', namespace, ver_ifhlm,
                          cmd_ifhlm, acc_ifhlm, con_ifhlm, obj_ifhlm)

        if namespace == 'hlm':
            try:
                hlm_req = cmd_ifhlm.lower()
            except AttributeError:
                self.logger.debug('unexpected hlm_req attribute')
                return self.app(env, start_response)
            account = acc_ifhlm
            container = con_ifhlm
            obj = obj_ifhlm
        else:
            try:
                (version, account, container, obj) = req.split_path(1, 4, True)
            except ValueError:
                self.logger.debug('split_path exception')
                return self.app(env, start_response)
            self.logger.debug(':%s:%s:%s:%s:', version, account, container,
                              obj)

        # More debug info
        self.logger.debug('req.headers: %s', str(self.req.headers))

        # If request is not HLM request or not a GET, it is not processed
        # by this middleware
        method = req.method
        if not (namespace == 'hlm'):
            hlm_req = None

        if not (method == 'GET' and
                (obj or hlm_req == 'status' or hlm_req == 'requests') or
                method == 'POST' and
                (hlm_req == 'migrate' or hlm_req == 'recall' or
                 hlm_req == 'smigrate' or hlm_req == 'srecall')):
            if method == 'PUT' and obj:
                objpath = '/%s/%s/%s' % (account, container, obj)
                self._put_state_to_cache(objpath, 'resident')
            return self.app(env, start_response)

        # Process by this middleware. First check if the container and/or
        # object exist
        # TODO: Investigate impact of these checks on GET object performance,
        # if necessary consider skipping the check or doing it at a later step
        if not self.swift.container_exists(account, container):
                rbody = "/account/container /%s/%s does not exist." % \
                        (account,
                         container)
                rbody_json = {'error': rbody}
                rbody_json_str = json.dumps(rbody_json)
                return Response(status=HTTP_NOT_FOUND,
                                body=rbody_json_str,
                                content_type="application/json")(
                                    env, start_response)
        elif obj:
            obj_exists = False
            try:
                path = self.swift.make_path(account, container, obj)
                resp = self.swift.make_request('HEAD', path, {},
                                               (2, HTTP_NOT_FOUND))
                if not resp.status_int == HTTP_NOT_FOUND:
                    obj_exists = True
            except Exception, e:  # noqa
                self.logger.error('List container objects error: %s', str(e))
                rbody = "Unable to check does object %s belong to /%s/%s." % \
                        (obj, account, container)
                rbody_json = {'error': rbody}
                rbody_json_str = json.dumps(rbody_json)
                return Response(status=HTTP_INTERNAL_SERVER_ERROR,
                                body=rbody_json_str,
                                content_type="application/json")(
                                    env,
                                    start_response)
            if not obj_exists:
                rbody = "Object /%s/%s/%s does not exist." % (account,
                                                              container, obj)
                rbody_json = {'error': rbody}
                rbody_json_str = json.dumps(rbody_json)
                return Response(status=HTTP_NOT_FOUND,
                                body=rbody_json_str,
                                content_type="application/json")(
                                    env,
                                    start_response)

        # Process GET object data request, if object is migrated return error
        # code 412 'Precondition Failed' (consider using 455 'Method Not Valid
        # in This State') - the error code is returned if any object replica is
        # migrated.
        # TODO: provide option to return error code only if all replicas are
        # migrated, and redirect get request to one of non-migrated replicas
        if req.method == "GET" and obj \
                and hlm_req != 'status' and hlm_req != 'requests':
            # check status and either let GET proceed or return error code
            hlm_req = 'status'
            status = 'unknown'
            # check if status is cached in memcached
            if self.mcache:
                (valid, cached) = self._get_object_state_from_cache(account,
                                                                    container,
                                                                    obj)
                if valid:
                    status = cached

            if status == 'unknown':
                # Distribute request to storage nodes get responses
                self.distribute_request_to_storage_nodes_get_responses(
                    hlm_req,
                    account,
                    container,
                    obj)

                # Merge responses from storage nodes
                # i.e. merge self.response_in into self.response_out
                self.merge_responses_from_storage_nodes(hlm_req)

                # Resident or premigrated state is condition to pass request,
                # else return error code
                self.logger.debug('self.response_out: %s',
                                  str(self.response_out))
                obj = "/" + "/".join([account, container, obj])
                status = self.response_out[obj]

            if status not in ['resident', 'premigrated']:
                return Response(status=HTTP_PRECONDITION_FAILED,
                                body="Object %s needs to be RECALL-ed before "
                                "it can be accessed.\n" % obj,
                                content_type="text/plain")(env, start_response)

            return self.app(env, start_response)

        # Synchronous query about pending/failed previous SwiftHLM requests
        # Return pending/failed requests that match queried account(/container)
        elif (method == 'GET' and hlm_req == 'requests'):
            self.logger.debug('Requests query')
            self.get_pending_and_failed_requests(account, container, obj)
            if len(self.response_out) == 0:
                txt_msg = "There are no pending or failed SwiftHLM requests."
                self.response_out.append(txt_msg)
            jout = json.dumps(self.response_out)
            return Response(status=HTTP_OK,
                            body=jout,
                            content_type="text/plain")(env, start_response)

        # Async hlm migration or recall request
        elif method == 'POST' and \
                (hlm_req == 'migrate'or hlm_req == 'recall'):
            # if not self.swift:
            #    self.create_internal_swift_client()
            self.logger.debug(':%s:%s:%s:%s:', account, container, obj,
                              hlm_req)
            # Pass to Dispatcher also storage policy index spi, because
            # self.app is not available in Dispatcher
            # TODO w/o self.app, using Ring.get_nodes(acc,cont)
            spi = self.get_storage_policy_index(account, container)
            self.logger.debug('spi: %s', str(spi))
            self.queue_migration_or_recall_request(hlm_req, account, container,
                                                   spi, obj)
            self.logger.debug('Queued %s request.', hlm_req)
            # If migrating, set cached object status to 'migrated'
            # at dispatch time, only correct in case migration failed
            if hlm_req == 'migrate':
                self._put_migrated_state_to_cache(account, container, obj)

            return Response(status=HTTP_OK,
                            body='Accepted %s request.\n' % hlm_req,
                            content_type="text/plain")(env, start_response)

        # scur
        # Synchronous SwiftHLM status/mig/rec request
        elif (method == 'GET' and hlm_req == 'status') \
                or method == 'POST' and \
                (hlm_req == 'smigrate' or hlm_req == 'srecall'):
            if (hlm_req == 'smigrate' or hlm_req == 'srecall'):
                hlm_req = hlm_req[1:]
            cached = False
            if method == 'GET':
                if obj:
                    (valid, cache_data) = self._get_object_state_from_cache(
                        account, container, obj)
                    if valid:
                        cached = True
                        self.response_out = {}
                        objpath = '/%s/%s/%s' % (account, container, obj)
                        self.response_out[objpath] = cache_data
                else:
                    if self._objects_cached(account, container):
                        cached = True

            if not cached:
                # Distribute request to storage nodes get responses
                self.distribute_request_to_storage_nodes_get_responses(
                    hlm_req, account, container, obj)

                # Merge responses from storage nodes
                # i.e. merge self.response_in into self.response_out
                self.merge_responses_from_storage_nodes(hlm_req)

            # Report result
            # jout = json.dumps(out) + str(len(json.dumps(out)))
            jout = json.dumps(self.response_out)  # testing w/ response_in
            return Response(status=HTTP_OK,
                            body=jout,
                            content_type="text/plain")(env, start_response)

        return self.app(env, start_response)

    def get_list_of_objects(self, account, container):
        try:
            objects_iter = self.swift.iter_objects(account, container)
        except UnexpectedResponse as err:
            self.logger.error('List container objects error: %s', err)
            return False
        except Exception, e:  # noqa
            self.logger.error('List container objects error: %s', str(e))
            return False
        objects = []
        if objects_iter:
            # pick and return a request
            for obj in objects_iter:
                objects.append(obj['name'])
        return objects

    def _get_object_state_from_cache(self, account, container, object):
        memcache_key = u'hlm/%s/%s/%s' % (account, container,
                                         object)
        cache_data = None
        try:
            cache_data = self.mcache.get(memcache_key)
            if cache_data is None:
                return False, None
            self.logger.debug('Got cache entry %s: %s', memcache_key,
                              cache_data)

        except MemcacheConnectionError:
            self.logger.error('Memcache connection error')
            return False, None
        return True, cache_data

    def _put_state_to_cache(self, objpath, state):
        if self.mcache:
            memcache_key = u'hlm%s' % objpath
            try:
                self.mcache.set(memcache_key, state)
                self.logger.debug('Cached: %s: %s', memcache_key, state)
            except MemcacheConnectionError:
                self.logger.error('Memcache connection error')
                return False
        else:
            self.logger.debug('Cache not found')
            return False
        return True

    def _put_migrated_state_to_cache(self, account, container, objname):
        if objname:
            objpath = u'/%s/%s/%s' % (account, container, objname)
            return self._put_state_to_cache(objpath, 'migrated')
        else:
            try:
                objects_iter = self.swift.iter_objects(account, container)
            except UnexpectedResponse as err:
                self.logger.error('List container objects error: %s', err)
                return False
            except Exception, e:  # noqa
                self.logger.error('List container objects error: %s', str(e))
                return False
            if objects_iter:
                for obj in objects_iter:
                    objpath = '/%s/%s/%s' % (account, container, obj['name'])
                    if not self._put_state_to_cache(objpath, 'migrated'):
                        return False
        return True

    def _remove_obj_from_cache(self, objpath):
        if self.mcache:
            memcache_key = u'hlm%s' % objpath
            try:
                self.mcache.delete(memcache_key)
                self.logger.debug('Deleted %s from cache', memcache_key)
            except MemcacheConnectionError:
                self.logger.error('Memcache connection error')
                return False
        else:
            return False
        return True

    def _remove_from_cache(self, account, container, objname):
        if objname:
            objpath = u'/%s/%s/%s' % (account, container, objname)
            return self._remove_obj_from_cache(objpath)
        else:
            try:
                objects_iter = self.swift.iter_objects(account, container)
            except UnexpectedResponse as err:
                self.logger.error('List container objects error: %s', err)
                return False
            except Exception, e:  # noqa
                self.logger.error('List container objects error: %s', str(e))
                return False
            if objects_iter:
                for obj in objects_iter:
                    objpath = u'/%s/%s/%s' % (account, container, obj['name'])
                    if not self._remove_obj_from_cache(objpath):
                        return False
        return True

    def _objects_cached(self, account, container):
        self.response_out = {}
        try:
            objects_iter = self.swift.iter_objects(account, container)
        except UnexpectedResponse as err:
            self.logger.error('List container objects error: %s', err)
            return False
        except Exception, e:  # noqa
            self.logger.error('List container objects error: %s', str(e))
            return False
        if objects_iter:
            for obj in objects_iter:
                (valid, cache_data) = self._get_object_state_from_cache(
                    account, container, obj['name'])
                if not valid:
                    return False
                objpath = u'/%s/%s/%s' % (account, container, obj['name'])
                self.response_out[objpath] = cache_data
        return True

    def create_per_storage_node_objects_list_and_request(self, hlm_req,
                                                         account, container,
                                                         obj, spi):
        # Create per node list of object(s) replicas
        # Syntax: per_node_list={'node1':[obj1,obj3], 'node2':[obj3,obj4]}
        # First get list of objects
        objects = []
        if obj:
            self.logger.debug('Object request: %s', str(obj))
            objects.append(str(obj))
        else:
            self.logger.debug('Container request')
            # Get list of objects
            objects = self.get_list_of_objects(account, container)
            if objects:
                self.logger.debug('objects(first 1024 bytes): %s',
                                  str(objects)[0:1023])
        # Add each object to its nodes' lists
        per_node_list = defaultdict(list)
        # Set container storage policy (if not passed to and set by Dispatcher)
        if not spi:
            spi = self.get_storage_policy_index(account, container)
        for obj in objects:
            obj_path = '/' + account + '/' + container + '/' + obj
            ips, devices, storage_policy_index, swift_dir \
                = self.get_obj_storage_nodes(account, container, obj, spi)
            i = 0
            for ip_addr in ips:
                obj_path_and_dev = {}
                obj_path_and_dev['object'] = obj_path
                obj_path_and_dev['device'] = devices[i]
                i += 1
                # per_node_list[ip_addr].append(obj_path)
                per_node_list[ip_addr].append(obj_path_and_dev)

        # Create json-formatted requests
        self.per_node_request = defaultdict(list)
        for ip_addr in per_node_list:
            request = {}
            request['request'] = hlm_req
            request['objects'] = per_node_list[ip_addr]
            request['storage_policy_index'] = storage_policy_index
            request['swift_dir'] = swift_dir
            self.per_node_request[ip_addr] = request

    def submit_request_to_storage_node_and_get_response(self, ip_addr):
        self.stdin_lock.acquire()
        self.logger.debug('Dispatching request to %s', str(ip_addr))
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        ssh_client.load_system_host_keys()
        ssh_client.connect(ip_addr, username=getpass.getuser())
        # Prepare remote Handler execution ssh pipe
        stdin, stdout, stderr = ssh_client.exec_command(
                'python -m ' + 'swifthlm.handler')
        ich = stdin.channel
        och = stdout.channel
        # Remote process stderr is not (yet) used here
        ech = stderr.channel
        # Send request data
        ich.sendall(json.dumps(self.per_node_request[ip_addr]))
        stdin.flush()
        ich.shutdown_write()
        stdin.close()
        response = ''
        self.stdin_lock.release()

        self.stout_lock.acquire()
        # Set initial max amount of data to receive, after first receive we
        # adapt to the receive buffer size
        max_receive_bytes = 100
        # Ensure that reads are blocking (non-busy wait)
        och.setblocking(1)
        while True:
            chunk = och.recv(max_receive_bytes)
            self.logger.debug("Bytes received: <%d>", len(chunk))
            if (len(chunk) == 0) and och.eof_received:
                # Stop receiving as channel stream has closed.
                # Inspired by Paramiko channel.py source comments.
                # Other methods to determine command completion are
                # unreliable.
                break
            # Adjust max retrieve size to receive buffer length.
            # Note that it is assumed that data is delivered constantly once
            # available ie. max_receive_bytes is non-zero after first data
            # receiption.
            max_receive_bytes = len(och.in_buffer)
            response += chunk

        self.logger.debug("Response (first+last 512 bytes): <%s ... %s>" %
                          (response[0:512], response[-512:]))
        self.stout_lock.release()
        # Closing the client will close the transport and channels
        ssh_client.close()
        self.response_in[ip_addr] = response
        return

    def distribute_request_to_storage_nodes_get_responses(self, hlm_req,
                                                          account,
                                                          container,
                                                          obj, spi=None):
        # Create per storage node list of object(s) replicas
        # Syntax: per_node_list={'node1':[obj1,obj3], 'node2':[obj3,obj4]}
        # ... and the request for submitting to Handler
        self.create_per_storage_node_objects_list_and_request(hlm_req,
                                                              account,
                                                              container,
                                                              obj, spi)

        self.logger.debug(
            'After'
            ' self.create_per_storage_node_objects_list_and_request()')

        # For each storage node/list dispatch request to the storage node
        # and get response
        self.response_in = defaultdict(list)
        threads = []
        for ip_addr in self.per_node_request:
            # logs inside loop outside of threads nok...
            th = threading.Thread(
                target=self.submit_request_to_storage_node_and_get_response,
                args=(ip_addr,))
            th.start()
            threads.append(th)
        for th in threads:
            th.join()

    def merge_responses_from_storage_nodes(self, hlm_req):
        if hlm_req == 'status':
            # STATUS
            self.response_out = {}
            for ip_addr in self.response_in:
                self.logger.debug('response_in[ip_addr](first 1024 bytes): %s',
                                  str(self.response_in[ip_addr])[0:1023])
                resp_in = {}
                try:
                    resp_in = (json.loads(
                        self.response_in[ip_addr]))['objects']
                except ValueError as err:
                    self.logger.error('Could not decode JSON response: %s',
                                      err)
                for dct in resp_in:
                    self.logger.debug('dct: %s', str(dct))
                    obj = dct['object']
                    if obj not in self.response_out:
                        self.response_out[obj] = dct['status']
                    elif self.response_out[obj] != dct['status']:
                        self.response_out[obj] = 'unknown'
                    # Cache status response
                    self._put_state_to_cache(obj, self.response_out[obj])
        else:
            # MIGRATE or RECALL
            self.response_out = "0"
            for ip_addr in self.response_in:
                if self.response_in[ip_addr] != self.response_out:
                    self.response_out = "1"
            if self.response_out == "0":
                self.response_out = "SwiftHLM " + hlm_req + \
                        " request completed successfully."
            elif self.response_out == "1":
                self.response_out = "SwiftHLM " + hlm_req + \
                        " request failed."
            else:
                self.response_out = "Unable to invoke SwiftHLM " + \
                        hlm_req + " request."

    # Create internal swift client self.swift
    def create_internal_swift_client(self):
        conf = self.conf
        request_tries = int(conf.get('request_tries') or 3)
        internal_client_conf_path = conf.get('internal_client_conf_path')
        proxy_config_file = r'/etc/swift/proxy-server.conf'
        proxy_config = readconf(proxy_config_file)
        proxy_app_config = proxy_config.get('app:proxy-server', None)
        allow_acc_mgmt = proxy_app_config.get('allow_account_management', None)
        self.logger.debug('allow_account_management: %s\n',
                allow_acc_mgmt)
        if allow_acc_mgmt == 'true':
            ic_conf_body_use = re.sub(r'allow_account_management = .+\n',
                    r'allow_account_management = true\n',
                    ic_conf_body)
        else:
            ic_conf_body_use = ic_conf_body
        if not internal_client_conf_path:
            # self.logger.warning(
            # ('Configuration option internal_client_conf_path not '
            # 'defined. Using default configuration, See '
            # 'internal-client.conf-sample for options'))
            internal_client_conf = ConfigString(ic_conf_body_use)
        else:
            internal_client_conf = internal_client_conf_path
        self.logger.debug('internal_client_conf: %s\n',
                str(internal_client_conf))
        try:
            self.swift = InternalClient(
                internal_client_conf, 'SwiftHLM Middleware', request_tries)
        except IOError as err:
            if err.errno != ENOENT:
                raise
            raise SystemExit(
                _('Unable to load internal client from config: %r (%s)') %
                (internal_client_conf_path, err))

    def direct_put_to_swifthlm_account(self, container, obj, headers):
        """
        :param container: a container name in SWIFTHLM_ACCOUNT
        :param obj: a object name
        :param headers: a dict of headers
        :returns: the request does succeed or not
        """
        def _check_success(*args, **kwargs):
            try:
                direct_put_container_object(*args, **kwargs)
                return 1
            except (ClientException, Timeout, socket.error):
                return 0

        pile = GreenPile()
        part, nodes = self.container_ring.get_nodes(
            SWIFTHLM_ACCOUNT, container)
        for node in nodes:
            pile.spawn(_check_success, node, part,
                       SWIFTHLM_ACCOUNT, container, obj, headers=headers,
                       conn_timeout=5, response_timeout=15)

        successes = sum(pile)
        if successes >= quorum_size(len(nodes)):
            return True
        else:
            return False

    def queue_migration_or_recall_request(self, hlm_req,
                                          account, container, spi, obj):
        # Debug info
        self.logger.debug('Queue HLM %s request\n', hlm_req)
        self.logger.debug('/acc/con/obj: %s/%s/%s', account, container, obj)
        # Queue request as empty object in special /account/container
        # /SWIFTHLM_ACCOUNT/SWIFTHLM_PENDING_REQUESTS_CONTAINER
        # Name object using next syntax
        # /yyyymmddhhmmss.msc/migrate|recall/account/container/spi
        # /yyyymmddhhmmss.msc/migrate|recall/account/container/spi/object
        curtime = datetime.datetime.now().strftime("%Y%m%d%H%M%S.%f")[:-3]
        req_name = "/".join(['', curtime, hlm_req, account, container,
                             str(spi)])
        if obj:
            req_name += "/" + obj
        # Queue SwiftHLM task by storing empty object to special container
        headers = {'X-Size': 0,
                   'X-Etag': 'swifthlm_task_etag',
                   'X-Timestamp': Timestamp(time.time()).internal,
                   'X-Content-Type': 'application/swifthlm-task'}
        try:
            self.direct_put_to_swifthlm_account(
                SWIFTHLM_PENDING_REQUESTS_CONTAINER, req_name, headers)
        except Exception:
            self.logger.exception(
                'Unhandled Exception trying to create queue')
            return False
        return True

    def pull_a_mig_or_rec_request_from_queue(self):
        # Pull a request from SWIFTHLM_PENDING_REQUESTS_CONTAINER
        # First list the objects (requests) from the queue
        # headers_out = {'X-Newest': True}
        try:
            objects = self.swift.iter_objects(
                    account=SWIFTHLM_ACCOUNT,
                    container=SWIFTHLM_PENDING_REQUESTS_CONTAINER)
            # headers=headers_out)
        except UnexpectedResponse as err:
            self.logger.error('Pull request error: %s', err)
            return False
        except Exception, e:  # noqa
            self.logger.error('Pull request error: %s', str(e))
            return False
        request = None
        if objects:
            # Pick a request, currently the oldest one
            # TODO: consider merging requests, prioritizing recalls
            for obj in objects:
                request = str(obj['name'])
                self.logger.debug('Pulled a request from queue: %s', request)
                break
        return request

    def queue_failed_migration_or_recall_request(self, request):
        # Debug info
        self.logger.debug('Queue failed request: %s', request)
        # Create container/queue for failed requests, if not existing
        # TODO: consider checking/doing this 'one time' only e.g. at install
        if not self.swift.container_exists(
                account=SWIFTHLM_ACCOUNT,
                container=SWIFTHLM_FAILED_REQUESTS_CONTAINER):
            try:
                self.swift.create_container(
                    account=SWIFTHLM_ACCOUNT,
                    container=SWIFTHLM_FAILED_REQUESTS_CONTAINER)
            except Exception, e:  # noqa
                self.logger.error('Queue request error: %s', str(e))
                return False
        # queue failed request
        body = ''
        try:
            self.swift.upload_object(
                FileLikeIter(body),
                account=SWIFTHLM_ACCOUNT,
                container=SWIFTHLM_FAILED_REQUESTS_CONTAINER,
                obj=request)
        except UnexpectedResponse as err:
            self.logger.error('Queue failed request error: %s', err)
            return False
        except Exception, e:  # noqa
            self.logger.error('Queue failed request error: %s', str(e))
            return False
        return True

    def success_remove_related_requests_from_failed_queue(self, request):
        ts, hlm_req, acc, con, spi, obj = \
            self.decode_request(request)
        failed_requests = \
            self.get_list_of_objects(SWIFTHLM_ACCOUNT,
                                     SWIFTHLM_FAILED_REQUESTS_CONTAINER)
        for freq in failed_requests:
            fts, fhlm_req, facc, fcon, fspi, fobj = \
                self.decode_request(freq)
            # TODO Consider removing obj requests when cont request succeeds
            # as well as other similar "merging" logic
            if fobj == obj and fcon == con and facc == acc:
                if not self.delete_request_from_queue(
                        freq, SWIFTHLM_FAILED_REQUESTS_CONTAINER):
                    self.logger.warning('Stale failed request %s', freq)

    def delete_request_from_queue(self, request, queue):
        # Debug info
        self.logger.debug('Delete %s from %s', request, queue)
        # delete request
        try:
            self.swift.delete_object(
                account=SWIFTHLM_ACCOUNT,
                container=queue,
                obj=request)
        except UnexpectedResponse as err:
            self.logger.error('Delete request error: %s', err)
            return False
        except Exception, e:  # noqa
            self.logger.error('Delete request error: %s', str(e))
            return False
        return True

    def decode_request(self, request):
        # Note: no backward compatibility to previous implementation
        # that used '--' as delimiter.
        req_parts = request.split('/')[1:]
        timestamp = req_parts[0]
        hlm_req = req_parts[1]
        account = req_parts[2]
        container = req_parts[3]
        spi = req_parts[4]
        if len(req_parts) > 5:
            obj = '/'.join(req_parts[5:])
        else:
            obj = None
        return timestamp, hlm_req, account, container, spi, obj

    def get_pending_and_failed_requests(self, acc, con, obj):
        self.logger.debug('Get pending hlm requests')
        pending_requests = \
            self.get_list_of_objects(SWIFTHLM_ACCOUNT,
                                     SWIFTHLM_PENDING_REQUESTS_CONTAINER)
        self.logger.debug('pending: %s', str(pending_requests))
        self.logger.debug('Get failed hlm requests')
        failed_requests = \
            self.get_list_of_objects(SWIFTHLM_ACCOUNT,
                                     SWIFTHLM_FAILED_REQUESTS_CONTAINER)
        self.logger.debug('failed: %s', str(failed_requests))
        self.response_out = []
        for preq in pending_requests:
            self.logger.debug('pending: %s', str(preq))
            ts, hlm_req, a, c, sp, o = self.decode_request(preq)
            if not obj and a == acc and c == con or \
                obj and a == acc and c == con and o == obj or \
                    obj and not o and a == acc and c == con:
                self.response_out.append(preq + '--pending')
        for freq in failed_requests:
            ts, hlm_req, a, c, sp, o = self.decode_request(freq)
            if not obj and a == acc and c == con or \
                obj and a == acc and c == con and o == obj or \
                    obj and not o and a == acc and c == con:
                self.response_out.append(freq + '--failed')
        self.logger.debug('reqs: %s', str(self.response_out))


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    register_swift_info('hlm')

    def hlm_filter(app):
        return HlmMiddleware(app, conf)
    return hlm_filter
