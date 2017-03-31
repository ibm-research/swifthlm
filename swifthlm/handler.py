#!/usr/bin/python

# (C) Copyright 2017 IBM Corp.
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
Authors:
Slavisa Sarafijanovic (sla@zurich.ibm.com)
"""

"""
This file contains implementation of the SwiftHLM Handler component of the
SwiftHLM - a Swift extension for high latency media support.  SwiftHLM Handler
is installed on a Swift storage node, and invoked by a SwiftHLM proxy
middleware (SwiftHLM Middleware) when processing STATUS request or by SwiftHLM
Dispatcher process when processing MIGRATE or RECALL request. For an object or
a list of objects from a container, SwiftHLM Handler creates a list that maps
objects to file path(s) and submits the list to the HLM backend for migration,
recall or status processing.  
"""

from sys import stdin, stdout 
from collections import defaultdict
#from swift.common import read_config_file
import ConfigParser
from ConfigParser import RawConfigParser
from swift.common.utils import readconf
from swift.common.utils import json, get_logger, split_path
import logging

from swift.obj.server import ObjectController
from swift.common.storage_policy import POLICIES
from swift.common.exceptions import ConnectionTimeout, DiskFileQuarantined, \
    DiskFileNotExist, DiskFileCollision, DiskFileNoSpace, DiskFileDeleted, \
    DiskFileDeviceUnavailable, DiskFileExpired, ChunkReadTimeout, \
    DiskFileXattrNotSupported
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPCreated, \
    HTTPInternalServerError, HTTPNoContent, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestTimeout, HTTPUnprocessableEntity, \
    HTTPClientDisconnect, HTTPMethodNotAllowed, Request, Response, \
    HTTPInsufficientStorage, HTTPForbidden, HTTPException, HeaderKeyDict, \
    HTTPConflict, HTTPServerError
import os
import imp

#scor aux
from swift.proxy.controllers.base import get_container_info

#scor aux
from swift.common.utils import hash_path

#
import swifthlm.dummy_connector
import importlib

# SwiftHLM Handler maps objects to files and submits requests to Storage
# Backend via Backend Connector
class Handler(object):

    def __init__(self):
        self.request_in = ''
        self.request_out = ''
        self.response_in = ''
        self.response_out = ''

        # Config
        configFile = r'/etc/swift/object-server.conf'
        self.conf = readconf(configFile) 
        # readconf does not load the [DEFAULT] section, adding that manually
        rcp = RawConfigParser()
        cf = open(configFile, 'r')
        rcp.readfp(cf)
        full_conf = self.conf.copy()
        full_conf.update(rcp.defaults())
        cf.close()
        self.conf = full_conf

        # Logging
        hlm_stor_node_config = self.conf.get('hlm', None)
        if hlm_stor_node_config:
            hlm_stor_node_log_level = hlm_stor_node_config.get('set log_level',
                    None)
        if hlm_stor_node_log_level:
            self.conf['log_level'] = hlm_stor_node_log_level
        self.logger = get_logger(self.conf, name='hlm-handler',
                log_route='swifthlm', fmt="%(server)s: %(msecs)03d "
                "[%(filename)s:%(funcName)20s():%(lineno)s] %(message)s")

        self.logger.info('info: Initialized Handler')
        self.logger.debug('dbg: Initialized Handler')
        #self.logger.info('conf: %s', self.conf)

        # Generic backend interface (GBI) configuration options
        self.gbi_provide_dirpaths_instead_of_filepaths = False
        conf_gbi_provide_dirpaths_instead_of_filepaths = \
                hlm_stor_node_config.get(\
                    'gbi_provide_dirpaths_instead_of_filepaths',
                    'False')
        if conf_gbi_provide_dirpaths_instead_of_filepaths == 'True':
            self.gbi_provide_dirpaths_instead_of_filepaths = True

        # Backend connector (directory and .py filename) can be configured in 
        # /etc/swift/object-server.conf
        # If nothing is configured a dummy backend connector, that is provided
        # and installed with SwiftHLM is used by default
        swifthlm_connector_module = hlm_stor_node_config.get(
                'swifthlm_connector_module',
                '')
        swifthlm_connector_dir = hlm_stor_node_config.get(
                'swifthlm_connector_dir',
                '')
        swifthlm_connector_filename = hlm_stor_node_config.get(
                'swifthlm_connector_filename',
                '') 
        swifthlm_connector_path = swifthlm_connector_dir + '/' + \
                swifthlm_connector_filename
        if swifthlm_connector_module:
            self.logger.debug('swifthlm_connector_module: %s',
                    swifthlm_connector_module)
            self.swifthlm_connector_mod = \
                importlib.import_module(swifthlm_connector_module, package=None)
        elif swifthlm_connector_filename:
            swifthlm_connector_module = swifthlm_connector_filename[:-3]
            self.logger.debug('swifthlm_connector_path: %s',
                    swifthlm_connector_path)
            self.swifthlm_connector_mod = \
                imp.load_source(swifthlm_connector_module,
                swifthlm_connector_path)
        else:
            self.logger.debug('Using default swifthlm_connector_module: %s',
                    'swifthlm.dummy_connector')
            self.swifthlm_connector_mod = swifthlm.dummy_connector

    # Receive request from dispatcher
    def receive_request(self):
        
        self.logger.debug('Receiving request from Dispatcher')
        self.request_in = str(stdin.read())

        return
       
    # Map objects to their local storage server data replicas
    # and create a request for the generic backend interface 
    def map_objects_to_targets(self):

        self.logger.debug('Mapping objects to files')
        self.logger.debug('request_in(first 1024 bytes): %s',
                str(self.request_in)[0:1023])
    
        request_in_dict = json.loads(self.request_in)
        #TODO consider modifying incoming request in place
        self.request_out = {}
        self.request_out['request'] = request_in_dict['request']
        objects_and_files = []
        for obj_and_dev in request_in_dict['objects']:
            obj_and_file = {}
            obj_and_file['object'] = obj_and_dev['object'] 
            self.logger.debug('obj: %s', obj_and_dev)        
            try:
                (account, container, obj) = split_path(obj_and_dev['object'],
                        3, 3, False)
            except ValueError:
                self.logger.debug('split_path exception')        
                raise
            device = obj_and_dev['device']
            # TODO, can can storage_policy_index be determined from storage
            # node to not have to pass from proxy?                      
#           # container_info = get_container_info(
#           #     {'PATH_INFO': '/v1/%s/%s' % (account, container)},
#           #     self.app, swift_source='LE')
#           # storage_policy_index = container_info['storage_policy']
#           # obj_ring = self.get_object_ring(storage_policy_index)
            swift_dir = request_in_dict['swift_dir']
            storage_policy_index = request_in_dict['storage_policy_index']
            obj_ring = POLICIES.get_object_ring(storage_policy_index,
                    swift_dir)
            #need partition, same comment as for storage_policy_index
            partition, nodes = obj_ring.get_nodes(account, container, obj)
            self.logger.debug('Storage nodes: %s' % str(nodes))
            self.logger.debug('partition: %s', partition)
            #scor (aux)
            #key = hash_path(account, container, obj, raw_digest=True)
            key = hash_path(account, container, obj)
            self.logger.debug('hash_path or key: %s', key)
            
            # Create/use Object Controller to map objects to files            
            oc = ObjectController(self.conf, self.logger)
            self.logger.debug('oc.node_timeout: %s', oc.node_timeout)            
            policy = POLICIES.get_by_index(storage_policy_index)
            self.logger.debug('policy: %s index: %s', policy, str(int(policy)))
            try:
                oc.disk_file = oc.get_diskfile(
                    device, partition, account, container, obj,
                    policy=policy)
            except DiskFileDeviceUnavailable: #scor
                self.logger.error("Unavailable device: %s, for object: %s,"
                "storage policy: %s", device, obj_and_dev['object'], policy)
            data_dir = oc.disk_file._datadir
            self.logger.debug('data_dir: %s', data_dir)
            # Swift-on-File detection
            # Get the device path from the object server config file
            devpath = self.conf.get('devices', None)
            # The Swift-on-File device directory is a symlink
            # in the devpath directory constructed like shown below
            sofpath = devpath + '/' + obj_and_dev['device']
            if str.find(data_dir, sofpath) == 0 and os.path.islink(sofpath):
                # data_dir starts with sofpath and sofpath is a symlink -> SoF
                self.logger.debug('SOF detected, sofpath: %s, realpath: %s',
                                  sofpath, os.path.realpath(sofpath))
                # Follow the symlink and append a/c/o to get the data file path
                oc._data_file = os.path.realpath(sofpath) + \
                                obj_and_file['object']
                data_dir = os.path.realpath(sofpath) + '/' + account +\
                           '/' + container
            else:
                if not self.gbi_provide_dirpaths_instead_of_filepaths:
                    files = os.listdir(oc.disk_file._datadir)
                    file_info = oc.disk_file._get_ondisk_file(files)
                    oc._data_file = file_info.get('data_file')
                    self.logger.debug('data_file: %s', oc._data_file)
            # Add file path to the request
            self.logger.debug('obj_and_dev: %s', obj_and_dev)
            if not self.gbi_provide_dirpaths_instead_of_filepaths:
                obj_and_file['file'] = oc._data_file
            else:
                obj_and_file['file'] = data_dir 
            self.logger.debug('obj_and_file: %s', obj_and_file)
            objects_and_files.append(obj_and_file)
            
        self.logger.debug('objects_and_files(first 1024 bytes): %s',
               str(objects_and_files[0:1023]))
        self.request_out['objects'] = objects_and_files

        self.logger.debug('request_in(first 1024 bytes): %s',
                str(self.request_in)[0:1023]) 
        self.logger.debug('request_out(first 1024 bytes): %s',
                str(self.request_out)[0:1023]) 
        pass

        return
    # Submit request to Backend via Backend Connector
    # and get Response from Backend
    def submit_request_get_response(self):
        
        self.logger.debug('Submitting request to backend')
        #self.response_out = self.request_in
        connector = self.swifthlm_connector_mod.SwiftHlmBackendConnector()
        self.response_in = \
            connector.submit_request_get_response(self.request_out)
        self.response_out = self.response_in
        return


    # Return request result back to SwiftHLM Proxy Middleware (STATUS)
    # or to Asynchronous Distributor (MIGRATION or RECAL)
    def return_response(self):

        self.logger.debug('Return response to Dispatcher')
        stdout.write(json.dumps(self.response_out))
        stdout.flush()
        stdout.close()

        return


if __name__ == '__main__':
    handler = Handler()
    handler.receive_request()
    handler.map_objects_to_targets()
    handler.submit_request_get_response()
    handler.return_response()

