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
This file implements SwiftHLM Dummy Backend Connector, a reference
implementation reusable for implementing a SwiftHLM Backend Connector for your
own HLM storage backend, which is considered backend-specific and external for
SwiftHLM. Any SwiftHLM Backend Connector implementation must implement
SwiftHlmBackendConnector class and its public method for SwiftHLM Generic
Backend API used between SwiftHLM and SwiftHLM Connector.

*** SwiftHLM Generic Backend API version 0.2.1 ***
API versions with 3rd digit different from 0, such 0.2.1, should be considered
developmental and not stable.

    response = SwiftHlmBackendConnector.submit_request_get_response(request)

request =
  {
  command : status,
  objects :
    [
      { object : /a/c/obj1, file : /srv/node/filepath1 },
      { object : /a/c/obj2, file : /srv/node/filepath2 }
    ]
  }

response =
  {
  objects :
    [
      {object : /a/c/obj1, file : /srv/node/filepath1, status : migrated,},
      {object : /a/c/obj2, file : /srv/node/filepath2, status : resident},
      {object : /a/c/obj3, file : /srv/node/filepath3, status : premigrated},
      {object : /a/c/obj4, file : /srv/node/filepath4, status : unknown}
    ]
  }

The data structures used are dicitionary and list, the values are strings,
shown above unquoted and additinally indented for easier reading.

In addition to 'status', other requests are 'migrate' or 'recall' for which the
response is integer:
    0 - success
    1 - 1 or more objects could not be migrated/recalled
    2 - unable to process request for all objects (e.g. cannot invoke backend)

Internal methods of SwiftHlmBackendConnector are backend specific, and
typically involve reformatting the list of object and files to be migrated,
submitting the list and the operation to backend, and receiving response from
backend. Typically it is the backend that moves data between LLM (low latency
media) and HLM (hight latency media) and changes or reports replica state. For
other types of HLM backend the data move and state management function may be
implemented in the SwiftHLM Backend Connector of that backend.

Authors:
Slavisa Sarafijanovic (sla@zurich.ibm.com)

"""

from sys import stdin, stdout
from collections import defaultdict
import ConfigParser
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

# scor aux
from swift.proxy.controllers.base import get_container_info

# scor aux
from swift.common.utils import hash_path

import sqlite3

# SwiftHLM Backend Connector
class SwiftHlmBackendConnector(object):

    def __init__(self):
        self.__request_in = {}
        self.__request_out = {}
        self.__response_in = {}
        self.__response_out = {}

        # Config
        configFile = r'/etc/swift/object-server.conf'
        self.conf = readconf(configFile)

        # Logging
        hlm_stor_node_config = self.conf.get('hlm', None)
        if hlm_stor_node_config:
            hlm_stor_node_log_level = hlm_stor_node_config.get('set log_level',
                                                               None)
        if hlm_stor_node_log_level:
            self.conf['log_level'] = hlm_stor_node_log_level
        self.logger = get_logger(self.conf, name='hlm-connector',
                                 log_route='swifthlm',
                                 fmt="%(server)s: %(msecs)03d "
                                 "[%(filename)s:%(funcName)20s():%(lineno)s] "
                                 "%(message)s")

        self.logger.info('info: Initialized Connector')
        self.logger.debug('dbg: Initialized Connector')
        # self.logger.info('conf: %s', self.conf)

    # Next method is to be invoked by SwiftHLM Handler using SwiftHLM Generic
    # Backend Interface (GBI) declared above in this file. It adapts SwiftHLM
    # request for an assumed dummy storage backend, mocks invoking the dummy
    # backend operations, reformats the backend response to GBI format, and
    # returns the response to SwitHLM handler
    def submit_request_get_response(self, request):
        self.__receive_request(request)
        self.__reformat_swifthlm_request_to_specific_backend_api()
        self.__submit_request_to_backend_get_response()
        self.__reformat_backend_response_to_generic_backend_api()
        return self.__response_out

    # This exemplary private method receives the request from SwiftHLM Handler
    def __receive_request(self, request):
        self.logger.debug('Receiving request from Handler')
        self.__request_in = request

    # This exemplary private method reformats request to backend API
    # Some backends expect as input a file that lists the object data files to
    # be migrated or recalled. For this dummy backend connector it just copies
    # the incoming request
    def __reformat_swifthlm_request_to_specific_backend_api(self):
        self.logger.debug('Reformatting request to the specific Backend API')
        self.logger.debug('request_in: %s', self.__request_in)

        # Backend specific part, for the assumed dummy backend just copies the
        # incoming request
        self.__request_out = self.__request_in

    # This exemplary method submits request to Backend and gets Response from
    # Backend. The dummy backend stores object state (resident, premigrated,
    # or migrated) into a SQL database on file, using the object replica 
    # filepath as the key and its status as the value.
    # The database file is stored under /tmp/swifthlm_dummy_backend.db, which
    # upon need could be made configurable.
    # TODO: consider making the database file location configurable. 
    def __submit_request_to_backend_get_response(self):
        self.logger.debug('Submitting request to backend')
        database = '/tmp/swifthlm_dummy_backend.db'
        db_backend = SwiftHlmDummyBackendDb(database)
        if db_backend == None:
            self.logger.debug('failed to connect to db_backend db')  
        self.logger.debug('before migrate')
        # migrate 
        if self.__request_out['request'] == 'migrate':
            for object_file in self.__request_out['objects']:
                try:
                    db_backend.insert(object_file['file'], 'migrated')
                except sqlite3.Error as err:
                    self.logger.debug('error: inserting migrated status \
                        into database (%s)', err)
            db_backend.close()
            self.__response_in = 0
            return
        self.logger.debug('before recall')
        # recall 
        if self.__request_out['request'] == 'recall':
            for object_file in self.__request_out['objects']:
                db_backend.query(object_file['file'])
                if db_backend.status == 'migrated':
                    try:
                        db_backend.insert(object_file['file'], 'premigrated')
                    except sqlite3.Error as err:
                        self.logger.debug('error: inserting premigrated \
                            status into database (%s)', err)
            db_backend.close()
            self.__response_in = 0
            return
        self.logger.debug('before status')
        # status
        objects_files_statuses = []
        for object_file in self.__request_out['objects']:
            object_file_status = {}
            object_file_status['object'] = object_file['object']
            object_file_status['file'] = object_file['file']
            db_backend.query(object_file['file'])
            object_file_status['status'] = db_backend.status
            objects_files_statuses.append(object_file_status)
        db_backend.close()
        self.__response_in['objects'] = objects_files_statuses
        # self.__response_in = self.__request_out

    def __reformat_backend_response_to_generic_backend_api(self):
        self.logger.debug('Reformatting response to Generic Backend API')
        self.logger.debug('response_in: %s', self.__response_in)

        # Backend specific part, for the assumed dummy backend it just copies
        # the incoming response from the backend
        self.__response_out = self.__response_in

# SwiftHLM Dummy Backend Database
class SwiftHlmDummyBackendDb:

    def __init__(self,dbname):
        self.connection = None
        self.cursor = None
        self.database = dbname
        self.table = 'status_table'
        self.key = 'item_path'
        self.value = 'status'
        self.status = None # to store queried status
        self.connect()

    def connect(self):
        try:
            self.connection = sqlite3.connect(self.database)
            self.cursor = self.connection.cursor()
        except sqlite3.Error as err:
            self.logger.debug('error: connecting to dummy backend status \
                    database (%s)', err)
            reise
        self.cursor.execute('CREATE TABLE IF NOT EXISTS {tn} \
                        ({kn} TEXT PRIMARY KEY, {vn} TEXT)'\
                        .format(tn=self.table, kn=self.key, vn=self.value))
        #self.connection.commit() # is it needed at this step?

    def close(self):
        if self.connection:
            self.connection.commit()
            self.cursor.close()
            self.connection.close()

    def insert(self, path, status):
        c = self.cursor
        c.execute('REPLACE INTO {tn} ({kn}, {vn}) VALUES (?, ?)'\
        .format(tn=self.table, kn=self.key, vn=self.value), (path, status))

    def query(self, path):
        c = self.cursor
        c.execute('SELECT {vn} FROM {tn} WHERE {kn}=?'\
        .format(tn=self.table, kn=self.key, vn=self.value), (path, )) #..h, )!!
        status = c.fetchone()
        if status:
            self.status = str(status[0])
        else:
            self.status = 'resident' # TODO: Handling 'unknown' status

if __name__ == '__main__':
    # SwiftHlmConnector class is not assumed to be used standalone, instead it
    # is imported for a configured backend by SwiftHLM Handler and invoked from
    # the Handler. Alternatively it could be modified to be invoked as a new
    # process and/or remotely similar to SwiftHLM Dispatcher invoking SwiftHLM
    # Handler
    raise
