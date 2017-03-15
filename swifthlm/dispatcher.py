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
This file implements Disaptcher component of SwiftHLM. 
"""

import errno
import os
import uuid
from swift import gettext_ as _
from time import ctime, time
from random import choice, random, shuffle
from struct import unpack_from

from eventlet import sleep, Timeout

import swift.common.db
from swift.container.backend import ContainerBroker, DATADIR
from swift.common.container_sync_realms import ContainerSyncRealms
from swift.common.internal_client import (
    delete_object, put_object, InternalClient, UnexpectedResponse)
from swift.common.exceptions import ClientException
from swift.common.ring import Ring
from swift.common.ring.utils import is_local_device
from swift.common.utils import (
    audit_location_generator, clean_content_type, config_true_value,
    FileLikeIter, get_logger, hash_path, quote, urlparse, validate_sync_to,
    whataremyips, Timestamp)
from swift.common.daemon import Daemon
from swift.common.http import HTTP_UNAUTHORIZED, HTTP_NOT_FOUND
from swift.common.storage_policy import POLICIES
from swift.common.wsgi import ConfigString

###
from swift.common.utils import readconf
from socket import gethostname, gethostbyname
import imp
import sys

#
from swifthlm import middleware


class SwiftHlmDispatcher(object):
    """
    Daemon to dispatch asynchronous SwiftHLM requests, i.e. migration and
    recall requests.
    """

    def __init__(self):

        # Config
        configFile = r'/etc/swift/proxy-server.conf'
        self.conf = readconf(configFile)

        # This host ip address
        self.ip = gethostbyname(gethostname())

        # Swift directory
        self.swift_dir = self.conf.get('swift_dir', '/etc/swift')

        # Logging
        hlm_stor_node_config = self.conf.get('filter:hlm', None)
        if hlm_stor_node_config:
            hlm_stor_node_log_level = hlm_stor_node_config.get('set log_level',
                    None)
        if hlm_stor_node_log_level:
            self.conf['log_level'] = hlm_stor_node_log_level
        self.logger = get_logger(self.conf, name='hlm-dispatcher',
                log_route='swifthlm', fmt="%(server)s: %(msecs)03d "
                "[%(filename)s:%(funcName)20s():%(lineno)s] %(message)s")

        # Import SwiftHLM middleware function that can be reused by Dispatcher
        self.swifthlm_mw = middleware.HlmMiddleware('proxy-server', self.conf)
        # and (!) initialize internal swift client (not done at init in mw)
        #self.swifthlm_mw.create_internal_swift_client()

        self.logger.info('info: Initialized Dispatcher')
        self.logger.debug('dbg: Initialized Dispatcher')


    # Pulls a request from the queue, dispatches it to storage nodes, gets and
    # merges the responses, if success remove from queue else queue as failed
    # and remove from queue.
    def process_next_request(self):
        mw = self.swifthlm_mw
        # Pull request
        request = mw.pull_a_mig_or_rec_request_from_queue()
        if request:
            # Found a request to process
            self.logger.info('Processing request %s', request)
            if len(sys.argv) >= 2:
                print 'Processing request ' + request
            timestamp, hlm_req, account, container, spi, obj = \
                mw.decode_request(request)
            self.logger.debug('ts:%s, hlmreq:%s, ac:%s, c:%s, spi:%s, o:%s',
                    timestamp, hlm_req, account, container, spi, obj ) 
            # TODO: next is n.a. from Dispatcher until the function is improved
            #   self.spi = mw.get_storage_policy_index(account,
            #        container)
            # Distribute request to storage nodes get responses
            mw.distribute_request_to_storage_nodes_get_responses(
                hlm_req, account, container, obj, spi)
            # Merge responses from storage nodes
            mw.merge_responses_from_storage_nodes(hlm_req)

            # Queue failed request to failed-hlm-requests container/queue
            if not 'successful' in mw.response_out:
                if mw.queue_failed_migration_or_recall_request(request):
                    self.logger.debug('Queued failed request: %s', request)
                else:
                    self.logger.error('Failed to queue failed req.: %s',
                            request)

            # If a request is resubmitted upon a failure(s) and succeeds,
            # clean up the related failed requests
            if 'successful' in mw.response_out:
                mw.success_remove_related_requests_from_failed_queue(request)

            # Delete the processed request from the pending-hlm-requests queue
            if mw.delete_request_from_queue(request, 'pending-hlm-requests'):
                self.logger.debug('Deleted request from queue: %s', request)
            else:
                self.logger.error('Failed to delete request: %s', request)

        return

    # Dispatcher runs until stopped
    # ... unless it is invoked with sys.argv[1] == 1 (testing mode)
    def run(self, *args, **kwargs):
        if len(sys.argv) == 2 and str(sys.argv[1]) == "1":
            self.logger.debug('Polling the requests queue')
            print 'Polling the requests queue'
            self.process_next_request()
            return
        else:
            while True:
                if len(sys.argv) >= 2:
                    print 'Polling the requests queue'
                self.logger.debug('Polling the requests queue')
                self.process_next_request()
                sleep(5) #TODO: make polling frequency adaptive to load

if __name__ == '__main__':
    dispatcher = SwiftHlmDispatcher()
    dispatcher.run()
