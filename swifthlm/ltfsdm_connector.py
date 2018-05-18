#!/usr/bin/python

# (C) Copyright 2018 IBM Corp.
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
#

"""
Authors:
Slavisa Sarafijanovic (sla@zurich.ibm.com)
Harald Seipp (seipp@de.ibm.com)
"""

"""
This file implements SwiftHLM Connector for LTFS Data Management (LTFS DM)
backend, i.e. the connector between SwiftHLM and the tape-enabled file storage
backend LTFS DM. LTFS DM is a software that adds tape storage to a standard
disk based Linux filesystem - it keeps the original namespace of the disk file
system exposed to users and applications (via standard POSIX interface) but
allows migrating file data to and from attached tape storage. LTFS DM is open
sourced at https://github.com/ibm-research/LTFS-Data-Management.  
Toward SwiftHLM the connector implements SwiftHLM Generic Backend API as
declared in dummy_connector.py of SwiftHLM. On the backend side the connector
maps SwiftHLM requests to the backend's migrate, recall and query status
operations.
"""

from swift.common.utils import readconf
from swift.common.utils import json, get_logger
from sys import stdin, stdout
import os
import errno
import uuid
import subprocess

# SwiftHLM Backend Connector


class SwiftHlmBackendConnector(object):

    def __init__(self):
        self.__request_in = {}
        self.__request_out = {}
        self.__request_out_request = ''
        self.__request_out_filelist = ''
        self.__response_in = {}
        self.__response_out = {}

        # Config
        configFile = r'/etc/swift/object-server.conf'
        self.conf = readconf(configFile)

        # Logging
        self.hlm_stor_node_config = self.conf.get('hlm', None)
        if self.hlm_stor_node_config:
            hlm_stor_node_log_level = self.hlm_stor_node_config.get(
                'set log_level', None)
        if hlm_stor_node_log_level:
            self.conf['log_level'] = hlm_stor_node_log_level
        self.logger = get_logger(self.conf, name='hlm-connector',
                                 log_route='swifthlm', fmt="%(server)s: %(msecs)03d "
                                 "[%(filename)s:%(funcName)20s():%(lineno)s] %(message)s")

        self.logger.info('info: Initialized Connector')
        self.logger.debug('dbg: Initialized Connector')
        self.logger.info('conf: %s', self.conf['log_level'])
        #self.logger.info('conf: %s', self.conf)
        self.logger.debug('conf: %s', json.dumps(self.conf.get('hlm', None)))
        self.logger.debug('conf: %s', json.dumps(
            self.conf.get('ltfsdm', None)))

        # Connector settings
        self.ltfsdm_cfg = self.conf.get('ltfsdm', None)
        if not self.ltfsdm_cfg:
            self.logger.error('LTFS DM connector not configured in \
                    /etc/swift/object-server.conf')
            raise
        # Check connector settings, make temporary directory if it does not
        # exist
        self.ltfsdm_path = self.ltfsdm_cfg.get('ltfsdm_path',
                                               '/usr/local/bin/ltfsdm')
        # if not os.path.isfile(self.ltfsdm_path):
        if os.system('sudo -i ' + self.ltfsdm_path +
                     ' help > /dev/null 2>&1') != 0:
            self.logger.error("ERROR: ltfsdm binary not present at"
                              " configured (or default) path %s", self.ltfsdm_path)
            raise
        self.connector_tmp_dir = self.ltfsdm_cfg.get('connector_tmp_dir', None)
        if self.connector_tmp_dir:
            self.mkdir_minus_p(self.connector_tmp_dir)
        else:
            self.logger.error('Swifthlm temporary directory not configured')
            raise
        self.tape_storage_pool = self.ltfsdm_cfg.get('tape_storage_pool', None)
        if not self.tape_storage_pool:
            self.logger.error('Tape storage pool not configured.')
            raise

    # Next method is invoked by SwiftHLM Handler using SwiftHLM Generic Backend
    # Interface (GBI). It adapts SwiftHLM request for LTFS DM backend, invokes
    # the backend operations, reformats the backend response to GBI format, and
    # returns the response to SwitHLM Handler
    def submit_request_get_response(self, request):
        self.__receive_request(request)
        self.__reformat_swifthlm_request_to_specific_backend_api()
        self.__submit_request_to_backend_get_response()
        self.__reformat_backend_response_to_generic_backend_api()
        return self.__response_out

    # This method receives the request from SwiftHLM Handler
    def __receive_request(self, request):

        self.logger.debug('Receiving request from Handler')
        self.__request_in = request

        return

    # This method reformats request to backend API
    def __reformat_swifthlm_request_to_specific_backend_api(self):

        self.logger.debug('Reformatting request to the specific Backend API')
        self.logger.debug('request_in(first 1024 bytes): %s',
                          str(self.__request_in)[0:1023])

        # Backend specific part
        self.__request_out_request = self.__request_in['request']
        if str.lower((self.__request_in['request']).encode('utf-8')) == 'status':
            # status: reuse input request as is
            self.__request_out = self.__request_in
        else:
            # migration or recall: prepare list for bulk migration/recall
            # in a temporary file
            tmp_filename = str(uuid.uuid1())
            self.__request_out_list = self.connector_tmp_dir + '/' + \
                tmp_filename
            f = open(self.__request_out_list, 'w')
            for obj_and_file in self.__request_in['objects']:
                f.write(str(obj_and_file['file']) + '\n')
            f.close()
            fr = open(self.__request_out_list, 'r')
            file_list_content = fr.read()
            self.logger.debug('file_list: %s', file_list_content)
            fr.close()

        return

    # This method submits request to Backend and gets Response from Backend
    def __submit_request_to_backend_get_response(self):

        self.logger.debug('Submitting request to backend')
        if self.__request_out_request == 'status':
            # query status
            self.query_status_receive_response()
        elif self.__request_out_request == 'migrate':
            #self.__response_in = 0
            self.migrate_receive_response()
        elif self.__request_out_request == 'recall':
            self.recall_receive_response()
        else:  # wrong request, TODO: move this check, do early as possible
            raise
        return

    def __reformat_backend_response_to_generic_backend_api(self):

        self.logger.debug('Reformatting response to Generic Backend API')
        self.logger.debug('response_in(first 1024 bytes): %s',
                          str(self.__response_in)[0:1023])

        # In this connector implementaiton, the mapping of the response from
        # the backend to the GBI is done in the functions
        # migrate_receive_response(), recall_receive_response() and
        # query_status_receive_response() when setting response_in varible, it
        # only remains to copy it to response_out.
        self.__response_out = self.__response_in

        return

    def mkdir_minus_p(self, dir_path):
        try:
            os.makedirs(dir_path)
        except OSError as err:  # TODO: check python 3.x
            if err.errno == errno.EEXIST and os.path.isdir(dir_path):
                pass
            else:
                raise
        return

    def migrate_receive_response(self):
        self.logger.debug('In migrate_receive_response()')
        listfile = self.__request_out_list
        request = self.__request_out_request
        # Migrate object files - unfortunately ltfsdm migrate must be run as
        # root
        self.logger.debug('self.ltfsdm_path: %s', self.ltfsdm_path)
        cmd = ["sudo", "-i", self.ltfsdm_path, "migrate", "-f", listfile, '-P']
        for pool in self.tape_storage_pool.split():
            cmd.append(pool)
        self.logger.debug('cmd: %s', cmd)
        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE)
        out, error = p.communicate()
        rc = p.returncode
        self.logger.debug('migrate.out(first 1024 bytes): %s',
                          str(out)[0:1023])
        self.logger.debug('rc: %s', rc)
        if rc == 6:
            rc = 0
        self.__response_in = rc
        return

    def recall_receive_response(self):
        listfile = self.__request_out_list
        request = self.__request_out_request
        # Recall object files - unfortunately ltfsdm migrate must be run as
        # root
        cmd = ["sudo", "-i", self.ltfsdm_path, "recall", "-f", listfile]
        self.logger.debug('cmd: %s', cmd)
        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE)
        out, error = p.communicate()
        rc = p.returncode
        self.logger.debug('recall.out(first 1024 bytes): %s', str(out)[0:1023])
        self.logger.debug('rc: %s', rc)
        self.__response_in = rc
        return

    def query_status_receive_response(self):
        self.logger.debug('query_status_receive_response()')

        # prepare temporary lists unique file name prefix
        lists_prefix = str(uuid.uuid1())
        input_list = self.connector_tmp_dir + '/' + lists_prefix + \
            '.list.status.input'
        self.logger.debug('input_list: %s', input_list)
        f = open(input_list, 'w')
        for obj_and_file in self.__request_in['objects']:
            f.write(str(obj_and_file['file']) + '\n')
        f.close()

        # mmapplypolicy output is by default owned by root, 0600 file mode
        # so we create it as swift user to be able to process it later
        output_list = self.connector_tmp_dir + '/' + lists_prefix + \
            '.list.status.output'
        self.logger.debug('output_list: %s', output_list)
        open(output_list, 'w').close()
        output_list_prefix = self.connector_tmp_dir + '/' + lists_prefix

        # Prepare status scan command
        cmd = ["sudo" +
               " -i " +
               self.ltfsdm_path +
               " info" +
               " files" +
               " -f " + input_list +
               " | awk 'NR > 1 { print }'" +
               " >" + output_list]
        self.logger.debug('cmd: %s', cmd)
        # Invoke the command
        p = subprocess.Popen(cmd,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        # Check result
        if p.returncode:
            self.logger.error('Status query errors: %s', err)
            return

        fr = open(output_list, 'r')
        file_list_content = fr.read()
        self.logger.debug('output_list(first 1024 bytes): %s',
                          str(file_list_content)[0:1023])
        fr.close()

        # get file-status pairs
        names_statuses = {}
        fr = open(output_list, 'r')
        for line in fr.readlines():
            self.logger.debug('line: %s', str(line))
            file_name = line.split()[-1]
            file_status = line.split()[0]
            if file_status == 'r':
                file_status = 'resident'
            elif file_status == 'p':
                file_status = 'premigrated'
            elif file_status == 'm':
                file_status = 'migrated'
            self.logger.debug('file_name: %s', file_name)
            self.logger.debug('file_status: %s', file_status)
            names_statuses[file_name] = file_status

        # create object to file to status mapping
        objects = []
        for obj_and_file in self.__request_out['objects']:
            obj_file_status = {}
            obj_file_status['object'] = obj_and_file['object']
            obj_file_status['file'] = obj_and_file['file']
            filenamekey = obj_and_file['file']
            self.logger.debug('filenamekey: %s', filenamekey)
            filenamekey = os.path.realpath(filenamekey)
            self.logger.debug('filenamekey: %s', filenamekey)
            obj_file_status['status'] = names_statuses[filenamekey]
            objects.append(obj_file_status)
        self.__response_in['objects'] = objects

        # TODO: uncomment or modify next 2 lines once major defects are fixed
        # os.remove(input_list)
        # os.remove(output_list)
        return

    def set_statuses_to_unknown(self):
        objects = []
        for obj_and_file in self.__request_out['objects']:
            obj_file_status = obj_and_file
            obj_file_status['status'] = 'unknown'
            objects.append(obj_file_status)
        self.__response_in['objects'] = objects
        return


if __name__ == '__main__':
    # SwiftHlmConnector class is not assumed to be used standalone, instead it
    # is imported for a configured backend by SwiftHLM Handler and invoked from
    # the Handler.
    raise
