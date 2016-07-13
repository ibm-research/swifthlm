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

import json
import random
import subprocess
import unittest

import mock
from swift.common.swob import Request

from swifthlm import middleware as swifthlm


class FakeApp(object):
    def __init__(self, headers=None):
        if headers:
            self.headers = headers
        else:
            self.headers = {}

    def __call__(self, env, start_response):
        start_response('200 OK', self.headers)
        return []


class TestSwiftHLM(unittest.TestCase):

    def setUp(self):
        self.app = swifthlm.HlmMiddleware(FakeApp(), {})

    def test_migrate(self):
        subprocess.check_call = mock.Mock()
        random.choice = mock.Mock(return_value='0')
        environ = {'REQUEST_METHOD': 'POST'}
        req = Request.blank('/v1/a/c?MIGRATE', environ=environ,
                            headers={'X-Storage-Token': 'AUTH_t=='})
        resp = req.get_response(self.app)

        subprocess.check_call.assert_called_with(
            ['/opt/ibm/swift-hlm-backend/migrate', 'a/c', '000000000000'])
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, 'Submitted MIGRATE requests.\n')

    def test_recall(self):
        subprocess.check_call = mock.Mock()
        random.choice = mock.Mock(return_value='0')
        environ = {'REQUEST_METHOD': 'POST'}
        req = Request.blank('/v1/a/c?RECALL', environ=environ,
                            headers={'X-Storage-Token': 'AUTH_t=='})
        resp = req.get_response(self.app)

        subprocess.check_call.assert_called_with(
            ['/opt/ibm/swift-hlm-backend/recall', 'a/c', '000000000000'])
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, 'Submitted RECALL requests.\n')

    def test_get_status(self):
        subprocess.check_output = mock.Mock(return_value='{"object": "/v1/a/c/o", "status": "resident"}')
        random.choice = mock.Mock(return_value='0')
        req = Request.blank('/v1/a/c/o?STATUS')
        resp = req.get_response(self.app)

        subprocess.check_output.assert_called_with(
            ['/opt/ibm/swift-hlm-backend/status', 'a/c/o', '000000000000',
             'STATUS'])
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, '{"object": "/v1/a/c/o", "status": "resident"}\n')

    def test_invalid_get_status_POST(self):
        subprocess.check_output = mock.Mock(return_value='status output')
        random.choice = mock.Mock(return_value='0')
        environ = {'REQUEST_METHOD': 'POST'}
        req = Request.blank('/v1/a/c/o?STATUS', environ=environ)
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, '')

    def test_invalid_migrate_GET(self):
        subprocess.call = mock.Mock()
        random.choice = mock.Mock(return_value='0')
        req = Request.blank('/v1/a/c?MIGRATE')
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, '')

    def test_invalid_get_status_exception(self):
        subprocess.check_output = mock.Mock(
            side_effect=subprocess.CalledProcessError(1, 'cmd', 'boom!'))
        random.choice = mock.Mock(return_value='0')
        req = Request.blank('/v1/a/c/o?STATUS')
        resp = req.get_response(self.app)

        subprocess.check_output.assert_called_with(
            ['/opt/ibm/swift-hlm-backend/status', 'a/c/o', '000000000000',
             'STATUS'])
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, '{"object": "/v1/a/c/o", "status": ""}\n')

    def test_filter_factory(self):
        factory = swifthlm.filter_factory({'migrate_backend': '/a/b/c/migrate',
                                           'recall_backend': '/d/e/f/recall',
                                           'status_backend': '/g/h/i/status'})
        thehlm = factory('myapp')
        self.assertEqual(thehlm.migrate_backend, '/a/b/c/migrate')
        self.assertEqual(thehlm.recall_backend, '/d/e/f/recall')
        self.assertEqual(thehlm.status_backend, '/g/h/i/status')


if __name__ == '__main__':
    unittest.main()
