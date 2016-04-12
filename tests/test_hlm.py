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

        path = env.get('PATH_INFO')
        if path == '/v1/AUTH_.auth/account1/.services':
            return json.dumps({'storage': {
                'cluster_name': 'http://localhost/v1/AUTH_123'}})
        return []


class TestSwiftHLM(unittest.TestCase):

    def test_migrate(self):
        app = swifthlm.HlmMiddleware(FakeApp(), {})

        subprocess.call = mock.Mock()
        random.choice = mock.Mock(return_value='0')
        environ = {'REQUEST_METHOD': 'POST'}
        req = Request.blank('/v1/a/c?MIGRATE', environ=environ)
        resp = req.get_response(app)

        subprocess.call.assert_called_with(
            ['/opt/ibm/swift-hlm-backend/migrate', 'a/c', '000000000000'])
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, 'Accepted migration request.\n')

    def test_recall(self):
        app = swifthlm.HlmMiddleware(FakeApp(), {})

        subprocess.call = mock.Mock()
        random.choice = mock.Mock(return_value='0')
        environ = {'REQUEST_METHOD': 'POST'}
        req = Request.blank('/v1/a/c?RECALL', environ=environ)
        resp = req.get_response(app)

        subprocess.call.assert_called_with(
            ['/opt/ibm/swift-hlm-backend/recall', 'a/c', '000000000000'])
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, 'Accepted recall request.\n')

    def test_get_status(self):
        app = swifthlm.HlmMiddleware(FakeApp(), {})

        subprocess.check_output = mock.Mock(return_value='status output')
        random.choice = mock.Mock(return_value='0')
        req = Request.blank('/v1/a/c?STATUS')
        resp = req.get_response(app)

        subprocess.check_output.assert_called_with(
            ['/opt/ibm/swift-hlm-backend/status', 'a/c', '000000000000'])
        self.assertEquals(resp.status_int, 200)
        self.assertEquals(resp.body, 'status output')


if __name__ == '__main__':
    unittest.main()
