# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from novaclient.tests.unit import fakes
from novaclient.tests.unit.fixture_data import base


class Fixture(base.Fixture):

    base_url = 'os-security-group-rules'

    def setUp(self):
        super(Fixture, self).setUp()

        rule = {
            'id': 1,
            'parent_group_id': 1,
            'group_id': 2,
            'ip_protocol': 'TCP',
            'from_port': '22',
            'to_port': 22,
            'cidr': '10.0.0.0/8'
        }

        headers = self.json_headers

        self.requests_mock.get(self.url(),
                               json={'security_group_rules': [rule]},
                               headers=headers)

        for u in (1, 11, 12):
            self.requests_mock.delete(self.url(u),
                                      status_code=202,
                                      headers=headers)

        def post_rules(request, context):
            body = request.json()
            assert list(body) == ['security_group_rule']
            fakes.assert_has_keys(body['security_group_rule'],
                                  required=['parent_group_id'],
                                  optional=['group_id', 'ip_protocol',
                                            'from_port', 'to_port', 'cidr'])

            return {'security_group_rule': rule}

        self.requests_mock.post(self.url(),
                                json=post_rules,
                                headers=headers,
                                status_code=202)
