########
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

import pytest

from cosmo_tester.framework.examples.nodecellar import NodeCellarExample
from cosmo_tester.framework.fixtures import image_based_manager
from cosmo_tester.framework.util import prepare_and_get_test_tenant

manager = image_based_manager


def test_nodecellar_example(nodecellar):
    nodecellar.verify_all()


@pytest.fixture(
    scope='function',
    params=[
        'openstack',
        'simple',
    ],
)
def nodecellar(request, cfy, manager, attributes, ssh_key, tmpdir, logger):
    tenant = prepare_and_get_test_tenant(request.param, manager, cfy)
    nc = NodeCellarExample(
            cfy, manager, attributes, ssh_key, logger, tmpdir,
            tenant=tenant, suffix=request.param)
    nc.blueprint_file = '{type}-blueprint.yaml'.format(type=request.param)
    yield nc
