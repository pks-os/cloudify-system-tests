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

from cStringIO import StringIO
import pytest
import time

from cosmo_tester.framework.examples.hello_world import HelloWorldExample
from cosmo_tester.framework.cluster import CloudifyCluster
from .ha_helper import HighAvailabilityHelper as ha_helper


@pytest.fixture(scope='function', params=[2, 3])
def cluster(
        request, cfy, ssh_key, module_tmpdir, attributes, logger):
    """Creates a HA cluster from an image in rackspace OpenStack."""
    logger.info('Creating HA cluster of %s managers', request.param)
    cluster = CloudifyCluster.create_image_based(
        cfy,
        ssh_key,
        module_tmpdir,
        attributes,
        logger,
        number_of_managers=request.param,
        create=False)

    for manager in cluster.managers[1:]:
        manager.upload_plugins = False

    cluster.create()

    try:
        manager1 = cluster.managers[0]
        ha_helper.delete_active_profile()
        manager1.use()

        cfy.cluster.start(timeout=600,
                          cluster_host_ip=manager1.private_ip_address,
                          cluster_node_name=manager1.ip_address)

        for manager in cluster.managers[1:]:
            manager.use()
            cfy.cluster.join(manager1.ip_address,
                             timeout=600,
                             cluster_host_ip=manager.private_ip_address,
                             cluster_node_name=manager.ip_address)

        cfy.cluster.nodes.list()

        yield cluster

    finally:
        cluster.destroy()


@pytest.fixture(scope='function')
def cluster2(request, cfy, ssh_key, module_tmpdir, attributes, logger):
    """Like cluster, but not actually started

    So that we get two managers but can use one to be the proxy.
    """
    import pudb; pu.db  # NOQA
    cluster = CloudifyCluster.create_image_based(
        cfy,
        ssh_key,
        module_tmpdir,
        attributes,
        logger,
        number_of_managers=2,
        create=False)

    for manager in cluster.managers[1:]:
        manager.upload_plugins = False

    cluster.create()
    try:
        cluster.managers[0].use()

        with cluster.managers[1].ssh() as fabric:
            fabric.sudo('yum install socat -y')
            yield cluster
    finally:
        cluster.destroy()


@pytest.fixture(scope='function')
def hello_world2(cfy, cluster2, attributes, ssh_key, tmpdir, logger):
    cluster = cluster2
    hw = HelloWorldExample(
        cfy, cluster.managers[0], attributes, ssh_key, logger, tmpdir)
    hw.blueprint_file = 'openstack-blueprint.yaml'
    hw.inputs.update({
        'agent_user': attributes.centos7_username,
        'image': attributes.centos7_image_name,
    })

    yield hw
    if hw.cleanup_required:
        logger.info('Hello world cleanup required..')
        cluster.managers[0].use()
        hw.cleanup()


PROXY_SERVICE_TEMPLATE = """
[Unit]
Description=Proxy for port {port}
Wants=network-online.target

[Service]
User=root
Group=root
ExecStart=/bin/socat TCP-LISTEN:{port},fork TCP:{ip}:{port}
Restart=always
RestartSec=20s

[Install]
WantedBy=multi-user.target
"""


UPDATE_PROVIDER_CTX_SCRIPT = """
import sys
from manager_rest.server import app
from manager_rest.storage import get_storage_manager, models
from manager_rest.constants import PROVIDER_CONTEXT_ID
from sqlalchemy.orm.attributes import flag_modified


def update_provider_context(manager_ip):
    with app.app_context():
        sm = get_storage_manager()
        ctx = sm.get(models.ProviderContext, PROVIDER_CONTEXT_ID)
        ctx.context['cloudify']['cloudify_agent']['broker_ip'] = manager_ip
        flag_modified(ctx, 'context')
        sm.update(ctx)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Expected 1 argument - <manager-ip>')
        print('Provided args: {0}'.format(sys.argv[1:]))
        sys.exit(1)
    update_provider_context(sys.argv[1])
"""


CREATE_CERTS_SCRIPT = """
import logging
import sys

import utils


class CtxWithLogger(object):
    logger = logging.getLogger('internal-ssl-certs-logger')


utils.ctx = CtxWithLogger()

def generate_internal_ssl_cert(ips):
    return utils._generate_ssl_certificate(
        ips,
        ips[0],
        utils.INTERNAL_SSL_CERT_FILENAME,
        utils.INTERNAL_SSL_KEY_FILENAME,
        utils.INTERNAL_PKCS12_FILENAME,
    )

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Expected at least 1 argument - <manager-ip>')
        print('Provided args: {0}'.format(sys.argv[1:]))
        sys.exit(1)
    utils.generate_internal_ssl_cert(sys.argv[1:])

"""


def test_agent_via_proxy(cfy, cluster2, hello_world2, logger):
    # use separate cluster2 and helloworld2; really, i should've made a
    # separate test module

    # - run 2 managers
    # - one of them stops being a manager, and instead is the proxy
    # - the other is the manager, and updates its internal cert and provider
    # context to the proxy ips

    cluster = cluster2
    hello_world = hello_world2

    # prepare the proxy: stop manager stuff, run socat on 2 ports
    # TODO use a clean centos machine, not a manager, so that all the stopping
    # manager stuff isn't required
    with cluster.managers[1].ssh() as fabric:
        ip = cluster.managers[0].private_ip_address
        for service in ['cloudify-rabbitmq', 'cloudify-amqpinflux', 'cloudify-riemann', 'nginx', 'cloudify-restservice']:  # NOQA
            fabric.sudo('systemctl disable {0}'.format(service))
            fabric.sudo('systemctl stop {0}'.format(service))
        for port in [5671, 53333]:
            service = 'proxy_{0}'.format(port)
            filename = '/usr/lib/systemd/system/{0}.service'.format(service)
            fabric.put(
                StringIO(PROXY_SERVICE_TEMPLATE.format(ip=ip, port=port)),
                filename, use_sudo=True)
            fabric.sudo('systemctl enable {0}'.format(service))
            fabric.sudo('systemctl start {0}'.format(service))

    # prepare the actual manager to point to the proxy:
    #  - provider context broker_ip
    #  - TODO: other stuff in the context? (fileserver url?)
    #  - generate certs using the proxxy ip
    #  - note: we need cert that has both proxy and manager ip, because
    #    manager's own mgmtworker will try to contact restservice via the old
    #    ip (unless we change that?)
    with cluster.managers[0].ssh() as fabric:
        fabric.put(StringIO(UPDATE_PROVIDER_CTX_SCRIPT),
                   '/tmp/update_ctx.py', use_sudo=True)
        fabric.put(StringIO(CREATE_CERTS_SCRIPT),
                   '/tmp/create_certs.py', use_sudo=True)
        cmd = '/opt/mgmtworker/env/bin/python /tmp/create_certs {0} {1}'.format(  # NOQA
            cluster.managers[1].private_ip_address,
            cluster.managers[0].private_ip_address)
        fabric.sudo(cmd)

        cmd = 'MANAGER_REST_CONFIG_PATH=/opt/manager/cloudify-rest.conf /opt/manager/env/bin/python /tmp/update_ctx.py {0}'.format(  # NOQA
            cluster.managers[1].private_ip_address)
        fabric.sudo(cmd)

    hello_world.upload_blueprint()
    hello_world.create_deployment()
    hello_world.install()


@pytest.fixture(scope='function')
def hello_world(cfy, cluster, attributes, ssh_key, tmpdir, logger):
    hw = HelloWorldExample(
        cfy, cluster.managers[0], attributes, ssh_key, logger, tmpdir)
    hw.blueprint_file = 'openstack-blueprint.yaml'
    hw.inputs.update({
        'agent_user': attributes.centos7_username,
        'image': attributes.centos7_image_name,
    })

    yield hw
    if hw.cleanup_required:
        logger.info('Hello world cleanup required..')
        cluster.managers[0].use()
        hw.cleanup()


def test_data_replication(cfy, cluster, hello_world,
                          logger):
    manager1 = cluster.managers[0]
    ha_helper.delete_active_profile()
    manager1.use()
    ha_helper.verify_nodes_status(manager1, cfy, logger)
    hello_world.upload_blueprint()
    hello_world.create_deployment()
    hello_world.install()

    logger.info('Manager %s resources', manager1.ip_address)
    m1_blueprints_list = cfy.blueprints.list()
    m1_deployments_list = cfy.deployments.list()
    m1_plugins_list = cfy.plugins.list()

    for manager in cluster.managers[1:]:
        ha_helper.set_active(manager, cfy, logger)
        ha_helper.delete_active_profile()
        manager.use()
        ha_helper.verify_nodes_status(manager, cfy, logger)

        logger.info('Manager %s resources', manager.ip_address)
        assert m1_blueprints_list == cfy.blueprints.list()
        assert m1_deployments_list == cfy.deployments.list()
        assert m1_plugins_list == cfy.plugins.list()

    ha_helper.set_active(manager1, cfy, logger)
    ha_helper.delete_active_profile()
    manager1.use()


def test_set_active(cfy, cluster,
                    logger):
    manager1 = cluster.managers[0]
    ha_helper.delete_active_profile()
    manager1.use()
    ha_helper.verify_nodes_status(manager1, cfy, logger)

    for manager in cluster.managers[1:]:
        ha_helper.set_active(manager, cfy, logger)
        ha_helper.delete_active_profile()
        manager.use()
        ha_helper.verify_nodes_status(manager, cfy, logger)


def test_delete_manager_node(cfy, cluster, hello_world,
                             logger):
    ha_helper.set_active(cluster.managers[1], cfy, logger)
    expected_master = cluster.managers[0]
    for manager in cluster.managers[1:]:
        logger.info('Deleting manager %s', manager.ip_address)
        manager.delete()
        ha_helper.wait_leader_election(
            [m for m in cluster.managers if not m.deleted], logger)

    logger.info('Expected leader %s', expected_master)
    ha_helper.verify_nodes_status(expected_master, cfy, logger)
    hello_world.upload_blueprint()


def test_failover(cfy, cluster, hello_world,
                  logger):
    """Test that the cluster fails over in case of a service failure

    - stop nginx on leader
    - check that a new leader is elected
    - stop mgmtworker on that new leader, and restart nginx on the former
    - check that the original leader was elected
    """
    expected_master = cluster.managers[-1]
    # stop nginx on all nodes except last - force choosing the last as the
    # leader (because only the last one has services running)
    for manager in cluster.managers[:-1]:
        logger.info('Simulating manager %s failure by stopping'
                    ' nginx service', manager.ip_address)
        with manager.ssh() as fabric:
            fabric.run('sudo systemctl stop nginx')
        # wait for checks to notice the service failure
        time.sleep(20)
        ha_helper.wait_leader_election(cluster.managers, logger)
        cfy.cluster.nodes.list()

    ha_helper.verify_nodes_status(expected_master, cfy, logger)

    new_expected_master = cluster.managers[0]
    # force going back to the original leader - start nginx on it, and
    # stop mgmtworker on the current leader (simulating failure)
    with new_expected_master.ssh() as fabric:
        logger.info('Starting nginx service on manager %s',
                    new_expected_master.ip_address)
        fabric.run('sudo systemctl start nginx')

    with expected_master.ssh() as fabric:
        logger.info('Simulating manager %s failure by stopping '
                    'cloudify-mgmtworker service',
                    expected_master.ip_address)
        fabric.run('sudo systemctl stop cloudify-mgmtworker')

    # wait for checks to notice the service failure
    time.sleep(20)
    ha_helper.wait_leader_election(cluster.managers, logger)
    cfy.cluster.nodes.list()

    ha_helper.verify_nodes_status(new_expected_master, cfy, logger)
    hello_world.upload_blueprint()


def test_remove_manager_from_cluster(cfy, cluster, hello_world,
                                     logger):
    ha_helper.set_active(cluster.managers[1], cfy, logger)
    ha_helper.delete_active_profile()

    expected_master = cluster.managers[0]
    nodes_to_check = list(cluster.managers)
    for manager in cluster.managers[1:]:
        manager.use()
        logger.info('Removing the manager %s from HA cluster',
                    manager.ip_address)
        cfy.cluster.nodes.remove(manager.ip_address)
        nodes_to_check.remove(manager)
        ha_helper.wait_leader_election(nodes_to_check, logger)

    ha_helper.delete_active_profile()
    expected_master.use()

    ha_helper.verify_nodes_status(expected_master, cfy, logger)
    hello_world.upload_blueprint()


def test_uninstall_dep(cfy, cluster, hello_world,
                       logger):
    manager1 = cluster.managers[0]
    ha_helper.delete_active_profile()
    manager1.use()
    ha_helper.verify_nodes_status(manager1, cfy, logger)
    hello_world.upload_blueprint()
    hello_world.create_deployment()
    hello_world.install()

    manager2 = cluster.managers[-1]
    ha_helper.set_active(manager2, cfy, logger)
    ha_helper.delete_active_profile()
    manager2.use()
    hello_world.uninstall()
