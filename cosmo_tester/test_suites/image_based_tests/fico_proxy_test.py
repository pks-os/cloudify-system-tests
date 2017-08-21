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

import time
import json
import pytest
from cStringIO import StringIO

from cosmo_tester.framework.examples.hello_world import HelloWorldExample
from cosmo_tester.framework.cluster import CloudifyCluster, MANAGERS


@pytest.fixture(scope='function')
def cluster(request, cfy, ssh_key, module_tmpdir, attributes, logger):
    """Like cluster, but not actually started

    So that we get two managers but can use one to be the proxy.
    """
    managers = [MANAGERS['4.1.1.1']() for _ in range(2)]

    for manager in managers[1:]:
        manager.upload_plugins = False

    managers.append(MANAGERS['notamanager'](upload_plugins=False))
    cluster = CloudifyCluster.create_image_based(
        cfy,
        ssh_key,
        module_tmpdir,
        attributes,
        logger,
        managers=managers,
        create=False)

    cluster.create()
    try:
        cluster.managers[0].use()

        with cluster.managers[-1].ssh() as fabric:
            fabric.sudo('yum install socat -y')
            yield cluster
    finally:
        cluster.destroy()


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
    generate_internal_ssl_cert(sys.argv[1:])

"""


IPTABLES_TEMPLATE = """
iptables -A INPUT -p tcp -s 127.0.0.1 --dport 5671 -j ACCEPT
iptables -A INPUT -p tcp -s {own_ip} --dport 5671 -j ACCEPT
iptables -A INPUT -p tcp -s {proxy_ip} --dport 5671 -j ACCEPT
iptables -A INPUT -p tcp --dport 5671 -j DROP

iptables -A INPUT -p tcp -s 127.0.0.1 --dport 53333 -j ACCEPT
iptables -A INPUT -p tcp -s {own_ip} --dport 53333 -j ACCEPT
iptables -A INPUT -p tcp -s {proxy_ip} --dport 53333 -j ACCEPT
iptables -A INPUT -p tcp --dport 53333 -j DROP
"""


CERTS = [
    '/etc/cloudify/ssl/cloudify_internal_cert.pem',
    '/etc/cloudify/ssl/cloudify_internal_key.pem',
    '/etc/cloudify/ssl/cloudify_internal.p12',
]


def _make_certs(manager, proxy_ip):
    create_certs_path = '/opt/cloudify/manager-ip-setter/create_certs.py'
    with manager.ssh() as fabric:
        fabric.put(StringIO(CREATE_CERTS_SCRIPT),
                   create_certs_path, use_sudo=True)
        cmd = '/opt/mgmtworker/env/bin/python {0} {1} {2}'.format(
            create_certs_path,
            proxy_ip,
            manager.private_ip_address)
        fabric.sudo(cmd)
        certs = [StringIO() for _ in CERTS]
        for path, dest in zip(CERTS, certs):
            fabric.get(path, dest, use_sudo=True)
    return certs


def _upload_certs(manager, certs):
    with manager.ssh() as fabric:
        for path, src in zip(CERTS, certs):
            fabric.put(src, path, use_sudo=True)


def test_agent_via_proxy(cfy, cluster, hello_world, logger):
    # - run 2 managers
    # - one of them stops being a manager, and instead is the proxy
    # - the other is the manager, and updates its internal cert and provider
    # context to the proxy ips
    import pudb; pu.db  # NOQA
    proxy = cluster.managers[-1]
    cluster_managers = cluster.managers[:-1]
    _set_proxy(proxy, cluster_managers[0].private_ip_address)

    agent_config = {
        'rest_host': proxy.private_ip_address,
        'broker_ip': proxy.private_ip_address,
    }
    certs = None
    for manager in cluster_managers:
        if certs is None:
            certs = _make_certs(manager, proxy.private_ip_address)
        else:
            _upload_certs(manager, certs)

        with manager.ssh() as fabric:
            fabric.put(StringIO(json.dumps(agent_config)),
                       '/opt/manager/agent_config.json', use_sudo=True)
            fabric.sudo('printf "\\nAGENT_CONFIG_PATH=/opt/manager/agent_config.json\\n" >> /etc/sysconfig/cloudify-mgmtworker')  # NOQA
            fabric.sudo('systemctl restart cloudify-rabbitmq')
            fabric.sudo('systemctl restart nginx')
            fabric.sudo('systemctl restart cloudify-mgmtworker')

            iptables_cmds = IPTABLES_TEMPLATE.format(
                own_ip=manager.private_ip_address,
                proxy_ip=proxy.private_ip_address).splitlines()
            for cmd in iptables_cmds:
                if cmd:
                    fabric.sudo(cmd)

    cfy.cluster.start(timeout=600,
                      cluster_host_ip=cluster_managers[0].private_ip_address)
    cluster_managers[1].use()
    cfy.cluster.join(cluster_managers[0].ip_address,
                     timeout=600,
                     cluster_host_ip=cluster_managers[1].private_ip_address,
                     cluster_node_name=cluster_managers[1].ip_address)
    hello_world.upload_blueprint()
    hello_world.create_deployment()
    hello_world.install()

    cluster.managers[0].delete()
    _set_proxy(proxy, cluster_managers[1].private_ip_address, restart=True)
    time.sleep(30)


def _set_proxy(proxy, ip, restart=False):
    with proxy.ssh() as fabric:
        for port in [5671, 53333]:
            service = 'proxy_{0}'.format(port)
            filename = '/usr/lib/systemd/system/{0}.service'.format(service)
            fabric.put(
                StringIO(PROXY_SERVICE_TEMPLATE.format(ip=ip, port=port)),
                filename, use_sudo=True)
            fabric.sudo('systemctl daemon-reload')
            fabric.sudo('systemctl enable {0}'.format(service))
            fabric.sudo('systemctl start {0}'.format(service))
            if restart:
                fabric.sudo('systemctl restart {0}'.format(service))
