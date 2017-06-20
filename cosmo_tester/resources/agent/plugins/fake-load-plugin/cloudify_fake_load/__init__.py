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

import json
from socket import socket

from cloudify.decorators import operation
from cloudify import ctx


@operation
def start():
    ""
    send_message(
        'start',
        ctx.instance,
        )


@operation
def stop():
    ""
    send_message(
        'stop',
        ctx.instance,
        )


def send_message(action, instance):
    r_props = ctx.instance.runtime_properties
    host = r_props['host']
    port = r_props['port']

    tenant_info = ctx._context['tenant']
    connection_info = {
        'user': tenant_info['broker_username'],
        'password': tenant_info['broker_password'],
        'vhost': tenant_info['rabbitmq_vhost'],
        'host': ctx.bootstrap_context.broker_config['broker_ip'],
        }

    sock = socket((host, port))

    try:
        sock.sendall(json.dumps({
            'action': action,
            'instance': instance,
            'connection_info': connection_info,
            }))
    finally:
        sock.close()