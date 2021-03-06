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

import os
from threading import Thread
import time
from datetime import datetime
import csv

from cosmo_tester.framework.fixtures import image_based_manager
from cloudify_rest_client.client import CloudifyClient
from cloudify_rest_client.exceptions import CloudifyClientError
from requests import ConnectionError
from paramiko import SSHException
from random import randint

manager = image_based_manager

BLUEPRINT_NAME = 'scale'
BLUEPRINT_FILE_NAME = 'blueprint.yaml'
TENANT = 'default_tenant'
BLUEPRINT_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(
            __file__), '..', '..', 'resources/blueprints/scale/load-bp.zip'))

try:
    concurrent_create_deployments = int(
        os.environ['CONCURRENT_CREATE_DEPLOYMENTS'])
    num_of_deployments = int(os.environ['NUM_OF_DEPLOYMENTS'])
    concurrent_workflows = int(os.environ['CONCURRENT_WORKFLOWS'])
    url = os.environ['URL']
    cycle_num = int(os.environ['CYCLE_NUM'])
    cycle_sleep = int(os.environ['CYCLE_SLEEP'])
    manager_server_flavor_name = os.environ['MANAGER_SERVER_FLAVOR_NAME']
except (KeyError, ValueError):
    envvars_provided = False
else:
    envvars_provided = True
    STAT_FILE_PATH = '/tmp/scale/{0}_manager_stats_{1}.csv'.format(
        manager_server_flavor_name,
        datetime.now().strftime("%Y%m%d-%H%M%S"))

WORKFLOWS = ['geturl_wf', 'gentar_wf', 'factorial_wf']


def test_concurrent_workflows(cfy, manager, logger):
    if not envvars_provided:
        raise RuntimeError('Not all required envvars have been provided')
    _set_max_workers_num(manager)
    exec_params = {'url': url,
                   'cycle_num': cycle_num,
                   'cycle_sleep': cycle_sleep}

    if not os.path.exists(os.path.dirname(STAT_FILE_PATH)):
        os.makedirs(os.path.dirname(STAT_FILE_PATH))

    logger.info('Test parameters:')
    logger.info('******************')
    logger.info('Total number of deployments: {0}'.
                format(num_of_deployments))
    logger.info('Create concurrent deployments number: {0}'.
                format(concurrent_create_deployments))
    logger.info('Number of concurrent workflows: {0}'.
                format(concurrent_workflows))
    logger.info('Number of cycles in each deployment: {0}'.
                format(cycle_num))
    logger.info('Sleep milisec in each deployment: {0}'.
                format(cycle_sleep))
    logger.info('******************')
    logger.info('Preparing test environment...')

    client = CloudifyClient(username='admin',
                            password='admin',
                            host=manager.ip_address,
                            tenant='default_tenant')

    deployments = _prepare_test_env(cfy, manager, client, logger)

    logger.info('Preparing test environment is completed.')
    time.sleep(5)

    stat_thread = Thread(target=statistics, args=(manager,
                                                  client,
                                                  logger, ))
    stat_thread.daemon = True
    stat_thread.start()

    logger.info('Running concurrent executions '
                'and monitoring manager resources...')

    workflow_count = 0
    for i in range(len(deployments)):
        threads = []
        if workflow_count + concurrent_workflows < len(deployments):
            for j in range(concurrent_workflows):
                workflow = _get_workflow()
                t = Thread(target=execution,
                           args=(client,
                                 deployments[workflow_count],
                                 workflow,
                                 exec_params,
                                 logger,))
                threads.append(t)
                workflow_count += 1
                logger.info('Running {0} workflow'.format(workflow))
            for t in threads:
                t.start()
            for t in threads:
                t.join()

    time.sleep(cycle_num * cycle_sleep / 1000)

    logger.info('Terminated workflows: {0}'.
                format(len([e for e in
                            client.executions.list(
                                _get_all_results=True,
                                status='terminated')])))
    logger.info('Failed workflows: {0}'.
                format(len([e for e in
                            client.executions.list(
                                _get_all_results=True,
                                status='failed')])))
    logger.info('Pending workflows: {0}'.
                format(len([e for e in
                            client.executions.list(
                                _get_all_results=True,
                                status='pending')])))


def statistics(manager, client, logger):
    """thread worker function"""
    top_cpu_command = "top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'"
    memory_used_command = "free | grep Mem | awk '{print $3/$2 * 100.0}'"
    load_averages_command = "cat /proc/loadavg | awk '{print $1}'"

    with open(STAT_FILE_PATH, 'w') as csvfile:
        fieldnames = ['time',
                      'executions_num',
                      'top_cpu_%',
                      'load_averages',
                      'used_memory_%']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        while True:
            executions_num = top_cpu = \
                load_averages = memory_used_perc = None
            try:
                executions_num = _get_running_executions_num(client)
            except ConnectionError:
                pass
            except CloudifyClientError:
                _check_nginx_status(logger)

            current_time = datetime.now().strftime('%H:%M:%S')
            with manager.ssh() as fabric:
                try:
                    top_cpu = fabric.run(top_cpu_command)
                    load_averages = fabric.run(load_averages_command)
                    memory_used_perc = fabric.run(memory_used_command)
                except EOFError or SSHException:
                    pass

            writer.writerow({'time': current_time,
                             'executions_num': executions_num,
                             'top_cpu_%': top_cpu,
                             'load_averages': load_averages,
                             'used_memory_%': memory_used_perc, })
            time.sleep(1)
    return


def deployment(client, deployment_id, logger):
    """thread worker function"""
    client.deployments.create(BLUEPRINT_NAME,
                              deployment_id)
    logger.info('Deployment {0} is created.'.format(deployment_id))
    return


def execution(client, deployment_id, workflow, exec_params, logger):
    """thread worker function"""
    try:
        client.executions.start(deployment_id, workflow,
                                parameters=exec_params)
    except CloudifyClientError:
        _check_nginx_status(logger)
        logger.info(
            'Failed to run workflow {0} for deployment {1}'.
            format(workflow, deployment_id))
    return


def _prepare_test_env(cfy, manager, client, logger):
    cfy.blueprints.upload(
        '-b', BLUEPRINT_NAME,
        '-n', BLUEPRINT_FILE_NAME,
        BLUEPRINT_PATH,
        '-t', TENANT)

    dep_count = 0
    deployments = []
    for i in range(num_of_deployments / concurrent_create_deployments):
        threads = []
        for j in range(concurrent_create_deployments):
            dep_count += 1
            deployment_id = BLUEPRINT_NAME + '_deployment_' + str(dep_count)
            t = Thread(target=deployment, args=(client, deployment_id, logger))
            threads.append(t)
            deployments.append(deployment_id)
        for t in threads:
            t.start()

        manager.wait_for_all_executions()

    return deployments


def _get_workflow():
    return WORKFLOWS[randint(0, 2)]


def _set_max_workers_num(manager):
    with manager.ssh() as fabric:
        fabric.run('sudo sed -i -e \''
                   's/MAX_WORKERS="100"/MAX_WORKERS="1000"/\' '
                   '/etc/sysconfig/cloudify-mgmtworker')
        fabric.run('sudo systemctl restart cloudify-mgmtworker')


def _get_running_executions_num(client):
    return len([execution for execution in
                client.executions.list(
                    _get_all_results=True,
                    status='started')])


def _check_nginx_status(logger):
    with manager.ssh() as fabric:
        try:
            logger.info('Nginx status: {0}'.format(
                fabric.run(
                    'sudo systemctl status nginx.service')))
            logger.info('Rest service status: {0}'.format(
                fabric.run(
                    'sudo systemctl status '
                    'cloudify-restservice.service')))
        except SSHException:
            pass
