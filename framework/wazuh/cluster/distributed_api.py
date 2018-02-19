#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.cluster.management import send_request, read_config, check_cluster_status, get_node, get_nodes, get_status_json, get_name_from_ip, get_ip_from_name
from wazuh.cluster import api_protocol_messages as api_protocol
from wazuh.exception import WazuhException
from wazuh import common
import threading
from sys import version
import logging
import re
import ast
import json

is_py2 = version[0] == '2'
if is_py2:
    from Queue import Queue as queue
else:
    from queue import Queue as queue


def send_request_to_node(node, config_cluster, request_type, args, result_queue):
    error, response = send_request(host=node, port=config_cluster["port"], key=config_cluster['key'],
                        data="{0} {1}".format(request_type, 'a'*(common.cluster_protocol_plain_size - len(request_type + " "))),
                         file=args.encode())
    if error != 0 or ((isinstance(response, dict) and response.get('error') is not None and response['error'] != 0)):
        logging.debug(response)
        result_queue.put({'node': node, 'reason': "{0} - {1}".format(error, response), 'error': 1})
    else:
        result_queue.put(response)


def append_node_result_by_type(node, result_node, request_type, current_result=None):
    if current_result == None:
        current_result = {}
    if request_type == api_protocol.list_requests_agents['RESTART_AGENTS']:
        if isinstance(result_node.get('data'), dict):
            if result_node.get('data').get('affected_agents') != None:
                if current_result.get('affected_agents') is None:
                    current_result['affected_agents'] = []
                current_result['affected_agents'].extend(result_node['data']['affected_agents'])

            if result_node.get('data').get('failed_ids'):
                if current_result.get('failed_ids') is None:
                    current_result['failed_ids'] = []
                current_result['failed_ids'].extend(result_node['data']['failed_ids'])

            if result_node.get('data').get('failed_ids') != None and result_node.get('data').get('msg') != None:
                current_result['msg'] = result_node['data']['msg']
            if current_result.get('failed_ids') == None and result_node.get('data').get('msg') != None:
                current_result['msg'] = result_node['data']['msg']
            if current_result.get('failed_ids') != None and current_result.get('affected_agents') != None:
                current_result['msg'] = "Some agents were not restarted"
        else:
            if current_result.get('data') == None:
                current_result = result_node

    elif  isinstance(current_result, dict) and \
    (request_type in api_protocol.list_requests_managers.values() or \
     request_type in api_protocol.list_requests_wazuh.values() or \
      request_type in api_protocol.list_requests_stats.values() or \
       request_type == api_protocol.list_requests_cluster['CLUSTER_CONFIG']):
        if current_result.get('items') == None:
            current_result['items'] = []
        if result_node.get('data') != None:
            current_result['items'].append(result_node['data'])
        else:
            current_result['items'].append(result_node)
        index = 0
        if (len(current_result['items']) > 0):
            index = len(current_result['items']) -1

        if (isinstance(current_result['items'][len(current_result['items'])-1], dict)):
            current_result['items'][index]['node_id'] = get_name_from_ip(node)
            current_result['items'][index]['url'] = node
        elif (isinstance(current_result['items'][len(current_result['items'])-1], list)):
            current_result['items'][index].append({
                'node_id':get_name_from_ip(node),
                'url':node})
        if current_result.get('totalItems') == None:
            current_result['totalItems'] = 0
        current_result['totalItems'] += 1
    else:
        if isinstance(result_node, dict):
            if result_node.get('data') != None:
                current_result = result_node['data']
            elif result_node.get('message') != None:
                current_result['message'] = result_node['message']
                current_result['error'] = result_node['error']
        else:
            current_result = result_node
    return current_result


def send_request_to_nodes(config_cluster, header, data, nodes, args):
    threads = []
    result = {}
    result_node = {}
    result_nodes = {}
    result_queue = queue()

    for node in nodes:
        if node is not None:
            logging.info("Sending {2} request from {0} to {1}".format(get_node()['node'], nodes, header))
            t = threading.Thread(target=send_request_to_node, args=(str(node), config_cluster, header, data, result_queue))
            threads.append(t)
            t.start()
            result_node = result_queue.get()
        else:
            result_node['data'] = {}
            result_node['data']['failed_ids'] = []
            for id in remote_nodes[node]:
                node = {}
                node['id'] = id
                node['error'] = {'message':"Agent not found",'code':-1}
                result_node['data']['failed_ids'].append(node)
        result_nodes[node] = result_node
    for t in threads:
        t.join()
    for node, result_node in result_nodes.iteritems():
        result = append_node_result_by_type(node, result_node, header, result)
    return result


def is_a_local_request():
    config_cluster = read_config()
    return not config_cluster or not check_cluster_status() or config_cluster['node_type'] == 'client'


def is_cluster_running():
    return get_status_json()['running'] == 'yes'


def prepare_message(request_type, node_agents={}, args=[]):
    header = api_protocol.protocol_messages['DISTRIBUTED_REQUEST'] + " " + request_type
    data = {} # Data for each node

    # Send to all nodes
    if len(node_agents) == 0:
        nodes = list(map(lambda x: x['url'], get_nodes()['items']))
        node_agents = {node: [] for node in nodes}

    if not request_type is api_protocol.list_requests_cluster['MASTER_FORW']:
        for node in node_agents.keys():
            data[node] = {}
            data[node][api_protocol.protocol_messages['NODEAGENTS']] = node_agents[node]
            data[node][api_protocol.protocol_messages['ARGS']] = args
    else:
        node = get_ip_from_name(get_actual_master()['name'])
        request_redirected = args.pop()
        data[node][api_protocol.protocol_messages['REQUEST_TYPE']] = request_type
        data[node][api_protocol.protocol_messages['NODEAGENTS']] = node_agents
        data[node][api_protocol.protocol_messages['ARGS']] = args

    nodes = node_agents.keys()
    data = json.dumps(data)
    return header, data, nodes


def distributed_api_request(request_type, node_agents={}, args=[], from_cluster=False, instance=None):
    """
    Send distributed request
    'node_agents': Dictionary of node -> list agents. Sample: {'192.168.56.102': ['003', '004'], '192.168.56.103': []}.
    'args': List of arguments.
    'from_cluster': Request comes from the cluster.
    'instance': Instance for local request.
    """

    config_cluster = read_config()
    result, result_local = None, None

    # Not from cluster and not elected mater --> Redirect to master
    '''
    if not from_cluster and get_actual_master()['name'] != config_cluster["node_name"]:
        args.append(request_type)
        request_type = api_protocol.list_requests_cluster['MASTER_FORW']
    '''

    header, data, nodes = prepare_message(request_type=request_type, node_agents=node_agents, args=args)

    # Elected master resolves his own request in local
    '''
    if (instance != None \
        and get_actual_master()['name'] == config_cluster["node_name"] \
        and get_ip_from_name(config_cluster["node_name"]) in node_agent):

        try:
            result_local = {'data':api_request(request_type=request_type, args=node_agents[get_ip_from_name(config_cluster["node_name"])], instance=instance), 'error':0}
        except Exception as e:
            result_local = {'data':str(e), 'error':1}
        del node_agents[get_ip_from_name(config_cluster["node_name"])]
    '''

    if len(node_agents) > 0:
        result = send_request_to_nodes(config_cluster=config_cluster, header=header, data=data, nodes=nodes, args=args)

    # Merge local and distributed results
    '''
    if result_local is not None:
        result = append_node_result_by_type(get_ip_from_name(config_cluster["node_name"]), result_local, request_type, current_result=result, nodes=nodes)
    '''

    return result


def get_config_distributed(node_id=None, cluster_depth=1):
    if is_a_local_request() or cluster_depth <= 0:
        return read_config_json()
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = api_protocol.list_requests_cluster['CLUSTER_CONFIG']
        return distributed_api_request(request_type=request_type, cluster_depth=cluster_depth, affected_nodes=node_id)


def api_request(request_type, args, cluster_depth, instance=None):
    res = ""

    if request_type == api_protocol.list_requests_agents['RESTART_AGENTS']:
        if (len(args) == 2):
            agents = args[0].split("-")
            restart_all = ast.literal_eval(args[1])
        else:
            agents = None
            restart_all = ast.literal_eval(args[0])
        res = instance.restart_agents(agents, restart_all, cluster_depth)

    elif request_type == api_protocol.list_requests_agents['AGENTS_UPGRADE_RESULT']:
        try:
            agent = args[0]
            timeout = args[1]
            res = instance.get_upgrade_result(agent, timeout)
        except Exception as e:
            res = str(e)

    elif request_type == api_protocol.list_requests_agents['AGENTS_UPGRADE']:
        agent_id = args[0]
        wpk_repo = ast.literal_eval(args[1])
        version = ast.literal_eval(args[2])
        force = ast.literal_eval(args[3])
        chunk_size = ast.literal_eval(args[4])
        try:
            res = instance.upgrade_agent(agent_id, wpk_repo, version, force, chunk_size)
        except Exception as e:
            res = str(e)

    elif request_type == api_protocol.list_requests_agents['AGENTS_UPGRADE_CUSTOM']:
        agent_id = args[0]
        file_path = ast.literal_eval(args[1])
        installer = ast.literal_eval(args[2])
        try:
            res = instance.upgrade_agent_custom(agent_id, file_path, installer)
        except Exception as e:
            res = str(e)

    elif request_type == api_protocol.list_requests_syscheck['SYSCHECK_LAST_SCAN']:
        res = instance.last_scan(args[0])

    elif request_type == api_protocol.list_requests_syscheck['SYSCHECK_RUN']:
        if (len(args) == 2):
            agents = args[0]
            all_agents = ast.literal_eval(args[1])
        else:
            agents = None
            all_agents = ast.literal_eval(args[0])
        res = instance.run(agents, all_agents, cluster_depth)

    elif request_type == api_protocol.list_requests_syscheck['SYSCHECK_CLEAR']:
        if (len(args) == 2):
            agents = args[0]
            all_agents = ast.literal_eval(args[1])
        else:
            agents = None
            all_agents = ast.literal_eval(args[0])
        res = instance.clear(agents, all_agents, cluster_depth)

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_PCI']:
        index = 0
        agents = None
        if (len(args) == 5):
            agents = args[0]
            index = index + 1
        offset = ast.literal_eval(args[index])
        index = index + 1
        limit = ast.literal_eval(args[index])
        index = index + 1
        sort = ast.literal_eval(args[index])
        index = index + 1
        search = ast.literal_eval(args[index])
        res = args
        res = instance.get_pci(agents, offset, limit, sort, search)

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_CIS']:
        index = 0
        agents = None
        if (len(args) == 5):
            agents = args[0]
            index = index + 1
        offset = ast.literal_eval(args[index])
        index = index + 1
        limit = ast.literal_eval(args[index])
        index = index + 1
        sort = ast.literal_eval(args[index])
        index = index + 1
        search = ast.literal_eval(args[index])
        res = args
        res = instance.get_cis(agents, offset, limit, sort, search)

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_LAST_SCAN']:
        res = instance.last_scan(args[0])

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_RUN']:
        if (len(args) == 2):
            agents = args[0]
            all_agents = ast.literal_eval(args[1])
        else:
            agents = None
            all_agents = ast.literal_eval(args[0])
        res = instance.run(agents, all_agents, cluster_depth)

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_CLEAR']:
        if (len(args) == 2):
            agents = args[0]
            all_agents = ast.literal_eval(args[1])
        else:
            agents = None
            all_agents = ast.literal_eval(args[0])
        res = instance.clear(agents, all_agents, cluster_depth)

    elif request_type == api_protocol.list_requests_managers['MANAGERS_STATUS']:
        res = instance.managers_status(cluster_depth=cluster_depth)

    elif request_type == api_protocol.list_requests_managers['MANAGERS_LOGS']:
        type_log = args[0]
        category = args[1]
        months = ast.literal_eval(args[2])
        offset = ast.literal_eval(args[3])
        limit = ast.literal_eval( args[4])
        sort = ast.literal_eval(args[5])
        search = ast.literal_eval(args[6])
        res = instance.managers_ossec_log(type_log=type_log, category=category, months=months, offset=offset, limit=limit, sort=sort, search=search, cluster_depth=cluster_depth)

    elif request_type == api_protocol.list_requests_managers['MANAGERS_LOGS_SUMMARY']:
        months = ast.literal_eval(args[0])
        res = instance.managers_ossec_log_summary(months=months, cluster_depth=cluster_depth)

    elif request_type == api_protocol.list_requests_stats['MANAGERS_STATS_TOTALS']:
        year = ast.literal_eval(args[0])
        month = ast.literal_eval(args[1])
        day = ast.literal_eval(args[2])
        res = instance.totals(year=year, month=month, day=day, cluster_depth=cluster_depth)

    elif request_type == api_protocol.list_requests_stats['MANAGERS_STATS_HOURLY']:
        res = instance.hourly(cluster_depth=cluster_depth)

    elif request_type == api_protocol.list_requests_stats['MANAGERS_STATS_WEEKLY']:
        res = instance.weekly(cluster_depth=cluster_depth)

    elif request_type == api_protocol.list_requests_managers['MANAGERS_OSSEC_CONF']:
        section = args[0]
        field = ast.literal_eval(args[1])
        res = instance.managers_get_ossec_conf(section=section, field=field, cluster_depth=cluster_depth)

    elif request_type == api_protocol.list_requests_wazuh['MANAGERS_INFO']:
        res = instance.managers_get_ossec_init(cluster_depth=cluster_depth)

    elif request_type == api_protocol.list_requests_cluster['CLUSTER_CONFIG']:
        res = get_config_distributed(cluster_depth=cluster_depth)
    return res
