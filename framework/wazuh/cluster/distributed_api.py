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
import logging

is_py2 = version[0] == '2'
if is_py2:
    from Queue import Queue as queue
else:
    from queue import Queue as queue


def append_node_result_by_type(node, result_node, request_type, current_result=None):
    request_type = request_type.split(' ')
    if request_type > 1 and request_type[0] == api_protocol.list_requests_cluster['DISTRIBUTED_REQUEST']:
        request_type = request_type[1]
    if current_result is None:
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

            if not result_node.get('data').get('failed_ids') is None and not result_node.get('data').get('msg') is None:
                current_result['msg'] = result_node['data']['msg']
            if current_result.get('failed_ids') is None and not result_node.get('data').get('msg') is None:
                current_result['msg'] = result_node['data']['msg']
            if not current_result.get('failed_ids') is None and not current_result.get('affected_agents') is None:
                current_result['msg'] = "Some agents were not restarted"
        else:
            if current_result.get('data') is None:
                current_result = result_node

    elif  isinstance(current_result, dict) and \
    (request_type in api_protocol.list_requests_managers.values() or \
      request_type in api_protocol.list_requests_stats.values() or \
       request_type == api_protocol.list_requests_cluster['CLUSTER_CONFIG']):
        if current_result.get('items') is None:
            current_result['items'] = []
        if not result_node.get('data') is None:
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
        if current_result.get('totalItems') is None:
            current_result['totalItems'] = 0
        current_result['totalItems'] += 1
    else:
        if isinstance(result_node, dict):
            if not result_node.get('data') is None:
                current_result = result_node['data']
            elif not result_node.get('message') is None:
                current_result['message'] = result_node['message']
                current_result['error'] = result_node['error']
        else:
            current_result = result_node
    return current_result


def send_request_to_node(host, config_cluster, header, data, result_queue):
    header = "{0} {1}".format(header, 'a'*(common.cluster_protocol_plain_size - len(header + " ")))
    error, response = send_request(host=host, port=config_cluster["port"], key=config_cluster['key'],
                        data=header, file=data.encode())
    if error != 0 or ((isinstance(response, dict) and response.get('error') is not None and response['error'] != 0)):
        logging.debug(response)
        result_queue.put({'node': host, 'reason': "{0} - {1}".format(error, response), 'error': 1})
    else:
        result_queue.put(response)


def send_request_to_nodes(config_cluster, header, data, nodes, args):
    threads = []
    result = {}
    result_node = {}
    result_nodes = {}
    result_queue = queue()

    for node in nodes:
        if node is not None:
            logging.info("Sending {0} request from {1} to {2} (Message: '{3}')".format(header, get_node()['node'], node, str(data[node])))
            t = threading.Thread(target=send_request_to_node, args=(str(node), config_cluster, header, json.dumps(data[node]), result_queue))
            threads.append(t)
            t.start()
            result_node = result_queue.get()
        else:
            result_node['data'] = {}
            result_node['data']['failed_ids'] = []
            for id in data[node][api_protocol.protocol_messages['NODEAGENTS']]:
                res= {}
                res['id'] = id
                res['error'] = {'message':"Agent does not exist",'code':1701}
                result_node['data']['failed_ids'].append(res)
        result_nodes[node] = result_node
    for t in threads:
        t.join()
    for node, result_node in result_nodes.iteritems():
        result = append_node_result_by_type(node=node, result_node=result_node, request_type=header, current_result=result)
    return result


def is_a_local_request():
    return not read_config() or not check_cluster_status() or read_config()['node_type'] == 'client'


def is_cluster_running():
    return get_status_json()['running'] == 'yes'


def prepare_message(request_type, node_agents={}, args=[]):
    """
    Prepare a message to be send.
    :param request_type: Type of request. It have to be one of 'api_protocol_messages.all_list_requests'.
    :param node_agents: Dictionary of nodes -> list of agents. Sample:
        - Agent 003 and 004 in node 192.168.56.102: node_agents={'192.168.56.102': ['003', '004']},
        - Node 192.168.56.103 or all agents in node 192.168.56.103: {'192.168.56.103': []}.
        - All nodes: {}.
    :param args: List of arguments.
    :return:
        - header: Header of message to be send. It's a String.
        - data: Body of message to be send. It's a dictinionary with NODEAGENTS, ARGS and REQUEST_TYPE.
        - nodes: List of destinatary nodes of the message.
    """
    header = api_protocol.all_list_requests['DISTRIBUTED_REQUEST'] + " " + request_type
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
    return header, data, nodes


def get_dict_nodes(nodes):
    """
    Get a dictionary of affected nodes.
    :param agent_id: Node name or id or list of nodes.
    :return: Dictionary of nodes
        - Node 192.168.56.103: {'192.168.56.103': []}.
        - All nodes: {}.
    """
    node_agents = {}
    if nodes:
        if not isinstance(nodes, list):
            nodes = [nodes]
        for node in nodes:
            # Is name or addr?
            if not re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").match(node):
                addr = get_ip_from_name(node)
                if addr != None:
                    node_agents[addr] = []
            else:
                node_agents[node] = []
    return node_agents


def distributed_api_request(request_type, node_agents={}, args=[], from_cluster=False, instance=None):
    """
    Send distributed request using the cluster.
    :param request_type: Type of request. It have to be one of 'api_protocol_messages.all_list_requests'.
    :param node_agents: Dictionary of nodes -> list of agents. Sample:
        - Agent 003 and 004 in node 192.168.56.102: node_agents={'192.168.56.102': ['003', '004']},
        - Node 192.168.56.103 or all agents in node 192.168.56.103: {'192.168.56.103': []}.
        - All nodes: {}.
    :param args: List of arguments.
    :param from_cluster: Request comes from the cluster. If request is from cluster, it not be redirected.
    :param instance: Instance for resolve local request.
    :return: Output of API distributed call in JSON.
    """
    logging.warning("distributed_api_request: Received request_type='" + str(request_type) + "' node_agents='" + str(node_agents) + "' args='" + str(args) + "' from_cluster='" + str(from_cluster)) #TODO: Remove this line.
    config_cluster = read_config()
    result, result_local = None, None

    # Not from cluster and not elected mater --> Redirect to master
    '''
    if not from_cluster and get_actual_master()['name'] != config_cluster["node_name"]:
        args.append(request_type)
        request_type = api_protocol.list_requests_cluster['MASTER_FORW']
    '''

    header, data, nodes = prepare_message(request_type=request_type, node_agents=node_agents, args=args)
    logging.warning("distributed_api_request: got message header='" + str(header) + "' data='" + str(data) + "' nodes='" + str(nodes)) #TODO: Remove this line.


    # Elected master resolves his own request in local
    '''
    if (instance != None \
        and get_actual_master()['name'] == config_cluster["node_name"] \
        and get_ip_from_name(config_cluster["node_name"]) in node_agent):

        try:
            result_local = {'data':api_request(request_type=request_type, args=node_agents[get_ip_from_name(config_cluster["node_name"])], instance=instance), 'error':0}
        except Exception as e:
            result_local = {'data':str(e), 'error':1}
        del data[get_ip_from_name(config_cluster["node_name"])]
    '''

    if len(data) > 0:
        logging.warning("distributed_api_request: Sending request") #TODO: Remove this line.
        result = send_request_to_nodes(config_cluster=config_cluster, header=header, data=data, nodes=nodes, args=args)
        logging.warning("distributed_api_request: result=" + str(result)) #TODO: Remove this line.

    # Merge local and distributed results
    '''
    if result_local is not None:
        result = append_node_result_by_type(get_ip_from_name(config_cluster["node_name"]), result_local, request_type, current_result=result, nodes=nodes)
    '''

    return result


def get_config_distributed(node_id=None, from_cluster=False):
    if is_a_local_request() or from_cluster:
        return read_config_json()
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = api_protocol.list_requests_cluster['CLUSTER_CONFIG']
        return distributed_api_request(request_type=request_type, node_agents=get_dict_nodes(node_id))


def execute_request(request_type, args=[], agents={}, instance=None):
    result = ""

    logging.warning("Data received --> request_type --> {}  ---  args --> {}  ---  agents --> {}".format(str(request_type), str(args), str(agents))) #TODO: Remove this line.

    if request_type == api_protocol.list_requests_agents['RESTART_AGENTS']:
        result = instance.restart_agents(agent_id=agents, restart_all=args[0])

    elif request_type == api_protocol.list_requests_managers['MANAGERS_INFO']:
        result = instance.request_get_ossec_init(from_cluster=True)

    elif request_type == api_protocol.list_requests_managers['MANAGERS_STATUS']:
        result = instance.request_status(from_cluster=True)

    '''
    elif request_type == api_protocol.list_requests_managers['MANAGERS_OSSEC_CONF']:
        result = instance.request_get_ossec_conf(section=args[0], field=args[1], from_cluster=True)

    elif request_type == api_protocol.list_requests_managers['MANAGERS_LOGS']:
        result = instance.request_ossec_log(type_log=args[0], category=args[1], months=args[2], \
              offset=args[3], limit=args[4], sort=args[5], search=args[6], cluster_depth=args[7])

    elif request_type == api_protocol.list_requests_managers['MANAGERS_LOGS_SUMMARY']:
        result = instance.managers_ossec_log_summary(months=args[0])

    elif request_type == api_protocol.list_requests_stats['MANAGERS_STATS_TOTALS']:
        result = instance.totals(year=args[0], month=args[1], day=args[2])

    elif request_type == api_protocol.list_requests_stats['MANAGERS_STATS_HOURLY']:
        result = instance.hourly()

    elif request_type == api_protocol.list_requests_stats['MANAGERS_STATS_WEEKLY']:
        result = instance.weekly()

    elif request_type == api_protocol.list_requests_agents['AGENTS_UPGRADE_RESULT']:
        result = instance.get_upgrade_result(agent=agents, timeout=args[0])

    elif request_type == api_protocol.list_requests_agents['AGENTS_UPGRADE']:
        result = instance.upgrade_agent(agent_id=agents, wpk_repo=args[0], \
             version=args[1], force=args[2], chunk_size=args[3])

    elif request_type == api_protocol.list_requests_agents['AGENTS_UPGRADE_CUSTOM']:
        result = instance.upgrade_agent_custom(agent_id=agents, file_path=args[0], installer=args[1])

    elif request_type == api_protocol.list_requests_syscheck['SYSCHECK_LAST_SCAN']:
        result = instance.last_scan(args[0])

    elif request_type == api_protocol.list_requests_syscheck['SYSCHECK_RUN']:
        result = instance.run(agents=agents, all_agents=args[0])

    elif request_type == api_protocol.list_requests_syscheck['SYSCHECK_CLEAR']:
        result = instance.clear(agents=agents, all_agents=args[0])

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_PCI']:
        result = instance.get_pci(agents=agents, offset=args[0], limit=args[1], sort=args[2], search=args[3])

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_CIS']:
        result = instance.get_cis(agents=agents, offset=args[0], limit=args[1], sort=args[2], search=args[3])

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_LAST_SCAN']:
        result = instance.last_scan(args[0])

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_RUN']:
        result = instance.run(agents=agents, all_agents=args[0])

    elif request_type == api_protocol.list_requests_rootcheck['ROOTCHECK_CLEAR']:
        result = instance.clear(agents=agents, all_agents=args[0])
    '''
    '''
    elif request_type == api_protocol.list_requests_cluster['CLUSTER_CONFIG']:
        result = get_config_distributed()

    '''
    return result
