#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.cluster.management import send_request, read_config, check_cluster_status, get_node, get_nodes, get_status_json, get_name_from_ip, get_ip_from_name
from wazuh.cluster import api_protocol_messages as api_protocol
from wazuh.exception import WazuhException
from wazuh import common
import threading
from sys import version
import re
import ast
import json
from datetime import datetime
from operator import itemgetter
from itertools import islice
import multiprocessing as mp

import logging
import time

is_py2 = version[0] == '2'
if is_py2:
    from Queue import Queue as queue
else:
    from queue import Queue as queue


def merge_results(node, result_node, request_type, final_result=None):

    # Empty result_node --> Discard result
    if result_node.get("data") is None or result_node["data"].get("items") is None:
        if final_result.get("data") is None:
            final_result["data"] = {}
            final_result["data"]["items"] = {}
            final_result["data"]["totalItems"] = 0
        return final_result

    start_2 = time.time()

    # Empty final_result --> Initialize
    if final_result.get("data") is None:
        final_result["data"] = {}
        final_result["data"]["items"] = {}
        final_result["data"]["totalItems"] = 0

        for remote_agent in result_node["data"]["items"]:
            final_result["data"]["items"][remote_agent['id']] = remote_agent

        final_result["data"]["totalItems"] = result_node["data"]["totalItems"]
        final_result["data"][node] = result_node["data"]["Total_manager"]
        final_result["data"]["{}-totalItems".format(str(node))] = result_node["data"]["totalItems"]

        end_2 = time.time()
        elapsed_time_2 = end_2 - start_2

        final_result["Merging"]["{}".format(str(node))] = {}
        final_result["Merging"]["{}".format(str(node))]["Agents received"] = len(result_node["data"]["items"])
        final_result["Merging"]["{}".format(str(node))]["Time"] = elapsed_time_2
        return final_result

    else:
        # Add totalItems to final_result
        final_result["data"]["totalItems"] = final_result["data"]["totalItems"] + result_node["data"]["totalItems"]
        final_result["data"][node] = result_node["data"]["Total_manager"]
        final_result["data"]["{}-totalItems".format(str(node))] = result_node["data"]["totalItems"]

    for remote_agent in result_node["data"]["items"]:
        if remote_agent['id'] in final_result["data"]["items"]:
            # Agent in result_node haven't last keep alive --> Continue
            if remote_agent.get('lastKeepAlive') is None:
                continue
            elif final_result["data"]["items"][remote_agent['id']].get('lastKeepAlive') is None:
                # Agent in final_result haven't last keep alive --> Selecting remote agent
                final_result["data"]["items"][remote_agent['id']]= remote_agent
            else:
                # To compare the lastkeepalive of both agents
                last_keep_alive_time_result = datetime.strptime(final_result["data"]["items"][remote_agent['id']].get('lastKeepAlive'), '%Y-%m-%d %H:%M:%S')
                last_keep_alive_time_node = datetime.strptime(remote_agent['lastKeepAlive'], '%Y-%m-%d %H:%M:%S')
                if last_keep_alive_time_result > last_keep_alive_time_node:
                    final_result["data"]["items"][remote_agent['id']]= remote_agent

        else:
            final_result["data"]["items"][remote_agent['id']] = remote_agent

    end_2 = time.time()
    elapsed_time_2 = end_2 - start_2

    final_result["Merging"]["{}".format(str(node))] = {}
    final_result["Merging"]["{}".format(str(node))]["Time"] = elapsed_time_2
    final_result["Merging"]["{}".format(str(node))]["Agents received"] = len(result_node["data"]["items"])

    return final_result


def send_request_to_node(host, config_cluster, header, data, result_queue):
    header = "{0} {1}".format(header, 'a'*(common.cluster_protocol_plain_size - len(header + " ")))
    error, response = send_request(host=host, port=config_cluster["port"], key=config_cluster['key'],
                        data=header, file=data.encode())
    if error != 0 or ((isinstance(response, dict) and response.get('error') is not None and response['error'] != 0)):
        result_queue.put({'node': host, 'reason': "{0} - {1}".format(error, response), 'error': 1})
    else:
        result_queue.put(response)


def send_request_to_nodes(config_cluster, header, data, nodes):
    process = []
    result = {}
    result_node = {}
    result_nodes = {}
    result = {}


    start_2 = time.time()
    for node in nodes:
        logging.warning("Sending {0} request from {1} to {2} (Message: '{3}')".format(header, get_node()['node'], node, str(data[node])))

        result_queue = mp.Queue()
        p = mp.Process(target=send_request_to_node, args=(str(node), config_cluster, header, json.dumps(data[node]), result_queue))
        p.start()
        process.append(p)

        result_nodes[node] = result_queue.get()

    for p in process:
        p.join()

    end_2 = time.time()
    elapsed_time_2 = end_2 - start_2
    result["Receiving elapsed-time"] = elapsed_time_2

    result["Merging"] = {}
    start_2 = time.time()
    for node, result_node in result_nodes.iteritems():
        #logging.warning("{} ---- {}".format(node, result_node))
        result = merge_results(node=node, result_node=result_node, request_type=header, final_result=result)
    end_2 = time.time()
    elapsed_time_2 = end_2 - start_2
    result["Merging"]["Total time"] = elapsed_time_2
    result["Merging"]["Final agents"] = len(result["data"]["items"])
    del result["data"]

    return result


def is_a_local_request():
    return not read_config() or not check_cluster_status() or read_config()['node_type'] == 'client'


def is_cluster_running():
    return get_status_json()['running'] == 'yes'


def prepare_message(request_type, node_agents={}, args={}):
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
    header = api_protocol.protocol_messages['DISTRIBUTED_REQUEST'] + " " + request_type
    data = {} # Data for each node

    # Send to all nodes
    if len(node_agents) == 0:
        nodes = list(map(lambda x: x['url'], get_nodes()['items']))
        node_agents = {node: [] for node in nodes}

    if not request_type is api_protocol.protocol_messages['MASTER_FORW']:
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
    Get a dictionary of all nodes.
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


def apply_pagination_and_sort(result, offset=0, limit=common.database_limit, sort=None):
    if result.get("data") and result["data"].get("items") and isinstance(result["data"]["items"], list):
        if limit is not None and offset is not None:
            result["data"]["items"] = list(result["data"]["items"][offset:limit])

        if sort and sort['fields']:
            result["data"]["items"] = sorted(result["data"]["items"], key=itemgetter(sort['fields'][0]), reverse=True if sort['order'] == "desc" else False)

    return result


def distributed_api_request(request_type, node_agents={}, args={}, from_cluster=False):
    """
    Send distributed request using the cluster.
    :param request_type: Type of request. It have to be one of 'api_protocol_messages.all_list_requests'.
    :param node_agents: Dictionary of nodes -> list of agents. Sample:
        - Agent 003 and 004 in node 192.168.56.102: node_agents={'192.168.56.102': ['003', '004']},
        - Node 192.168.56.103 or all agents in node 192.168.56.103: {'192.168.56.103': []}.
        - All nodes: {}.
    :param args: List of arguments.
    :param from_cluster: Request comes from the cluster. If request is from cluster, it not be redirected.
    :return: Output of API distributed call in JSON.
    """
    start = time.time()
    config_cluster = read_config()
    result, result_local = None, None

    limit = common.database_limit
    offset = 0
    sort = None
    if args.get('limit'):
        limit = int(args['limit'])
        del args['limit']
    if args.get('offset'):
        offset = int(args['offset'])
        del args['offset']
    if args.get('sort'):
        sort = args['sort']
        del args['sort']

    args['limit'] = None

    header, data, nodes = prepare_message(request_type=request_type, node_agents=node_agents, args=args)

    if len(data) > 0:
        result = apply_pagination_and_sort(
            send_request_to_nodes(config_cluster=config_cluster, header=header, data=data, nodes=nodes),
            limit=limit, offset=offset, sort=sort);

    end = time.time()
    elapsed_time = end - start
    result["Total elapsed-time"] = elapsed_time

    result["Managers limit"] = args['limit']

    return result


def get_config_distributed(node_id=None, from_cluster=False):
    if is_a_local_request() or from_cluster:
        return read_config_json()
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = api_protocol.list_requests_cluster['CLUSTER_CONFIG']
        return distributed_api_request(request_type=request_type, node_agents=get_dict_nodes(node_id))


def get_node_agent(agent_id):
    data = None
    try:
        node_name = Agent(agent_id).get_basic_information()['node_name']
        data = get_ip_from_name(node_name)
    except Exception as e:
        data = None
    return data


def received_request(kwargs, request_function, request_type, from_cluster=False):
    node_agents = {}
    if kwargs.get('agent_id'):
        node_agents = get_agents_by_node(kwargs['agent_id'])

    if not request_type in api_protocol.all_list_requests.keys() or \
            is_a_local_request() or from_cluster:
        return request_function(**kwargs)
    else:
        if not is_cluster_running():
            logging.warning("Cluster is available but is not running properly")
            if not kwargs.get('node_id'): # It will be resolved in local
                return request_function(**kwargs)
            else: # It must be distributed
                raise WazuhException(3016)

        if kwargs.get('node_id'):
            node_agents = get_dict_nodes(kwargs['node_id'])
            del kwargs['node_id']

        return distributed_api_request(request_type=request_type, node_agents=node_agents, args=kwargs)
