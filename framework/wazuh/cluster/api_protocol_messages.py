#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from itertools import chain
from operator import itemgetter
import wazuh.manager as manager
import wazuh.stats as stats
import wazuh.syscheck as syscheck
import wazuh.rootcheck as rootcheck
import wazuh.configuration as configuration
from wazuh.agent import Agent
from wazuh import Wazuh

wazuh = Wazuh()

protocol_messages = {
    'DISTRIBUTED_REQUEST'   : 'distributed',
    'ARGS'                  : 'args',
    'NODEAGENTS'            : 'nodeagents',
    'REQUEST_TYPE'          : 'request_type',
    'MASTER_FORW'           : 'master_forward',
    'zip'                   : 'zip',
    'node'                  : 'node',
    'ready'                 : 'ready',
    'data'                  : 'data'
}

# API Messages
list_requests_agents = {
    'PUT/agents/restart'                   : Agent.restart_agents,
    '/agents'                             : Agent.get_agents_overview,
    'PUT/agents/:agent_id/restart'         : Agent.restart_agents,
    '/agents/:agent_id/upgrade_result'     : Agent.get_upgrade_result,
    'PUT/agents/:agent_id/upgrade'         : Agent.upgrade_agent,
    'PUT/agents/:agent_id/upgrade_custom'  : Agent.upgrade_agent_custom
}

list_requests_syscheck = {
    '/syscheck/:agent_id/last_scan'     : syscheck.last_scan,
    'PUT/syscheck'                      : syscheck.run,
    'DELETE/syscheck'                   : syscheck.clear
}

list_requests_rootcheck = {
    '/rootcheck/:agent_id/last_scan'   : rootcheck.last_scan,
    '/rootcheck/:agent_id/pci'         : rootcheck.get_pci,
    '/rootcheck/:agent_id/cis'         : rootcheck.get_cis,
    'PUT/rootcheck'                    : rootcheck.run,
    'DELETE/rootcheck'                 : rootcheck.clear
}

list_requests_managers = {
    '/manager/info'                   : wazuh.get_ossec_init,
    '/manager/status'                 : manager.status,
    '/manager/configuration'          : manager.get_ossec_conf,
    '/manager/logs/summary'           : manager.ossec_log_summary,
    '/manager/logs'                   : manager.ossec_log,
    '/manager/info/:node_id'          : wazuh.get_ossec_init,
    '/manager/status/:node_id'        : manager.status,
    '/manager/configuration/:node_id' : configuration.get_ossec_conf,
    '/manager/logs/summary/:node_id'  : manager.ossec_log_summary,
    '/manager/logs/:node_id'          : manager.ossec_log
}

list_requests_stats = {
    '/manager/stats'                  : stats.totals,
    '/manager/stats/weekly'           : stats.weekly,
    '/manager/stats/hourly'           : stats.hourly,
    '/manager/stats/:node_id'         : stats.totals,
    '/manager/stats/hourly/:node_id'  : stats.hourly,
    '/manager/stats/weekly/:node_id'  : stats.weekly
}

list_requests_cluster = {
    #'CLUSTER_CONFIG'        : cluster.get_nodes
}

# All dicts that start with "list_requests"
all_list_requests = dict(chain.from_iterable(map(lambda x: x.items(),
                    map(itemgetter(1), filter(lambda x:
                    x[0].startswith('list_requests'), locals().items())))))
