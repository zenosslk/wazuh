#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from itertools import chain
from operator import itemgetter

protocol_messages = {
    'ARGS'                  : 'args',
    'NODEAGENTS'            : 'nodeagents',
    'REQUEST_TYPE'          : 'request_type'
}

# API Messages
list_requests_agents = {
    'GET_AGENTS'            : '/agents',
    'RESTART_AGENTS'        : 'PUT/agents/restart',
    'RESTART_AGENTS_POST'   : 'POST/agents/restart',
    'AGENTS_UPGRADE_RESULT' : '/agents/:agent_id/upgrade_result',
    'AGENTS_UPGRADE'        : 'PUT/agents/:agent_id/upgrade',
    'AGENTS_UPGRADE_CUSTOM' : 'PUT/agents/:agent_id/upgrade_custom'
}

list_requests_syscheck = {
    'SYSCHECK_LAST_SCAN'    : '/syscheck/:agent_id/last_scan',
    'SYSCHECK_RUN'          : 'PUT/syscheck',
    'SYSCHECK_CLEAR'        : 'DELETE/syscheck'
}

list_requests_rootcheck = {
    'ROOTCHECK_LAST_SCAN'   : '/rootcheck/:agent_id/last_scan',
    'ROOTCHECK_PCI'         : '/rootcheck/:agent_id/pci',
    'ROOTCHECK_CIS'         : '/rootcheck/:agent_id/cis',
    'ROOTCHECK_RUN'         : 'PUT/rootcheck',
    'ROOTCHECK_CLEAR'       : 'DELETE/rootcheck'
}

list_requests_managers = {
    'MANAGERS_INFO'              : '/manager/info',
    'MANAGERS_STATUS'            : '/manager/status',
    'MANAGERS_OSSEC_CONF'        : '/manager/configuration',
    'MANAGERS_LOGS_SUMMARY'      : '/manager/logs/summary',
    'MANAGERS_LOGS'              : '/manager/logs',
    'MANAGERS_INFO_NODE'         : '/manager/info/:node_id',
    'MANAGERS_STATUS_NODE'       : '/manager/status/:node_id',
    'MANAGERS_OSSEC_CONF_NODE'   : '/manager/configuration/:node_id',
    'MANAGERS_LOGS_SUMMARY_NODE' : '/manager/logs/summary/:node_id',
    'MANAGERS_LOGS_NODE'         : '/manager/logs/:node_id'
}

list_requests_stats = {
    'MANAGERS_STATS_TOTALS'      : '/manager/stats',
    'MANAGERS_STATS_WEEKLY'      : '/manager/stats/weekly',
    'MANAGERS_STATS_HOURLY'      : '/manager/stats/hourly',
    'MANAGERS_STATS_TOTALS_NODE' : '/manager/stats',
    'MANAGERS_STATS_WEEKLY_NODE' : '/manager/stats/weekly',
    'MANAGERS_STATS_HOURLY_NODE' : '/manager/stats/hourly'
}

list_requests_cluster = {
    'DISTRIBUTED_REQUEST'   : 'distributed',
    'CLUSTER_CONFIG'        : '/cluster/config',
    'MASTER_FORW'           : 'master_forward',
    'zip'                   : 'zip',
    'node'                  : 'node',
    'ready'                 : 'ready',
    'data'                  : 'data'
}

# All dicts that start with "list_requests"
all_list_requests = dict(chain.from_iterable(map(lambda x: x.items(),
                    map(itemgetter(1), filter(lambda x:
                    x[0].startswith('list_requests'), locals().items())))))
