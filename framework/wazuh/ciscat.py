#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.utils import plain_dict_to_nested_dict
from operator import itemgetter

request_internal_limit = {'ciscat_results': 15}


def get_item_agent(agent_id, offset, limit, select, search, sort, filters, valid_select_fields, allowed_sort_fields,
                   table, nested=True, array=False):
    Agent(agent_id).get_basic_information()
    if select:
        select_fields = list(set(select['fields']) & set(valid_select_fields))
        if select_fields == []:
            incorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields))
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}". \
                                 format(', '.join(valid_select_fields), ','.join(incorrect_fields)))
    else:
        select_fields = valid_select_fields

    if search:
        search['fields'] = valid_select_fields

    # Sorting
    if sort and sort['fields']:
        # Check if every element in sort['fields'] is in allowed_sort_fields.
        if not set(sort['fields']).issubset(allowed_sort_fields):
            raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(
                ', '.join(allowed_sort_fields), ','.join(sort['fields'])))

    kwargs = {"agent_id": agent_id, "offset": offset, "limit": limit, "select": select_fields, "search": search,
              "sort": sort, "filters": filters, "table": table}
    if array:
        response = __get_array_response(**kwargs)
    else:
        response = __get_response(**kwargs)
        response = {} if not response else response[0]

        if nested:
            response = plain_dict_to_nested_dict(response)

    return response


def __get_array_response(agent_id, offset, limit, select, search, sort, filters, table):
    response = {'items': [], 'totalItems': 0}
    internal_limit = limit if limit < request_internal_limit[table] else request_internal_limit[table]
    for current_offset in range(0, limit, internal_limit):
        result_i, total = __get_response(agent_id=agent_id, table=table, offset=current_offset + offset,
                                         limit=internal_limit, select=select,
                                         sort=sort, search=search, filters=filters, count=True)
        if result_i == []:
            continue
        response['items'] += result_i
        response['totalItems'] = total
    return response


def __get_response(agent_id, offset, limit, select, search, sort, filters, table, count=False):
    response, total = Agent(agent_id)._load_info_from_agent_db(table=table, offset=offset, limit=limit, select=select,
                                                               count=True, sort=sort, search=search, filters=filters)
    if count:
        return response, total

    return response



def get_results_agent(agent_id, offset=0, limit=common.database_limit, select={}, search={}, sort={}, filters={},
                       nested=True):
    offset = int(offset)
    limit = int(limit)

    valid_select_fields = {'id', 'scan_id', 'scan_time', 'benchmark',
                           'profile', 'pass', 'fail', 'error',
                           'notchecked', 'unknown', 'score'}

    return get_item_agent(agent_id=agent_id, offset=offset, limit=limit, select=select,
                          search=search, sort=sort, filters=filters, allowed_sort_fields=valid_select_fields,
                          valid_select_fields=valid_select_fields, table='ciscat_results', nested=nested)



def _get_agent_items(func, offset, limit, select, filters, search, sort, array=False):
    agents, result = Agent.get_agents_overview(select={'fields': ['id']})['items'], []

    limit = int(limit)
    offset = int(offset)
    total = 0

    for agent in agents:
        items = func(agent_id=agent['id'], select=select, filters=filters, limit=limit, offset=offset, search=search,
                     sort=sort, nested=False)
        if items == {}:
            continue

        total += 1 if not array else items['totalItems']
        items = [items] if not array else items['items']

        for item in items:
            if limit <= len(result):
                break
            item['agent_id'] = agent['id']
            result.append(item)

    if sort and sort['fields']:
        result = sorted(result, key=itemgetter(sort['fields'][0]), reverse=True if sort['order'] == "desc" else False)

    return {'items': result, 'totalItems': total}


def get_results(offset=0, limit=common.database_limit, select=None, filters={}, search={}, sort={}):
    return _get_agent_items(func=get_results_agent, offset=offset, limit=limit, select=select,
                            filters=filters, search=search, sort=sort, array=False)