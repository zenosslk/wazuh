#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import os
import xml.etree.ElementTree as ET
import pytest

sys.path.insert(0, os.path.abspath('.'))
from wazuh import cluster
from wazuh import common
from wazuh.utils import load_wazuh_xml
from wazuh.exception import WazuhException


def set_config_value(config_opt, value, is_list=False):
    """
    Sets cluster's configuration config_opt to value
    """
    conf = load_wazuh_xml(common.ossec_conf)
    if not is_list:
        conf.find('ossec_config').find('cluster').find(config_opt).text = value
    else:
        list(conf.find('ossec_config').find('cluster').find(config_opt))[0].text = value
    with open(common.ossec_conf, 'w') as f:
        f.write(ET.tostring(conf.find('ossec_config'), method='html'))
    

def test_check_cluster_status_default():
    """
    Unit test for check_cluster_status function with default configuration
    """
    # with default configuration, the function should return False
    assert cluster.check_cluster_status() == False, "Cluster status with default configuration"
    

@pytest.fixture
def enable_disable_cluster():
    """
    Sets cluster disabled function to 'no'. Runs a test. Restores original value.
    """
    set_config_value('disabled','no')

    yield

    # restore original configuration
    set_config_value('disabled','yes')
    

def test_check_cluster_status_enabled(enable_disable_cluster):
    """
    Unit test for check_cluster_status setting cluster.enabled configuration to no
    """
    # setting cluster enabled parameter to yes should make the function return True
    assert cluster.check_cluster_status() == True, "Cluster status with cluster setting enabled"


def test_get_status_json_default():
    """
    Unit test for get_status_json with default configuration
    """
    status = cluster.get_status_json()
    assert status['enabled'] == 'no' and status['running'] == 'no', \
            "Cluster status with default configuration ({})".format(status)


def test_get_status_json_enabled(enable_disable_cluster):
    """
    Unit test for get_status_json with setting cluster.enabled configuration to yes
    """
    status = cluster.get_status_json()
    assert status['enabled'] == 'yes' and status['running'] == 'no', \
            "Cluster status with cluster enabled ({})".format(status)


def test_check_cluster_config_unspecified_key():
    """
    Checks that the 
    WazuhException: Error 3004 - Error in cluster configuration: Unspecified key
    is raised when calling check_cluster_config with default configuration
    """
    config = cluster.read_config()
    with pytest.raises(WazuhException, match="Error 3004 - Error in cluster configuration: Unspecified key"):
        cluster.check_cluster_config(config)


@pytest.fixture
def add_short_key_to_configuration():
    """
    Sets the cluster's key to abc
    """
    set_config_value('key','abc')

    yield

    set_config_value('key','a'*32)


def test_check_cluster_config_short_key(add_short_key_to_configuration):
    """
    Checks that the
    Error 3004 - Error in cluster configuration: Key must be 32 characters long and only have alphanumeric characters
    is raised when calling check_cluster_configuration with a short key
    """
    config = cluster.read_config()
    with pytest.raises(WazuhException, match='Error 3004 - Error in cluster configuration: Key must be 32 characters long and only have alphanumeric characters'):
        cluster.check_cluster_config(config)


@pytest.fixture(params=['NODE_IP', 'localhost', '0.0.0.0', '127.0.1.1'])
def add_wrong_ip_to_configuration(request):
    """
    Add a wrong IP to the nodes configuration
    """
    set_config_value('nodes',request.param,True)


def test_check_cluster_config_wrong_ip(add_wrong_ip_to_configuration):
    """
    Checks that the
    WazuhException: Error 3004 - Error in cluster configuration: Invalid elements in node fields: NODE_IP.
    is raised when calling check_cluster_configuration using the following IPs: NODE_IP, localhost, 127.0.1.1, 0.0.0.0
    """
    config = cluster.read_config()
    with pytest.raises(WazuhException, match=r'^Error 3004 - Error in cluster configuration: Invalid elements in node fields: [\w\.]+\.$'):
        cluster.check_cluster_config(config)
