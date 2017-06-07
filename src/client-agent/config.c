/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "agentd.h"

/* Global variables */
time_t available_server;
int run_foreground;
keystore keys;
agent *agt;


/* Read the config file (for the remote client) */
int ClientConf(const char *cfgfile)
{
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    agt->port = DEFAULT_SECURE;
    agt->rip = NULL;
    agt->lip = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;
    agt->protocol = UDP_PROTO;

    os_calloc(1, sizeof(wlabel_t), agt->labels);

    // Read client.xml
    debug2("%s: Reading Configuration [%s]", ARGV0, cfgfile);
    if (OS_ReadXML(cfgfile, &xml) < 0) {
        merror(XML_ERROR, ARGV0, cfgfile, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (-1);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "client") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_Client(chld_node, agt, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    // Read default labels.xml
    debug2("%s: Reading Configuration [%s]", ARGV0, DEFAULT_LABELS_CONF);
    if (OS_ReadXML(DEFAULT_LABELS_CONF, &xml) < 0) {
        merror(XML_ERROR, ARGV0, DEFAULT_LABELS_CONF, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (-1);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "labels") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_Labels(chld_node, &agt->labels, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    // Read shared labels.xml
    debug2("%s: Reading Configuration [%s]", ARGV0, SHARED_LABELS_CONF);
    if (OS_ReadXML(SHARED_LABELS_CONF, &xml) < 0) {
        merror(XML_ERROR, ARGV0, SHARED_LABELS_CONF, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (-1);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "labels") == 0 && ValidAgent(node[i])) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_Labels(chld_node, &agt->labels, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    return (1);
}
