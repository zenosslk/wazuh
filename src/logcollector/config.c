/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"


/* Read the config file (the localfiles) */
int LogCollectorConfig(const char *cfgfile, int accept_remote)
{
    logreader_config log_config;

    log_config.config = NULL;
    log_config.agent_cfg = 0;
    log_config.accept_remote = accept_remote;

    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

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
        if (strcmp(node[i]->element, "localfile") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_Localfile(chld_node, &log_config, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

#ifdef CLIENT
    log_config.agent_cfg = 1;
    debug2("%s: Reading Configuration [%s]", ARGV0, SHARED_LOGCOLLECTOR_CONF);
    if (OS_ReadXML(SHARED_LOGCOLLECTOR_CONF, &xml) < 0) {
        merror(XML_ERROR, ARGV0, SHARED_LOGCOLLECTOR_CONF, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (-1);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "localfile") == 0 && ValidAgent(node[i])) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_Localfile(chld_node, &log_config, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    log_config.agent_cfg = 0;
#endif

    logff = log_config.config;

    return (1);
}
