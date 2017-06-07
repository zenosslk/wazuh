/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "csyslogd.h"
#include "config/global-config.h"
#include "config/config.h"


/* Read configuration */
SyslogConfig **OS_ReadSyslogConf(__attribute__((unused)) int test_config, const char *cfgfile)
{
    struct SyslogConfig_holder config;
    SyslogConfig **syslog_config = NULL;
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    /* Modules for the configuration */
    config.data = syslog_config;

    /* Read configuration */
    // Read syslog.xml
    debug2("%s: Reading Configuration [%s]", ARGV0, cfgfile);
    if (OS_ReadXML(cfgfile, &xml) < 0) {
        merror(XML_ERROR, ARGV0, cfgfile, xml.err, xml.err_line);
        return (NULL);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (NULL);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "syslog_output") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_CSyslog(chld_node, &config, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    syslog_config = config.data;

    return (syslog_config);
}
