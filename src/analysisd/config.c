/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Functions to handle the configuration files */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "analysisd.h"
#include "config.h"
#include "active-response.h"

long int __crt_ftell; /* Global ftell pointer */
_Config Config;       /* Global Config structure */

int GlobalConf(const char *cfgfile)
{
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    /* Default values */
    Config.logall = 0;
    Config.logall_json = 0;
    Config.stats = 4;
    Config.integrity = 8;
    Config.rootcheck = 8;
    Config.hostinfo = 8;
    Config.picviz = 0;
    Config.prelude = 0;
    Config.zeromq_output = 0;
    Config.zeromq_output_uri = NULL;
    Config.zeromq_output_server_cert = NULL;
    Config.zeromq_output_client_cert = NULL;
    Config.jsonout_output = 0;
    Config.alerts_log = 1;
    Config.memorysize = 8192;
    Config.mailnotify = -1;
    Config.keeplogdate = 0;
    Config.syscheck_alert_new = 0;
    Config.syscheck_auto_ignore = 1;
    Config.ar = 0;

    Config.syscheck_ignore = NULL;
    Config.white_list = NULL;
    Config.hostname_white_list = NULL;

    /* Default actions -- only log above level 1 */
    Config.mailbylevel = 7;
    Config.logbylevel  = 1;

    Config.custom_alert_output = 0;
    Config.custom_alert_output_format = NULL;

    Config.includes = NULL;
    Config.lists = NULL;
    Config.decoders = NULL;
    Config.label_cache_maxage = 0;
    Config.show_hidden_labels = 0;

    os_calloc(1, sizeof(wlabel_t), Config.labels);

    // Read analisysd.xml: <global>, <alert>, <ruleset>, <command>, <syscheck>
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
        if (strcmp(node[i]->element, "global") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_Global(chld_node, &Config, NULL);
                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, "ruleset") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_Rules(chld_node, &Config, NULL);
                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, "alerts") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_Alerts(chld_node, &Config, NULL);
                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, "syscheck") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_GlobalSK(chld_node, &Config, NULL);
                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, "command") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                ReadActiveCommands(chld_node, ar_commands, NULL);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    // Read labels.xml
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
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_Labels(chld_node, &Config.labels, NULL);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    /* Minimum memory size */
    if (Config.memorysize < 2048) {
        Config.memorysize = 2048;
    }

    return (0);
}
