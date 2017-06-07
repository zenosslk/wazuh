/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
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
#include "remoted.h"
#include "config/config.h"


/* Read the config file (the remote access) */
int RemotedConfig(const char *cfgfile, remoted *cfg)
{
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    cfg->port = NULL;
    cfg->conn = NULL;
    cfg->allowips = NULL;
    cfg->denyips = NULL;

    // Read remote.xml
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
        if (strcmp(node[i]->element, "remote") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_Remote(chld_node, cfg, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    return (1);
}
