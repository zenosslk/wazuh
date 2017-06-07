/* Copyright (C) 2014 Daniel B. Cid
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */

#include "integrator.h"
#include "config/global-config.h"
#include "config/config.h"

void **OS_ReadIntegratorConf(char *cfgfile, IntegratorConfig ***integrator_config)
{
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    /* Reading configuration */
    // Read integrator.xml
    debug2("%s: Reading Configuration [%s]", ARGV0, cfgfile);
    if (OS_ReadXML(cfgfile, &xml) < 0) {
        merror(XML_ERROR, ARGV0, cfgfile, xml.err, xml.err_line);
        return(NULL);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return(NULL);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "integration") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_Integrator(chld_node, integrator_config, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    return (void**)*integrator_config;
}
