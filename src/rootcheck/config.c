/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef OSSECHIDS
#include "shared.h"
#include "rootcheck.h"
#include "config/config.h"


/* Read the rootcheck config */
int Read_Rootcheck_Config(const char *cfgfile)
{
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
        if (strcmp(node[i]->element, "rootcheck") == 0) {
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node){
                Read_Rootcheck(chld_node, &rootcheck, NULL);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

#ifdef CLIENT
    /* Read shared config */
    debug2("%s: Reading Client Configuration [%s]", ARGV0, SHARED_ROOTCHECK_CONF);

    if (OS_ReadXML(SHARED_ROOTCHECK_CONF, &xml) < 0) {
        merror(XML_ERROR, ARGV0, SHARED_ROOTCHECK_CONF, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (-1);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "rootcheck") == 0 && ValidAgent(node[i])) {
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node){
                Read_Rootcheck(chld_node, &rootcheck, NULL);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

#endif

    return (0);
}
#endif /* OSSECHIDS */
