/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"
#include "config/config.h"

#ifdef WIN32
static char *SYSCHECK_EMPTY[] = { NULL };
static registry REGISTRY_EMPTY[] = { { NULL, 0 } };
#endif


int Read_Syscheck_Config(const char *cfgfile)
{
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    syscheck.rootcheck      = 0;
    syscheck.disabled       = 0;
    syscheck.skip_nfs       = 0;
    syscheck.scan_on_start  = 1;
    syscheck.time           = SYSCHECK_WAIT * 2;
    syscheck.ignore         = NULL;
    syscheck.ignore_regex   = NULL;
    syscheck.nodiff         = NULL;
    syscheck.nodiff_regex   = NULL;
    syscheck.scan_day       = NULL;
    syscheck.scan_time      = NULL;
    syscheck.dir            = NULL;
    syscheck.opts           = NULL;
    syscheck.realtime       = NULL;
#ifdef WIN32
    syscheck.registry       = NULL;
    syscheck.reg_fp         = NULL;
#endif
    syscheck.prefilter_cmd  = NULL;

    /* Read syscheck.xml */
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
        if (strcmp(node[i]->element, "syscheck") == 0) {
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_Syscheck(chld_node, &syscheck, NULL);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }

    OS_ClearNode(node);
    OS_ClearXML(&xml);

#ifdef CLIENT
    /* Read shared syscheck.xml */
    debug2("%s: Reading Client Configuration [%s]", ARGV0, SHARED_SYSCHECK_CONF);

    if (OS_ReadXML(SHARED_SYSCHECK_CONF, &xml) < 0) {
        merror(XML_ERROR, ARGV0, SHARED_SYSCHECK_CONF, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (-1);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "syscheck") == 0 && ValidAgent(node[i])) {
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_Syscheck(chld_node, &syscheck, NULL);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }

    OS_ClearNode(node);
    OS_ClearXML(&xml);

#endif

#ifndef WIN32
    /* We must have at least one directory to check */
    if (!syscheck.dir || syscheck.dir[0] == NULL) {
        return (1);
    }
#else
    /* We must have at least one directory or registry key to check. Since
       it's possible on Windows to have syscheck enabled but only monitoring
       either the filesystem or the registry, both lists must be valid,
       even if empty.
     */
    if (!syscheck.dir) {
        syscheck.dir = SYSCHECK_EMPTY;
    }
    if (!syscheck.registry) {
            syscheck.registry = REGISTRY_EMPTY;
    }
    if ((syscheck.dir[0] == NULL) && (syscheck.registry[0].entry == NULL)) {
        return (1);
    }
#endif

    return (0);
}
