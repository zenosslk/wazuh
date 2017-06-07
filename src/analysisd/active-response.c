/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "active-response.h"

#ifndef WIN32
#include <sys/types.h>
#include <grp.h>
#endif

/* Active response commands */
OSList *ar_commands;
OSList *active_responses;

/* Initialize active response */
void AR_Init()
{
    ar_commands = OSList_Create();
    active_responses = OSList_Create();
    ar_flag = 0;

    if (!ar_commands || !active_responses) {
        ErrorExit(LIST_ERROR, ARGV0);
    }
}

/* Read active response configuration and write it
 * to the appropriate lists.
 */
int AR_ReadConfig(const char *cfgfile)
{
    FILE *fp;
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    /* Clean ar file */
    fp = fopen(DEFAULTARPATH, "w");
    if (!fp) {
        merror(FOPEN_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        return (OS_INVALID);
    }
    fprintf(fp, "restart-ossec0 - restart-ossec.sh - 0\n");
    fprintf(fp, "restart-ossec0 - restart-ossec.cmd - 0\n");
    fclose(fp);

#ifndef WIN32
    struct group *os_group;
    if ((os_group = getgrnam(USER)) == NULL) {
        merror("Could not get ossec gid.");
        return (OS_INVALID);
    }

    if ((chown(DEFAULTARPATH, (uid_t) - 1, os_group->gr_gid)) == -1) {
        merror("Could not change the group to ossec: %d", errno);
        return (OS_INVALID);
    }
#endif

    /* Set right permission */
    if (chmod(DEFAULTARPATH, 0640) == -1) {
        merror(CHMOD_ERROR, ARGV0, DEFAULTARPATH, errno, strerror(errno));
        return (OS_INVALID);
    }

    /* Read configuration */

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
        if (strcmp(node[i]->element, "active-response") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            if (!chld_node) {
                break;
            }
            ReadActiveResponses(chld_node, NULL, active_responses);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    return (0);
}
