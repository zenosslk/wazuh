/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "maild.h"
#include "config/config.h"


/* Read the Mail configuration */
int MailConf(int test_config, const char *cfgfile, MailConfig *Mail)
{
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    Mail->to = NULL;
    Mail->reply_to = NULL;
    Mail->from = NULL;
    Mail->idsname = NULL;
    Mail->smtpserver = NULL;
    Mail->heloserver = NULL;
    Mail->mn = 0;
    Mail->priority = 0;
    Mail->maxperhour = 12;
    Mail->gran_to = NULL;
    Mail->gran_id = NULL;
    Mail->gran_level = NULL;
    Mail->gran_location = NULL;
    Mail->gran_group = NULL;
    Mail->gran_set = NULL;
    Mail->gran_format = NULL;
    Mail->groupping = 1;
    Mail->strict_checking = 0;
#ifdef LIBGEOIP_ENABLED
    Mail->geoip = 0;
#endif

    // Read mail.xml
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
        if (strcmp(node[i]->element, "email_alerts") == 0) {
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_EmailAlerts(chld_node, NULL, Mail);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    // Read mail.xml
    debug2("%s: Reading Configuration [%s]", ARGV0, DEFAULT_ANALYSISD_CONF);
    if (OS_ReadXML(DEFAULT_ANALYSISD_CONF, &xml) < 0) {
        merror(XML_ERROR, ARGV0, DEFAULT_ANALYSISD_CONF, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (-1);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "global") == 0) {
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_Global(chld_node, NULL, Mail);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    if (!Mail->mn) {
        if (!test_config) {
            verbose(MAIL_DIS, ARGV0);
        }
        exit(0);
    }

    return (0);
}
