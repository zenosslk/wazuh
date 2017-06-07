/*
 * Authd settings manager
 * Copyright (C) 2017 Wazuh Inc.
 * May 29, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef LIBOPENSSL_ENABLED

#include "shared.h"
#include "auth.h"
#include "config/config.h"

// Read configuration
int authd_read_config(const char *path) {
    config.port = DEFAULT_PORT;
    config.force_time = -1;
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    // Read alerts.xml
    debug2("%s: Reading Configuration [%s]", ARGV0, path);
    if (OS_ReadXML(path, &xml) < 0) {
        merror(XML_ERROR, ARGV0, path, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (-1);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "auth") == 0) {
            if (chld_node = OS_GetElementsbyNode(&xml, node[i]), chld_node) {
                Read_Authd(chld_node, &config, NULL);
                OS_ClearNode(chld_node);
            }
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    if (!config.flags.force_insert) {
        config.force_time = -1;
    }

    return 0;
}

#endif
