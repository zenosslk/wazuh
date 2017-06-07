/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentlessd.h"
#include "config/config.h"

/* Prototypes */
static void help_agentlessd(void) __attribute__((noreturn));


/* Print help statement */
static void help_agentlessd()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULT_AGENTLESS_CONF);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    const char *dir  = DEFAULTDIR;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULT_AGENTLESS_CONF;
    int i;
    OS_XML xml;
    XML_NODE node, chld_node;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_agentlessd();
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    ErrorExit("%s: -u needs an argument", ARGV0);
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_agentlessd();
                break;
        }
    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Read config */
    lessdc.entries = NULL;
    lessdc.queue = 0;

    // Read agentless.xml
    debug2("%s: Reading Configuration [%s]", ARGV0, cfg);
    if (OS_ReadXML(cfg, &xml) < 0) {
        merror(XML_ERROR, ARGV0, cfg, xml.err, xml.err_line);
        return (OS_INVALID);
    }
    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        ErrorExit(XML_INV_AGENTLESS, ARGV0);
    }

    i = 0;
    while (node[i]) {
        if (strcmp(node[i]->element, "agentless") == 0) {
            chld_node = OS_GetElementsbyNode(&xml, node[i]);
            Read_CAgentless(chld_node, &lessdc, NULL);
            OS_ClearNode(chld_node);
        }
        i++;
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    /* Continue in daemon mode */
    if (!run_foreground) {
        nowDaemon();
        goDaemonLight();
    }

    if (chdir(dir) == -1) {
        ErrorExit(CHDIR_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    /* Exit if not configured */
    if (!lessdc.entries) {
        verbose("%s: INFO: Not configured. Exiting.", ARGV0);
        exit(0);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    debug1(PRIVSEP_MSG, ARGV0, dir, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* The real daemon now */
    Agentlessd();
}
