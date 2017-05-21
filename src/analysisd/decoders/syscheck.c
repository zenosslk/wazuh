/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Syscheck decoder */

#include "eventinfo.h"
#include "os_regex/os_regex.h"
#include "config.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "syscheck_op.h"

/* Compare the first common fields between sum strings */
static int SumCompare(const char *s1, const char *s2);

/* Initialize the necessary information to process the syscheck information */
void SyscheckInit()
{
    if (sdb.agents = OSHash_Create(), !sdb.agents) {
        ErrorExit(ARGV0 ": ERROR: at SyscheckInit(): at OSHash_Create()");
    }

    /* Clear db memory */
    memset(sdb.comment, '\0', OS_MAXSTR + 1);

    memset(sdb.size, '\0', OS_FLSIZE + 1);
    memset(sdb.perm, '\0', OS_FLSIZE + 1);
    memset(sdb.owner, '\0', OS_FLSIZE + 1);
    memset(sdb.gowner, '\0', OS_FLSIZE + 1);
    memset(sdb.md5, '\0', OS_FLSIZE + 1);
    memset(sdb.sha1, '\0', OS_FLSIZE + 1);
    memset(sdb.mtime, '\0', OS_FLSIZE + 1);
    memset(sdb.inode, '\0', OS_FLSIZE + 1);

    /* Create decoder */
    os_calloc(1, sizeof(OSDecoderInfo), sdb.syscheck_dec);
    sdb.syscheck_dec->id = getDecoderfromlist(SYSCHECK_MOD);
    sdb.syscheck_dec->name = SYSCHECK_MOD;
    sdb.syscheck_dec->type = OSSEC_RL;
    sdb.syscheck_dec->fts = 0;

    os_calloc(Config.decoder_order_size, sizeof(char *), sdb.syscheck_dec->fields);
    sdb.syscheck_dec->fields[SK_FILE] = "file";
    sdb.syscheck_dec->fields[SK_SIZE] = "size";
    sdb.syscheck_dec->fields[SK_PERM] = "perm";
    sdb.syscheck_dec->fields[SK_UID] = "uid";
    sdb.syscheck_dec->fields[SK_GID] = "gid";
    sdb.syscheck_dec->fields[SK_MD5] = "md5";
    sdb.syscheck_dec->fields[SK_SHA1] = "sha1";
    sdb.syscheck_dec->fields[SK_UNAME] = "uname";
    sdb.syscheck_dec->fields[SK_GNAME] = "gname";
    sdb.syscheck_dec->fields[SK_INODE] = "inode";

    sdb.id1 = getDecoderfromlist(SYSCHECK_MOD);
    sdb.id2 = getDecoderfromlist(SYSCHECK_MOD2);
    sdb.id3 = getDecoderfromlist(SYSCHECK_MOD3);
    sdb.idn = getDecoderfromlist(SYSCHECK_NEW);
    sdb.idd = getDecoderfromlist(SYSCHECK_DEL);

    sdb.index_limit = getDefine_Int("syscheck", "index_limit", 0, 1048576);

    debug1("%s: SyscheckInit completed.", ARGV0);
}

static void __setcompleted(const char *agent)
{
    FILE *fp;
    char buffer[OS_FLSIZE];

    /* Get agent file */
    snprintf(buffer, OS_FLSIZE , "%s/.%s.cpt", SYSCHECK_DIR, agent);

    fp = fopen(buffer, "w");
    if (fp) {
        fprintf(fp, "#!X");
        fclose(fp);
    }
}

static int __iscompleted(const char *agent)
{
    char buffer[OS_FLSIZE];
    FILE *fp;

    /* Get agent file */
    snprintf(buffer, OS_FLSIZE , "%s/.%s.cpt", SYSCHECK_DIR, agent);

    fp = fopen(buffer, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Set the database of a specific agent as completed */
static void DB_SetCompleted(const Eventinfo *lf)
{
    sk_meta_t *agent;

    if (agent = OSHash_Get(sdb.agents, lf->location), agent) {
        if (!agent->completed) {
            __setcompleted(lf->location);
            /* Set as completed in memory */
            agent->completed = 1;
        }
    }
}

// Insert a new entry in the index. On error, deletes index and returns -1.

int DBIndex_Insert(sk_meta_t * agent, const char * name, const fpos_t *fpos) {
    // Assert limit

    if (agent->entries_z >= sdb.index_limit) {
        merror(ARGV0 ": ERROR: index is full and will be disabled.");
        free(agent->fpos);
        OSHash_Free(agent->entries);
        agent->entries = NULL;
        return -1;
    }

    // Copy position and store

    agent->fpos[agent->entries_z] = *fpos;

    switch (OSHash_Add(agent->entries, name, agent->fpos + agent->entries_z)) {
    case 0:
        merror(ARGV0 ": ERROR: at DB_Load(): at OS_Add(%s)", name);
        return -1;

    case 1:
        merror(ARGV0 ": ERROR: at DB_Load(): duplicated '%s'", name);
        return 0;
    }

    agent->entries_z++;
    return 0;
}

// Load and index full agent Syscheck database. Leaves index null on error.
void DBIndex_Load(sk_meta_t * agent, const char * location) {
    fpos_t init_pos;
    char buffer[OS_MAXSTR + 1];
    char * name;
    char * end;

    os_calloc(sdb.index_limit, sizeof(fpos_t), agent->fpos);

    if (agent->entries = OSHash_Create(), !agent->entries) {
        merror(ARGV0 ": ERROR: at DB_Load(): at OS_Create()");
        return;
    }

    // Loop over the file
    while (fgetpos(agent->fp, &init_pos), fgets(buffer, OS_MAXSTR, agent->fp)) {

        // Ignore blank lines and lines with a comment

        if (buffer[0] == '\n' || buffer[0] == '#') {
            continue;
        }

        // Get name

        if (name = strchr(buffer, ' '), !name) {
            merror("%s: ERROR: Invalid integrity message in the database '%s'.", ARGV0, location);
            continue;
        }

        // New format - with a timestamp

        if (*(++name) == '!') {
            if (name = strchr(name, ' '), !name) {
                merror("%s: ERROR: Invalid integrity message in the database '%s'.", ARGV0, location);
                continue;
            }

            name++;
        }

        // Remove newline

        if (end = strchr(name, '\n'), end) {
            *end = '\0';
        }

        if (DBIndex_Insert(agent, name, &init_pos) < 0) {
            merror(ARGV0 ": ERROR: loading index for agent '%s'", location);
            return;
        }
    }

    fseek(agent->fp, 0, SEEK_SET);
    debug2(ARGV0 ": DEBUG: DBIndex_Load() for agent '%s'> %zd entries loaded.", location, agent->entries_z);
}

/* Return the metadata pointer to be used to verify the integrity */
static sk_meta_t * DB_File(const char * location)
{
    char buffer[OS_FLSIZE];
    sk_meta_t * agent;

    // Find agent

    if (agent = OSHash_Get(sdb.agents, location), agent) {
        /* Point to the beginning of the file */
        fseek(agent->fp, 0, SEEK_SET);
        return agent;
    }

    // If here, our agent wasn't found

    os_calloc(1, sizeof(sk_meta_t), agent);

    /* Get agent file */
    snprintf(buffer, OS_FLSIZE, "%s/%s", SYSCHECK_DIR, location);

    /* r+ to read and write. Do not truncate */
    if (agent->fp = fopen(buffer, "r+"), !agent->fp) {
        /* Try opening with a w flag, file probably does not exist */
        if (agent->fp = fopen(buffer, "w"), agent->fp) {
            fclose(agent->fp);
            agent->fp = fopen(buffer, "r+");
        }
    }

    /* Check again */
    if (!agent->fp) {
        merror("%s: Unable to open '%s'", ARGV0, buffer);
        return NULL;
    }

    if (OSHash_Add(sdb.agents, location, agent) != 2) {
        merror(ARGV0 ": ERROR: at DB_File(): at OSHash_Add(%s)", location);

        if (agent->entries) {
            OSHash_Free(agent->entries);
        }

        fclose(agent->fp);
        free(agent);
        return NULL;
    }

    /* Return the opened pointer (the beginning of it) */
    fseek(agent->fp, 0, SEEK_SET);

    if (sdb.index_limit) {
        DBIndex_Load(agent, location);
    }

    /* Check if the agent was completed */
    if (__iscompleted(location)) {
        agent->completed = 1;
    }

    return agent;
}

/* Search the DB for any entry related to the file being received */
static int DB_Search(const char *f_name, char *c_sum, Eventinfo *lf)
{
    int p = 0;

    char buffer[OS_MAXSTR + 1] = "";
    char *saved_sum = NULL;
    char *saved_name;
    char *end;

    sk_meta_t * agent;
    sk_sum_t oldsum;
    sk_sum_t newsum;
    fpos_t init_pos;
    fpos_t * _init_pos = NULL;

    // Get metadata pointer

    if (agent = DB_File(lf->location), !agent) {
        merror("%s: ERROR: handling integrity database.", ARGV0);
        lf->data = NULL;
        return (0);
    }

    // If index is available, use it to find entry

    if (agent->entries) {
        if (_init_pos = (fpos_t *)OSHash_Get(agent->entries, f_name), _init_pos) {
            if (fsetpos(agent->fp, _init_pos)) {
                merror("%s: ERROR: handling integrity database '%s' (fsetpos).", ARGV0, lf->location);
                return 0;
            }

            if (saved_sum = fgets(buffer, OS_MAXSTR, agent->fp), !saved_sum) {
                merror("%s: ERROR: handling integrity database '%s' (fgets).", ARGV0, lf->location);
                return 0;
            }
        }
    } else {
        debug2(ARGV0 ": DEBUG: DB_Search() using legacy search (no index)");
        _init_pos = &init_pos;

        if (fgetpos(agent->fp, _init_pos) < 0) {
            merror("%s: ERROR: handling integrity database (fgetpos).", ARGV0);
            return (0);
        }

        // Loop over the file

        while (saved_sum = fgets(buffer, OS_MAXSTR, agent->fp), saved_sum) {
            /* Ignore blank lines and lines with a comment */
            if (buffer[0] == '\n' || buffer[0] == '#') {
                fgetpos(agent->fp, _init_pos); /* Get next location */
                continue;
            }

            /* Get name */
            saved_name = strchr(buffer, ' ');
            if (saved_name == NULL) {
                merror("%s: Invalid integrity message in the database.", ARGV0);
                fgetpos(agent->fp, _init_pos); /* Get next location */
                continue;
            }
            *saved_name = '\0';
            saved_name++;

            /* New format - with a timestamp */
            if (*saved_name == '!') {
                saved_name = strchr(saved_name, ' ');
                if (saved_name == NULL) {
                    merror("%s: Invalid integrity message in the database", ARGV0);
                    fgetpos(agent->fp, _init_pos); /* Get next location */
                    continue;
                }
                saved_name++;
            }

            /* Remove newline from saved_name */
            if (end = strchr(saved_name, '\n'), end) {
                *end = '\0';
            }

            /* If name is different, go to next one */
            if (strcmp(f_name, saved_name) != 0) {
                /* Save current location */
                fgetpos(agent->fp, _init_pos);
                continue;
            }
        }
    }

    // If the file was found, compare

    if (saved_sum) {
        /* First three bytes are for frequency check */
        saved_sum += 3;

        /* Checksum match, we can just return and keep going */
        if (SumCompare(saved_sum, c_sum) == 0) {
            lf->data = NULL;
            return (0);
        }

        /* If we reached here, the checksum of the file has changed */
        if (saved_sum[-3] == '!') {
            p++;
            if (saved_sum[-2] == '!') {
                p++;
                if (saved_sum[-1] == '!') {
                    p++;
                } else if (saved_sum[-1] == '?') {
                    p += 2;
                }
            }
        }

        /* Check the number of changes */
        if (!Config.syscheck_auto_ignore) {
            sdb.syscheck_dec->id = sdb.id1;
        } else {
            switch (p) {
                case 0:
                    sdb.syscheck_dec->id = sdb.id1;
                    break;

                case 1:
                    sdb.syscheck_dec->id = sdb.id2;
                    break;

                case 2:
                    sdb.syscheck_dec->id = sdb.id3;
                    break;

                default:
                    lf->data = NULL;
                    return (0);
                    break;
            }
        }

        /* Add new checksum to the database */
        /* Commenting the file entry and adding a new one later */
        if (fsetpos(agent->fp, _init_pos)) {
            merror("%s: ERROR: handling integrity database (fsetpos).", ARGV0);
            return (0);
        }
        fputc('#', agent->fp);

        /* Add the new entry at the end of the file */
        fseek(agent->fp, 0, SEEK_END);

        // If index is available, store

        if (_init_pos != &init_pos && fgetpos(agent->fp, _init_pos) < 0) {
            merror("%s: ERROR: handling integrity database (fgetpos).", ARGV0);
            return (0);
        }

        fprintf(agent->fp, "%c%c%c%s !%ld %s\n",
                '!',
                p >= 1 ? '!' : '+',
                p == 2 ? '!' : (p > 2) ? '?' : '+',
                c_sum,
                (long int)lf->time,
                f_name);
        fflush(agent->fp);

        switch (sk_decode_sum(&newsum, c_sum)) {
        case -1:
            merror("%s: ERROR: Couldn't decode syscheck sum from log.", ARGV0);
            lf->data = NULL;
            return 0;

        case 0:
            switch (sk_decode_sum(&oldsum, saved_sum)) {
            case -1:
                merror("%s: ERROR: Couldn't decode syscheck sum from database.", ARGV0);
                lf->data = NULL;
                return 0;

            case 0:
                sk_fill_event(lf, f_name, &newsum);

                /* Generate size message */
                if (strcmp(oldsum.size, newsum.size) == 0) {
                    sdb.size[0] = '\0';
                } else {
                    snprintf(sdb.size, OS_FLSIZE,
                             "Size changed from '%s' to '%s'\n",
                             oldsum.size, newsum.size);

                    os_strdup(oldsum.size, lf->size_before);
                }

                /* Permission message */
                if (oldsum.perm == newsum.perm) {
                    sdb.perm[0] = '\0';
                } else if (oldsum.perm > 0 && newsum.perm > 0) {
                    char opstr[10];
                    char npstr[10];

                    strncpy(opstr, agent_file_perm(oldsum.perm), sizeof(opstr) - 1);
                    strncpy(npstr, agent_file_perm(newsum.perm), sizeof(npstr) - 1);
                    opstr[9] = npstr[9] = '\0';

                    snprintf(sdb.perm, OS_FLSIZE, "Permissions changed from "
                             "'%9.9s' to '%9.9s'\n", opstr, npstr);

                    lf->perm_before = oldsum.perm;
                }

                /* Ownership message */
                if (strcmp(newsum.uid, oldsum.uid) == 0) {
                    sdb.owner[0] = '\0';
                } else {
                    if (oldsum.uname && newsum.uname) {
                        snprintf(sdb.owner, OS_FLSIZE, "Ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum.uname, oldsum.uid, newsum.uname, newsum.uid);
                        os_strdup(oldsum.uname, lf->uname_before);
                    } else
                        snprintf(sdb.owner, OS_FLSIZE, "Ownership was '%s', "
                                 "now it is '%s'\n",
                                 oldsum.uid, newsum.uid);

                    os_strdup(oldsum.uid, lf->owner_before);
                }

                /* Group ownership message */
                if (strcmp(newsum.gid, oldsum.gid) == 0) {
                    sdb.gowner[0] = '\0';
                } else {
                    if (oldsum.gname && newsum.gname) {
                        snprintf(sdb.owner, OS_FLSIZE, "Group ownership was '%s (%s)', now it is '%s (%s)'\n", oldsum.gname, oldsum.gid, newsum.gname, newsum.gid);
                        os_strdup(oldsum.gname, lf->gname_before);
                    } else
                        snprintf(sdb.gowner, OS_FLSIZE, "Group ownership was '%s', "
                                 "now it is '%s'\n",
                                 oldsum.gid, newsum.gid);

                    os_strdup(oldsum.gid, lf->gowner_before);
                }

                /* MD5 message */
                if (strcmp(newsum.md5, oldsum.md5) == 0) {
                    sdb.md5[0] = '\0';
                } else {
                    snprintf(sdb.md5, OS_FLSIZE, "Old md5sum was: '%s'\n"
                             "New md5sum is : '%s'\n",
                             oldsum.md5, newsum.md5);
                    os_strdup(oldsum.md5, lf->md5_before);
                }

                /* SHA-1 message */
                if (strcmp(newsum.sha1, oldsum.sha1) == 0) {
                    sdb.sha1[0] = '\0';
                } else {
                    snprintf(sdb.sha1, OS_FLSIZE, "Old sha1sum was: '%s'\n"
                             "New sha1sum is : '%s'\n",
                             oldsum.sha1, newsum.sha1);
                    os_strdup(oldsum.sha1, lf->sha1_before);
                }

                /* Modification time message */
                if (oldsum.mtime && newsum.mtime && oldsum.mtime != newsum.mtime) {
                    char *old_ctime = strdup(ctime(&oldsum.mtime));
                    char *new_ctime = strdup(ctime(&newsum.mtime));
                    old_ctime[strlen(old_ctime) - 1] = '\0';
                    new_ctime[strlen(new_ctime) - 1] = '\0';

                    snprintf(sdb.mtime, OS_FLSIZE, "Old modification time was: '%s', now it is '%s'\n", old_ctime, new_ctime);
                    lf->mtime_before = oldsum.mtime;
                    free(old_ctime);
                    free(new_ctime);
                } else {
                    sdb.mtime[0] = '\0';
                }

                /* Inode message */
                if (oldsum.inode && newsum.inode && oldsum.inode != newsum.inode) {
                    snprintf(sdb.mtime, OS_FLSIZE, "Old inode was: '%ld', now it is '%ld'\n", oldsum.inode, newsum.inode);
                    lf->inode_before = oldsum.inode;
                } else {
                    sdb.inode[0] = '\0';
                }

                /* Provide information about the file */
                snprintf(sdb.comment, OS_MAXSTR, "Integrity checksum changed for: "
                         "'%.756s'\n"
                         "%s"
                         "%s"
                         "%s"
                         "%s"
                         "%s"
                         "%s",
                         f_name,
                         sdb.size,
                         sdb.perm,
                         sdb.owner,
                         sdb.gowner,
                         sdb.md5,
                         sdb.sha1
                        );

                if (lf->data)
                    os_strdup(lf->data, lf->diff);

                lf->event_type = FIM_MODIFIED;
                break;

            case 1:
                /* If file was re-added, do not compare changes */
                sdb.syscheck_dec->id = sdb.idn;
                lf->event_type = FIM_READDED;
                sk_fill_event(lf, f_name, &newsum);
                snprintf(sdb.comment, OS_MAXSTR,
                     "File '%.756s' was re-added.", f_name);

                break;
            }

            break;

        case 1:
            /* File deleted */
            sdb.syscheck_dec->id = sdb.idd;
            os_strdup(f_name, lf->filename);
            lf->event_type = FIM_DELETED;
            snprintf(sdb.comment, OS_MAXSTR,
                 "File '%.756s' was deleted. Unable to retrieve "
                 "checksum.", f_name);
        }

        /* Create a new log message */
        free(lf->full_log);
        os_strdup(sdb.comment, lf->full_log);
        lf->log = lf->full_log;
        lf->data = NULL;

        /* Set decoder */
        lf->decoder_info = sdb.syscheck_dec;

        return (1);
    } else {
        // If we reach here, this file is not present in our database

        fseek(agent->fp, 0, SEEK_END);

        // If index is available, store

        if (_init_pos != &init_pos) {

            if (fgetpos(agent->fp, &init_pos) < 0) {
                merror("%s: ERROR: handling integrity database (fgetpos).", ARGV0);
                return (0);
            }

            if (DBIndex_Insert(agent, f_name, &init_pos) < 0) {
                merror(ARGV0 ": ERROR: inserting entry into index for agent '%s'", lf->location);
                return 0;
            }
        }

        fprintf(agent->fp, "+++%s !%ld %s\n", c_sum, (long int)lf->time, f_name);
        fflush(agent->fp);

        switch (sk_decode_sum(&newsum, c_sum)) {
            case -1:
                merror("%s: ERROR: Couldn't decode syscheck sum from log.", ARGV0);
                break;

            case 0:
                lf->event_type = FIM_ADDED;

                /* Alert if configured to notify on new files */
                if ((Config.syscheck_alert_new == 1) && agent->completed) {
                    sdb.syscheck_dec->id = sdb.idn;
                    sk_fill_event(lf, f_name, &newsum);

                    /* New file message */
                    snprintf(sdb.comment, OS_MAXSTR,
                             "New file '%.756s' "
                             "added to the file system.", f_name);

                    /* Create a new log message */
                    free(lf->full_log);
                    os_strdup(sdb.comment, lf->full_log);
                    lf->log = lf->full_log;

                    /* Set decoder */
                    lf->decoder_info = sdb.syscheck_dec;
                    lf->data = NULL;

                    return (1);
                }

                break;

            case 1:
                merror("%s: WARN: Missing file entry.", ARGV0);
                break;
        }
    }

    lf->data = NULL;
    return (0);
}

/* Special decoder for syscheck
 * Not using the default decoding lib for simplicity
 * and to be less resource intensive
 */
int DecodeSyscheck(Eventinfo *lf)
{
    int result;
    char *c_sum;
    char *f_name;
    clock_t t0 = clock();

    /* Every syscheck message must be in the following format:
     * checksum filename
     */
    f_name = strchr(lf->log, ' ');
    if (f_name == NULL) {
        /* If we don't have a valid syscheck message, it may be
         * a database completed message
         */
        if (strcmp(lf->log, HC_SK_DB_COMPLETED) == 0) {
            DB_SetCompleted(lf);
            return (0);
        }

        merror(SK_INV_MSG, ARGV0);
        return (0);
    }

    /* Zero to get the check sum */
    *f_name = '\0';
    f_name++;

    /* Get diff */
    lf->data = strchr(f_name, '\n');
    if (lf->data) {
        *lf->data = '\0';
        lf->data++;
    } else {
        lf->data = NULL;
    }

    /* Check if file is supposed to be ignored */
    if (Config.syscheck_ignore) {
        char **ff_ig = Config.syscheck_ignore;

        while (*ff_ig) {
            if (strncasecmp(*ff_ig, f_name, strlen(*ff_ig)) == 0) {
                lf->data = NULL;
                return (0);
            }

            ff_ig++;
        }
    }

    /* Checksum is at the beginning of the log */
    c_sum = lf->log;

    /* Search for file changes */
    result = DB_Search(f_name, c_sum, lf);
    debug2(ARGV0 ": PROFILE: DecodeSyscheck() for '%s', %d µs", lf->location, (int)((double)(clock() - t0) * 1000000 / CLOCKS_PER_SEC));
    return result;
}

/* Compare the first common fields between sum strings */
int SumCompare(const char *s1, const char *s2) {
    const char *ptr1 = strchr(s1, ':');
    const char *ptr2 = strchr(s2, ':');
    size_t size1;
    size_t size2;

    while (ptr1 && ptr2) {
        ptr1 = strchr(ptr1 + 1, ':');
        ptr2 = strchr(ptr2 + 1, ':');
    }

    size1 = ptr1 ? (size_t)(ptr1 - s1) : strlen(s1);
    size2 = ptr2 ? (size_t)(ptr2 - s2) : strlen(s2);

    return size1 == size2 ? strncmp(s1, s2, size1) : 1;
}
