/*
 * Dynamic fields functions
 * Copyright (C) 2017 Wazuh Inc.
 * April 28, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fields.h"
#include <shared.h>

static FieldIdentifier* _fi_add_identifier(FieldIdentifier *ids, int i, const char *id);
static FieldIdentifier* _fi_add_indexer(FieldIdentifier *ids, int i, int index);

/*
 * Parse string into Field Identifier array (terminated with FI_END)
 * Returns NULL on error
 */
FieldIdentifier* fi_parse(const char *field_name) {
    FieldIdentifier *ids = NULL;
    char *temp;
    char *cur;
    char *next;
    int i = 0;
    int type;
    int index;
    int end = 0;

    if (!*field_name) {
        // The string is empty
        return NULL;
    }

    temp = strdup(field_name);

    for (cur = temp; !end; cur = next + 1) {
        next = strpbrk(cur, ".[");

        if (!next) {
            // No more tokens, add field and finish
            if (*cur) {
                ids = _fi_add_identifier(ids, i++, cur);
                break;
            } else {
                // Empty identifier
                goto error;
            }
        } else if (next == cur) {
            // Empty identifier
            goto error;
        }

        type = *next == '[' ? FI_INDEXER : FI_IDENTIFIER;
        *next = '\0';
        ids = _fi_add_identifier(ids, i++, cur);

        if (type == FI_INDEXER) {
            cur = next + 1;

            switch (*cur) {
            case '*':
                index = FI_INDEX_ALL;
                next = cur + 1;
                break;

            case '?':
                index = FI_INDEX_ANY;
                next = cur + 1;
                break;

            default:
                index = (int)strtol(cur, &next, 10);

                if (index < 0) {
                    // Negative index
                    goto error;
                }
            }

            if (next > cur && next[0] == ']') {
                ids = _fi_add_indexer(ids, i++, index);

                switch (next[1]) {
                case '\0':
                    end = 1;
                    break;

                case '.':
                    next++;
                    break;

                default:
                    // Neither '.' nor string end after ']'
                    goto error;
                }
            } else {
                // No number given, or incorrect token
                goto error;
            }
        }
    }

    ids[i].type = FI_END;
    free(temp);
    return ids;

error:

    if (ids) {
        ids[i].type = FI_END;
        fi_free(ids);
    }

    free(temp);
    return NULL;
}

// Free memory allocated by fi_parse()
void fi_free(FieldIdentifier *ids) {
    int i;

    if (ids) {
        for (i = 0; ids[i].type != FI_END; i++) {
            if (ids[i].type == FI_IDENTIFIER) {
                free(ids[i].id);
            }
        }

        free(ids);
    }
}

FieldIdentifier* _fi_add_identifier(FieldIdentifier *ids, int i, const char *id) {
    os_realloc(ids, sizeof(FieldIdentifier) * (i + 2), ids);
    ids[i].type = FI_IDENTIFIER;
    ids[i].id = strdup(id);
    return ids;
}

FieldIdentifier* _fi_add_indexer(FieldIdentifier *ids, int i, int index) {
    os_realloc(ids, sizeof(FieldIdentifier) * (i + 2), ids);
    ids[i].type = FI_INDEXER;
    ids[i].index = index;
    return ids;
}
