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

// Field identifier types
#define FI_END               0  // End of array
#define FI_IDENTIFIER        1  // For names
#define FI_INDEXER           2  // For array indexer
#define FI_INDEX_ALL        -1  // For all indexes [*]
#define FI_INDEX_ANY        -2  // For any index [?]

// Field identifier node
typedef struct FieldIdentifier {
    int type;
    char *id;   // When type==FI_IDENTIFIER
    int index;  // When type==FI_INDEXER
} FieldIdentifier;

/*
 * Parse string into Field Identifier array (terminated with FI_END)
 * Returns NULL on error
 */
FieldIdentifier* fi_parse(const char *field_name);

// Free memory allocated by fi_parse()
void fi_free(FieldIdentifier *ids);
