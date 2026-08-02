#ifndef contacts_h
#define contacts_h

#include <stddef.h>

#include "result.h"

result MIST_CREATE_CONTACT_BLOCK(
    char** output,

    const char* MIST_ADDRESS,
    const char* MIST_LABEL,
    const char* MIST_MEMO
);

result MIST_DECODE_CONTACT_BLOCK(
    char** MIST_ADDRESS_output,
    char** MIST_LABEL_output,
    char** MIST_MEMO_output,

    const char* MIST_CONTACT_BLOCK
);

#endif
