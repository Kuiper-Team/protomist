#ifndef contacts_h
#define contacts_h

#include "result.h"

result MIST_CREATE_CONTACT_BLOCK(
    char** output,

    const char* MIST_ADDRESS,
    const char* MIST_LABEL,
    const char* MIST_MEMO
);

#endif
