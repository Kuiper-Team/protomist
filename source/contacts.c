#include "contacts.h"

#include <string.h>

#include "bech32/wrapper.h"
#include "constants.h"
#include "result.h"

result MIST_CREATE_CONTACT_BLOCK(
    char** output,

    const char* MIST_ADDRESS,
    const char* MIST_LABEL,
    const char* MIST_MEMO
) {
    const size_t address_size = strlen(MIST_ADDRESS) + 1;
    const size_t label_size = strlen(MIST_LABEL) + 1;
    const size_t memo_size = strlen(MIST_MEMO) + 1;
    const size_t seperator_count = 2; //3 fields, hence 3 - 1 seperators.

    const size_t total_size = address_size + label_size + memo_size + seperator_count;

    char concatenated[total_size];
    strcpy(concatenated, MIST_ADDRESS);
    strcat(concatenated, MIST_CONTACT_FIELD_SEPERATOR);
    strcat(concatenated, MIST_LABEL);
    strcat(concatenated, MIST_CONTACT_FIELD_SEPERATOR);
    strcat(concatenated, MIST_MEMO);

    return MIST_BECH32M_ENCODE(
        output,
        MIST_BECH32M_HRP_CONTACT,
        concatenated,
        total_size
    );
}
