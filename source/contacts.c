#include "contacts.h"

#include <stdlib.h>
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
    const size_t address_length = strlen(MIST_ADDRESS);
    const size_t label_length = strlen(MIST_LABEL);
    const size_t memo_length = strlen(MIST_MEMO);
    const size_t seperator_count = 2; //3 fields, hence 3 - 1 seperators.

    const size_t total_length = address_length + label_length + memo_length + seperator_count;
    const size_t total_size = total_length + 1;

    char concatenated[total_size];
    strcpy(concatenated, MIST_ADDRESS);
    strcat(concatenated, MIST_CONTACT_FIELD_SEPERATOR);
    strcat(concatenated, MIST_LABEL);
    strcat(concatenated, MIST_CONTACT_FIELD_SEPERATOR);
    strcat(concatenated, MIST_MEMO);

    return MIST_BECH32M_ENCODE(
        output,
        MIST_BECH32M_HRP_CONTACT,
        (unsigned char*) concatenated,
        total_length
    );
}

result MIST_DECODE_CONTACT_BLOCK(
    char** MIST_ADDRESS_output,
    char** MIST_LABEL_output,
    char** MIST_MEMO_output,

    const char* MIST_CONTACT_BLOCK
) {
    unsigned char* decoded;
    result decoded_result = MIST_BECH32M_DECODE(
        &decoded,
        MIST_CONTACT_BLOCK
    );
    if (decoded_result != success)
        return decoded_result;

    char* decoded_string = (char*) decoded;
    
    char* token = strtok(decoded_string, MIST_CONTACT_FIELD_SEPERATOR);
    int field = 0;
    while (token != NULL) {
        size_t field_size = strlen(token) + 1;

        switch (field) {
            case 0:
                *MIST_ADDRESS_output = (char*) malloc(field_size * sizeof(char));
                if (*MIST_ADDRESS_output == NULL) {
                    free(decoded);

                    return out_of_memory;
                }

                strcpy(*MIST_ADDRESS_output, token);

                break;
            case 1:
                *MIST_LABEL_output = (char*) malloc(field_size * sizeof(char));
                if (*MIST_LABEL_output == NULL) {
                    free(decoded);

                    return out_of_memory;
                }

                strcpy(*MIST_LABEL_output, token);

                break;
            case 2:
                *MIST_MEMO_output = (char*) malloc(field_size * sizeof(char));
                if (*MIST_MEMO_output == NULL) {
                    free(decoded);

                    return out_of_memory;
                }

                strcpy(*MIST_MEMO_output, token);

                break;
            default:
                free(decoded);

                return malformed_contact_block;
        }

        token = strtok(NULL, MIST_CONTACT_FIELD_SEPERATOR);

        field++;
    }
    free(decoded);

    if (field != 3)
        return malformed_contact_block;

    return success;
}
