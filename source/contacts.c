#include "contacts.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "bech32/wrapper.h"
#include "constants.h"
#include "result.h"

//To-do: Unify data representation using protocol buffers.

// Source - https://stackoverflow.com/a/18972477
// Posted by rcs, modified by community. See post 'Timeline' for change history
// Retrieved 2026-07-21, License - CC BY-SA 4.0
static int strpos(
    const char* haystack,
    const char* needle,
    const int occurence
) {
    const char* res = haystack;
    for (int i = 1; i <= occurence; i++) {
        res = strstr(res, needle);
        if (!res)
            return -1;
        else if (i != occurence)
            res++;
    }

    return res - haystack;
}

static void copy_string_range(
    char* output,

    const char* source,
    const size_t start, //Inclusive
    const size_t end //Inclusive
) {
    size_t copied_index = 0;
    for (size_t index = start; index <= end; index++) {
        output[copied_index] = source[index];

        copied_index++;
    }
    output[copied_index] = '\0';
}

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

result MIST_DECODE_CONTACT_BLOCK( //Don't forget to free() all the outputs.
    char** MIST_ADDRESS_output,
    char** MIST_LABEL_output,
    char** MIST_MEMO_output,

    const char* MIST_CONTACT_BLOCK
) {
    unsigned char* bytes;
    result bytes_result = MIST_BECH32M_DECODE(
        &bytes,
        MIST_CONTACT_BLOCK
    );
    if (bytes_result != success)
        return bytes_result;

    char* decoded = (char*) bytes;

    const int label_start_int = strpos(decoded, MIST_CONTACT_FIELD_SEPERATOR, 1);
    const int memo_start_int = strpos(decoded, MIST_CONTACT_FIELD_SEPERATOR, 2);
    if (label_start_int == -1 || memo_start_int == -1) {
        free(bytes);

        return malformed_contact_block;
    }

    const size_t label_start = (size_t) label_start_int;
    const size_t memo_start = (size_t) memo_start_int;

    const size_t decoded_size = strlen((char*) decoded) + 1;
    const size_t address_size = label_start + 1;
    const size_t label_size = memo_start - label_start;
    const size_t memo_size = decoded_size - memo_start - 1;

    *MIST_ADDRESS_output = (char*) malloc(address_size * sizeof(char));
    *MIST_LABEL_output = (char*) malloc(label_size * sizeof(char));
    *MIST_MEMO_output = (char*) malloc(memo_size * sizeof(char));
    if (*MIST_ADDRESS_output == NULL || *MIST_LABEL_output == NULL || *MIST_MEMO_output == NULL) {
        free(bytes);
        free(*MIST_ADDRESS_output);
        free(*MIST_LABEL_output);
        free(*MIST_MEMO_output);

        return out_of_memory;
    }

    strncpy(*MIST_ADDRESS_output, decoded, label_start);
    (*MIST_ADDRESS_output)[address_size - 1] = '\0';
    //From Linux manual pages, strncpy(3): The name of these functions is confusing. These functions produce a null-padded character sequence, not a string (see string_copying(7)).
    //Therefore, the line below strncpy() adds a null terminator to convert *MIST_ADDRESS_output into a C string.

    copy_string_range(*MIST_LABEL_output, decoded, label_start + 1, memo_start - 1);
    copy_string_range(*MIST_MEMO_output, decoded, memo_start + 1, decoded_size - 2);

    free(bytes);
    
    return success;
}
