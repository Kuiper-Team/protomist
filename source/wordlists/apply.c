#include "apply.h"

#include <math.h>

#include "../constants.h"
#include "../result.h"
#include "../types.h"

#include "languages.h"

//protomist doesn't include a normalization function.
//For wordlists, UTF-8 NFKD normalization is preprocessed.
//For user MIST_ENTROPY, it is done by the caller.

result group_bits_in_11( //ONLY ENTROPY + CHECKSUM AS INPUT! NOT GENERAL PURPOSE!
    unsigned int* output,

    const unsigned char* MIST_ENTROPY //An array consisting of individual bytes
) {
    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++) {
        int absolute_start_bit = index * 11;
        int absolute_end_bit = absolute_start_bit + 10;

        int start_index = floor(absolute_start_bit / 8);
        int end_index = floor(absolute_end_bit / 8);

        int relative_start_bit = absolute_start_bit % 8;
        int relative_end_bit = absolute_end_bit % 8;

        unsigned int chunk1_mask = 0;
        for (int a = relative_start_bit; a <= 7; a++)
            chunk1_mask |= 1 << a;

        unsigned int chunk2_mask = 0;
        for (int a = 0; a <= relative_end_bit; a++)
            chunk2_mask |= 1 << a;

        unsigned int chunk1 = (MIST_ENTROPY[start_index] & chunk1_mask) >> relative_start_bit;
        unsigned int chunk2 = (MIST_ENTROPY[end_index] & chunk2_mask);

        if (end_index - start_index == 2) { //If a third chunk is necessary (DUMB SOLUTION)
            int middle_index = start_index + 1;

            unsigned int middle_chunk = MIST_ENTROPY[middle_index];

            output[index] = (chunk1 << (relative_end_bit + 1 + 8) | (middle_chunk << 8) | chunk2;
        } else {
            output[index] = (chunk1 << (relative_end_bit + 1)) | chunk2;
        }
    }
    //To fix: In some cases, there is a need for a third chunk.

    result success;
}

result apply_wordlist(
    char* output,

    const unsigned char* MIST_ENTROPY,
    const bip39_wordlist_language language
) {
    bip39_wordlist_pair* list_pointer;
    switch (language) {
        case en:
            list_pointer = en_list;
            break;
        case ja:
            list_pointer = ja_list;
            break;
        case ko:
            list_pointer = ko_list;
            break;
        case es:
            list_pointer = es_list;
            break;
        case zh_HANS:
            list_pointer = zh_HANS_list;
            break;
        case zh_HANT:
            list_pointer = zh_HANT_list;
            break;
        case fr:
            list_pointer = fr_list;
            break;
        case it:
            list_pointer = it_list;
            break;
        case cs:
            list_pointer = cs_list;
            break;
        case pt:
            list_pointer = pt_list;
            break;
        case ru:
            list_pointer = ru_list;
        case tr:
            list_pointer = tr_list;
            break;
        default:
            return language_unavailable;
    }

    *(list_pointer + word_index);

    return success;
}
