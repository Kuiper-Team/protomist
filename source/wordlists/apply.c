#include "apply.h"

#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../constants.h"
#include "../result.h"

#include "languages.h"

//protomist doesn't include a normalization function.
//For wordlists, UTF-8 NFKD normalization is preprocessed.
//For user MIST_ENTROPY, it is done by the caller.

result group_bits_in_11( //ONLY ENTROPY + CHECKSUM AS INPUT! NOT GENERAL PURPOSE!
    int* output,

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

            output[index] = chunk1 << (relative_end_bit + 1 + 8) | (middle_chunk << 8) | chunk2;
        } else {
            output[index] = (chunk1 << (relative_end_bit + 1)) | chunk2;
        }
    }
    //To fix: In some cases, there is a need for a third chunk (replace the dumb solution).

    return success;
}

result apply_wordlist( //Example: ["abandon", ...]
    char*** output, //Don't forge to free(). Also the size should be MIST_SEED_MNEMONIC_WORDS.

    const unsigned char* MIST_ENTROPY,
    const char** list_pointer //A const char* array from wordlist/languages.h, such as en_list.
) {
    int word_indices[MIST_SEED_MNEMONIC_WORDS];
    group_bits_in_11(word_indices, MIST_ENTROPY);

    for (int r = 0; r < MIST_SEED_MNEMONIC_WORDS; r++) {
        const int word_index = word_indices[r];

        const char* word = list_pointer[word_index];
        const size_t word_size = strlen(word) + 1;

        (*output)[r] = (char*) malloc(word_size * sizeof(char));
        if ((*output)[r] == NULL)
            return out_of_memory;

        strcpy((*output)[r], word);
    }

    return success;
}

result MIST_MNEMONIC_SENTENCE_JOIN(
    char** output,
    size_t* output_length,

    const char** MIST_MNEMONIC_SENTENCE
) {
    *output_length = 0;

    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++) {
        const char* word = MIST_MNEMONIC_SENTENCE[index];
        *output_length += strlen(word);
    }
    const size_t space_count = MIST_SEED_MNEMONIC_WORDS - 1;
    *output_length += space_count;

    const size_t output_size = *output_length + 1;
    *output = (char*) malloc(output_size * sizeof(char));
    if (*output == NULL)
        return out_of_memory;

    (*output)[0] = '\0';

    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++) {
        const char* word = MIST_MNEMONIC_SENTENCE[index];
        const size_t word_length = strlen(word);
        const size_t word_size = word_length + 1;

        if (index != MIST_SEED_MNEMONIC_WORDS - 1) { //Unless it's the last index, append space.
            char space_trailed[word_size + 1] = "";
            strcat(space_trailed, MIST_SEED_MNEMONIC_SPACE);

            strcat(*output, space_trailed);
        }
        strcat(*output, word);
    }

    return success;
}
