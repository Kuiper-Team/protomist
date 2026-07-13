#include "apply.h"

#include <assert.h>
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

uint8_t bip39_shift(
    size_t bit
) {
    return 1 << (8 - (bit % 8) - 1);
}

result apply_wordlist( //Example: {"abandon", ...}
    char*** output, //Don't forget to free() this. The size should be MIST_SEED_MNEMONIC_WORDS.

    const unsigned char* MIST_ENTROPY, //An array consisting of individual bytes
    const char** list_pointer //A const char* array from wordlist/languages.h, such as en_list.
) {
    size_t bit = 0;
    size_t word_indices[MIST_SEED_MNEMONIC_WORDS];
    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++) {
        size_t position = 0;
        for (size_t loop = 0; loop < MIST_SEED_MNEMONIC_BITS_PER_WORD; loop++) {
            bit = index * MIST_SEED_MNEMONIC_BITS_PER_WORD + loop;
            position <<= 1;

            const size_t byte = bit / 8;

            if ((MIST_ENTROPY[byte] & bip39_shift(bit)) > 0)
                position++;
        }

        assert(position < bip39_wordlist_size);

        word_indices[index] = position;
    }

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
