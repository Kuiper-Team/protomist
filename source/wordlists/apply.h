#ifndef wordlists_apply_h
#define wordlists_apply_h

#include <stddef.h>

#include "../result.h"
#include "../types.h"

result group_bits_in_11(
    int* output,

    const unsigned char* MIST_ENTROPY
);

result apply_wordlist(
    char*** output,

    const unsigned char* MIST_ENTROPY,
    const char** list_pointer
);

result MIST_MNEMONIC_SENTENCE_JOIN(
    char** output,
    size_t* output_length,

    const char** MIST_MNEMONIC_SENTENCE
);

#endif
