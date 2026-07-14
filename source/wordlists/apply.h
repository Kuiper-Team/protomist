#ifndef wordlists_apply_h
#define wordlists_apply_h

#include <stddef.h>
#include <stdint.h>

#include "../result.h"
#include "../types.h"

uint8_t bip39_shift(
    size_t bit
);

result apply_wordlist(
    char*** output,

    const unsigned char* MIST_ENTROPY,
    const char** list_pointer
);

result MIST_MNEMONIC_SENTENCE_JOIN(
    char** output,
    size_t* output_length,

    const char* const* MIST_MNEMONIC_SENTENCE
);

#endif
