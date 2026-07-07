#ifndef wordlists_apply_h
#define wordlists_apply_h

#include "../result.h"
#include "../types.h"

result group_bits_in_11(
    unsigned int* output,

    const unsigned char* MIST_ENTROPY
);

result apply_wordlist(
    char* output,

    const unsigned char* MIST_ENTROPY,
    const bip39_wordlist_language language
);

#endif
