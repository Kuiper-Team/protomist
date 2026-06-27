#ifndef wordlists_apply_h
#define wordlists_apply_h

#include "../result.h"
#include "../types.h"

result apply_wordlist(
    char* output,

    const unsigned char* MIST_ENTROPY,
    const bip39_wordlist_language language
);

#endif
