#ifndef wordlists_apply_h
#define wordlists_apply_h

#include <stddef.h>
#include <stdint.h>

#include "../result.h"
#include "../types.h"

result apply_wordlist(
    char*** output,

    const unsigned char* MIST_ENTROPY,
    const char* const* list_pointer
);

#endif
