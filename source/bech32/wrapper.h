#ifndef bech32_wrapper_h
#define bech32_wrapper_h

#include <stddef.h><

#include "../result.h"

result MIST_BECH32_ENCODE(
    char** output,
    size_t output_size,

    const char* hrp,
    const unsigned char* MIST_DECODED,
    const size_t MIST_DECODED_length
);

result MIST_BECH32_DECODE(
    unsigned char** output,
    size_t* output_size,
    char** MIST_HRP_output,

    const char* MIST_ENCODED
);

#endif
