#ifndef bech32_wrapper_h
#define bech32_wrapper_h

#include <stddef.h>

#include "../result.h"

result mist_bech32m_encode(
    char** output,
    size_t* output_size,

    const char* hrp,
    const unsigned char* input,
    const size_t input_length
);

result mist_bech32m_decode(
    unsigned char** output,
    size_t* output_size,
    char** hrp_output,

    const char* input
);

#endif
