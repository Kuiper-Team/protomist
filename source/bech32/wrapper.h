#ifndef dependencies_bech32_wrapper_h
#define dependencies_bech32_wrapper_h

#include "../result.h"

#ifdef __cplusplus
extern "C" {
#endif

result MIST_BECH32M_ENCODE(
    char* output,

    const unsigned char* MIST_DECODED,
    const size_t decoded_size
);

result MIST_BECH32M_DECODE(
    unsigned char* output,

    const unsigned char* MIST_ENCODED
);

result MIST_BECH32M_VALIDATE(,
    const char* MIST_ENCODED
);

#ifdef __cplusplus
}
#endif

#endif
