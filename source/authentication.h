#ifndef authentication_h
#define authentication_h

#include <stdbool.h>
#include <stddef.h>

#include "result.h"

result MIST_SIGN(
    char* output,

    const char* MIST_SECRET_KEY,
    const unsigned char* MIST_PAYLOAD,
    const size_t payload_size
);

result MIST_VERIFY_SIGNATURE(
    const char* MIST_ADDRESS,
    const unsigned char* MIST_PAYLOAD,
    const size_t payload_size,
    const char* MIST_ED25519_SIGNATURE
);

#endif
