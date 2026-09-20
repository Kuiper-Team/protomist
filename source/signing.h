#ifndef signing_h
#define signing_h

#include <stddef.h>

#include "pqxdh.h"
#include "result.h"

result mist_signing_sign(
    char* output,

    const struct mist_identity identity,
    const unsigned char* input,
    const size_t payload_size
);

result mist_signing_verify(
    const unsigned char* public_key,
    const unsigned char* signature,
    const size_t signature_size
);

#endif
