#ifndef xed25519_h
#define xed25519_h

#include <stddef.h>

#include "result.h"

result xed25519_sign(
    unsigned char* output,

    const unsigned char* x25519_secret_key,
    const unsigned char* message,
    const size_t message_size,
    const unsigned char* random
);

result xed25519_verify(
    const unsigned char* signature,
    const unsigned char* x25519_public_key,
    const unsigned char* message,
    const size_t message_size
);

#endif
