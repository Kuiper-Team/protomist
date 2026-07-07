#ifndef custom_pbkdf2_hmac_sha512_h
#define custom_pbkdf2_hmac_sha512_h

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool is_big_endian();

void BE(
    int32_t i
);

int custom_U(
    unsigned char* output,

    const unsigned char* Password,
    const unsigned char* Salt,
    const uint32_t i
);

int custom_F(
    unsigned char* output,

    const unsigned char* Password,
    const unsigned char* Salt,
    const int c,
    const uint32_t i
);

int custom_pbkdf2_hmac_sha512(
    unsigned char* DK,

    const unsigned char* Password,
    const unsigned char* Salt,
    const int c
);

#endif
