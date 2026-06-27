#include "custom_pbkdf2_hmac_sha512.h"

#include <sodium.h>
#include <string.h>

#include "constants.h"

//https://en.wikipedia.org/wiki/PBKDF2
//https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512

void BE(unsigned char* output, uint32_t i) {
    output[0] = (i >> 24) & 0xFF;
    output[1] = (i >> 16) & 0xFF;
    output[2] = (i >>  8) & 0xFF;
    output[3] = i & 0xFF;
}

int custom_U(
    unsigned char* output,

    const unsigned char* Password,
    const unsigned char* Salt,
    const uint32_t i
) {
    uint32_t INT_32_BE = i;
    BE(i);

    if (i == 1) {
        unsigned char concatenated[seed_generation_U1_concatenated_size];
        memcpy(concatenated, Salt, seed_generation_salt_size);
        memcpy(concatenated + seed_generation_salt_size, INT_32_BE, 4);

        crypto_auth_hmacsha512(
            output,
            concatenated,
            (unsigned long long)(seed_generation_U1_concatenated_size),
            Password
        );
    } else {
        unsigned char Un[seed_generation_hlen];
        custom_U(Un, i);

        unsigned char concatenated[seed_generation_Un_concatenated_size];
        memcpy(concatenated, Salt, seed_generation_salt_size);
        memcpy(concatenated + seed_generation_salt_size, Un, seed_generation_hlen)

        crypto_auth_hmacsha512(
            output,
            concatenated,
            (unsigned long long)(seed_generation_Un_concatenated_size),
            Password
        );
    }

    return 0;
}

int custom_F(
    unsigned char* output,

    const unsigned char* Password,
    const unsigned char* Salt,
    const int c,
    const uint32_t i
) {
    custom_U(output, 1);

    unsigned char dummy[seed_generation_hlen];
    for (uint32_t U_index = 2; U_index <= c; U_index++) {
        custom_U(dummy, U_index);
        for (uint32_t byte_index = 0; byte_index < seed_generation_hlen; byte_index++)
            output[byte_index] ^= dummy[byte_index];
    }
}

int custom_pbkdf2_hmac_sha512(
    unsigned char* DK,

    const unsigned char* Password,
    const unsigned char* Salt,
    const int c
) {
    //DK = T1 || T2 || ... || T(dkLen/hLen)
    //Concatenation needed
    for (int step = 0; step < seed_generation_dklen_hlen_ratio; step++)
      custom_F(DK, Password, Salt, c, i) 
}
