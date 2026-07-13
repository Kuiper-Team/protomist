#include "custom_pbkdf2_hmac_sha512.h"

#include <arpa/inet.h>
#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "constants.h"

/*
https://en.wikipedia.org/wiki/PBKDF2
https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512
*/

bool is_big_endian() { //From https://github.com/BaseMax/c-binary-serialization, under MIT License.
    union {
        uint32_t i;
        uint8_t c[4];
    } test = {0x01020304};

    return test.c[0] == 1;
}

int32_t INT_32_BE(
    int32_t i
) {
   return (int32_t) htonl((uint32_t) i);
}

int custom_U(
    unsigned char* output,

    const unsigned char* Password,
    const unsigned char* Salt,
    const uint32_t i
) {
    if (i == 1) {
        const int32_t INT_32_BE_array[1] = { INT_32_BE(i) };

        unsigned char concatenated[seed_generation_U1_concatenated_size];
        memcpy(concatenated, Salt, seed_generation_salt_size);
        memcpy(concatenated + seed_generation_salt_size /* Pointer arithmetic */, INT_32_BE_array, 4);

        crypto_auth_hmacsha512(
            output,
            concatenated,
            (unsigned long long)(seed_generation_U1_concatenated_size),
            Password
        );
    } else {
        unsigned char Un[seed_generation_hlen];
        custom_U(Un, Password, Salt, i);

        unsigned char concatenated[seed_generation_Un_concatenated_size];
        memcpy(concatenated, Salt, seed_generation_salt_size);
        memcpy(concatenated + seed_generation_salt_size, Un, seed_generation_hlen);

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
    custom_U(output, Password, Salt, 1);

    unsigned char dummy[seed_generation_hlen];
    for (uint32_t U_index = 2; U_index <= c; U_index++) {
        custom_U(dummy, Password, Salt, U_index);
        for (uint32_t byte_index = 0; byte_index < seed_generation_hlen; byte_index++)
            output[byte_index] ^= dummy[byte_index];
    }

    return 0;
}

int custom_pbkdf2_hmac_sha512(
    unsigned char* DK,

    const unsigned char* Password,
    const unsigned char* Salt,
    const int c,
    const uint32_t i
) {
    //DK = T1 || T2 || ... || T(dkLen/hLen)
    //Concatenation needed
    for (int step = 0; step < seed_generation_dklen_hlen_ratio; step++)
      custom_F(DK, Password, Salt, c, i);

    return 0;
}
