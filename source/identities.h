#ifndef identities_h
#define identities_h

#include "result.h"
#include "types.h"

//Protocol Functions
result MIST_ENCRYPT_SEED(
        unsigned char* output,
        unsigned long long output_length,
        unsigned char* MIST_NONCE_OUTPUT,
        unsigned char* MIST_SALT_OUTPUT,

        const unsigned char* MIST_SEED,
        const unsigned char* MIST_PASSPHRASE
);
result MIST_DECRYPT_SEED(
        unsigned char* output,
        unsigned long long output_length,

        const unsigned char* MIST_NONCE,
        const unsigned char* MIST_SALT,
        const unsigned char* MIST_CIPHERTEXT,
        const long long ciphertext_length,
        const unsigned char* MIST_PASSPHRASE,
        const size_t passphrase_length
);

#endif
