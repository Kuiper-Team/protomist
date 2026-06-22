#ifndef identities_h
#define identities_h

#include "result.h"
#include "types.h"

//Protocol Functions
result MIST_ENCRYPT_SEED(
        unsigned char* output,
        unsigned char* nonce_output,
        unsigned long long ciphertext_length;

        const unsigned char* MIST_SEED,
        const unsigned char* MIST_PASSPHRASE,
        const size_t passphrase_length
);
result MIST_DECRYPT_SEED(
        unsigned char* output,

        const unsigned char* MIST_NONCE,
        const unsigned char* MIST_CIPHERTEXT,
        const unsigned char* MIST_PASSPHRASE,
        const size_t passphrase_length
);

#endif
