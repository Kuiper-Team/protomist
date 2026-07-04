#ifndef identities_h
#define identities_h

#include "result.h"
#include "types.h"

result MIST_GENERATE_MNEMONIC_SENTENCE(
    unsigned char* output
);

result MIST_GENERATE_SEED(
    unsigned char* output,

    unsigned char* MIST_SEED_MNEMONIC_SENTENCE
);

result MIST_ENCRYPT_SEED(
    unsigned char* output,
    unsigned long long output_length,
    unsigned char* MIST_NONCE_OUTPUT,
    unsigned char* MIST_SALT_OUTPUT,

    const unsigned char* MIST_SEED,
    const char* MIST_PASSPHRASE,
    const size_t passphrase_length
);
result MIST_DECRYPT_SEED(
    unsigned char* output,
    unsigned long long output_length,

    const unsigned char* MIST_NONCE,
    const unsigned char* MIST_SALT,
    const unsigned char* MIST_CIPHERTEXT,
    const long long ciphertext_length,
    const char* MIST_PASSPHRASE,
    const size_t passphrase_length
);

#endif
