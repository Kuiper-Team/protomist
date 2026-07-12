#ifndef identities_h
#define identities_h

#include "result.h"
#include "wordlists/apply.h"

#include <stddef.h>

result MIST_GENERATE_MNEMONIC_SENTENCE(
    char** output,

    const char** list_pointer 
);

result MIST_GENERATE_SEED(
    unsigned char** output,

    const char** MIST_SEED_MNEMONIC_SENTENCE
);

result MIST_ENCRYPT_SEED(
    unsigned char** output,
    unsigned long long output_length,
    unsigned char** MIST_NONCE_OUTPUT,
    unsigned char** MIST_SALT_OUTPUT,

    const unsigned char* MIST_SEED,
    const char* MIST_PASSPHRASE,
    const size_t passphrase_length
);
result MIST_DECRYPT_SEED(
    unsigned char** output,
    unsigned long long output_length,

    const unsigned char* MIST_NONCE,
    const unsigned char* MIST_SALT,
    const unsigned char* MIST_CIPHERTEXT,
    const long long ciphertext_length,
    const char* MIST_PASSPHRASE,
    const size_t passphrase_length
);

result MIST_RESTORE_KEYS(
    unsigned char** MIST_ID_OUTPUT,
    unsigned char** curve25519_public_output,
    unsigned char** curve25519_private_output,
    unsigned char** ed25519_public_output,
    unsigned char** ed25519_private_output,

    const unsigned char* MIST_SEED
);

#endif
