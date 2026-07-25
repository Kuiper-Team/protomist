#ifndef identities_h
#define identities_h

#include "constants.h"
#include "result.h"
#include "wordlists/apply.h"

#include <stddef.h>

result MIST_GENERATE_MNEMONIC_SENTENCE(
    char** output,

    const char* const* list_pointer 
);

result MIST_JOIN_MNEMONIC_SENTENCE(
    char** output,
    size_t output_length,

    char** MIST_MNEMONIC_SENTENCE
);

result MIST_GENERATE_SEED(
    unsigned char* output,
    const size_t output_size,

    char** MIST_SEED_MNEMONIC_SENTENCE
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

result MIST_RESTORE_IDENTITY(
    char** MIST_ADDRESS_output,
    unsigned char* MIST_IDENTITY_PK_output,
    unsigned char* MIST_IDENTITY_SK_output,

    const unsigned char* MIST_SEED
);

result MIST_GENERATE_SUBKEY(
    unsigned char* MIST_SUB_PK_output,
    unsigned char* MIST_SUB_SK_output,

    const unsigned char* MIST_SEED,
    const char* MIST_CONTEXT,
    const subkey_type MIST_SUBKEY_TYPE
);
#endif
