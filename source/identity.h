#ifndef identities_h
#define identities_h

#include <stddef.h>

#include "constants.h"
#include "result.h"

typedef struct {
    unsigned char public_key[MIST_ED25519_PK_SIZE],
    unsigned char secret_key[MIST_ED25519_SK_SIZE]
} mist_identity_subkey_signing;

typedef struct {
    unsigned char public_key[MIST_X25519_PK_SIZE],
    unsigned char secret_key[MIST_X25519_SK_SIZE]
} mist_identity_subkey_encryption;

typedef struct {
    unsigned char key[MIST_XCHACHA20_POLY1305_KEY_SIZE],
    unsigned char nonce[MIST_XCHACHA20_POLY1305_NONCE_SIZE]
} mist_identity_subkey_symmetric_encryption;

typedef struct {
    unsigned char public_key[MIST_MLKEM768_PK_SIZE],
    unsigned char secret_key[MIST_MLKEM768_SK_SIZE]
} mist_identity_subkey_key_encapsulation;

typedef mist_identity_subkey_signing mist_identity;

result mist_identity_subkey_generate_signing(
    mist_identity_subkey_signing* output
);

result mist_identity_subkey_generate_encryption(
    mist_identity_subkey_encryption* output
);

result mist_identity_subkey_generate_symmetric_encryption(
    mist_identity_subkey_symmetric_encryption* output
);

result mist_identity_subkey_generate_key_encapsulation(
    mist_identity_subkey_key_encapsulation* output
);

result mist_identity_generate(
    mist_identity* output
);

#endif
